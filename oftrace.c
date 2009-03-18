#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <net/ethernet.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#include <openflow/openflow.h>
#include "oftrace.h"

#ifndef BUFLEN
// max packetsize * fudge factor of two
#define BUFLEN (65536<<1)
#endif

typedef union openflow_msg_type {
	struct ofp_packet_in * packet_in;
	struct ofp_packet_out * packet_out;
	struct ofp_flow_mod * flow_mod;
} openflow_msg_type;

typedef struct openflow_msg
{
	// where the data is stored
	unsigned char data[BUFLEN];
	int captured;
	struct pcaprec_hdr_s phdr;
	// convenience pointers
	struct ether_header * ether;
	struct iphdr * ip;
	struct tcphdr * tcp;
	struct ofp_header * ofph;
	union openflow_msg_type type;
} openflow_msg;

int read_pcap_header(FILE * pcap);
int do_analyze(FILE * pcap, uint32_t ip, int port);
int get_next_openflow_msg(FILE * pcap, uint32_t ip, int port,openflow_msg * msg);

/************************
 * main()
 *
 */

int main(int argc, char * argv[])
{
	FILE * pcap=NULL;
	char * filename = "openflow.trace";
	char * controller = "172.27.74.150";
	int port = OFP_TCP_PORT;
	uint32_t controller_ip;
	// FIXME: parse options from cmdline
	if(argc>1)
		filename=argv[1];
	if(argc>2)
		controller=argv[2];
	if(argc>3)
		port=atoi(argv[3]);
	fprintf(stderr,"Defaulting to reading from pcap file %s for controller %s on port %d\n",
			filename,controller,port);
	pcap = fopen(filename,"r");
	inet_pton(AF_INET,controller,&controller_ip);	// FIXME: use getaddrinfo
	if(!pcap)
	{
		fprintf(stderr,"Failed to open %s ; exiting\n",filename);
		perror("fopen");
		exit(1);
	}
	if(read_pcap_header(pcap)!=1)
		return 0;
	return do_analyze(pcap,controller_ip, port);
}
/************************************************************************
 * do_analyze:
 * 	analyze openflow msgs from the given file
 */

int do_analyze(FILE * pcap, uint32_t ip, int port)
{
	int count = 0;
	openflow_msg m;
	char dst_ip[BUFLEN];
	char src_ip[BUFLEN];
	struct timeval start,diff;
	start.tv_sec = 0;	
	// for each openflow msg
	while( get_next_openflow_msg(pcap, ip, port, &m) != 0)
	{
		count ++;
		if(start.tv_sec == 0)
		{
			start.tv_sec = m.phdr.ts_sec;
			start.tv_usec = m.phdr.ts_usec;
		}
		diff.tv_sec = m.phdr.ts_sec - start.tv_sec;
		if(m.phdr.ts_usec < start.tv_usec)
		{
			diff.tv_usec = m.phdr.ts_usec + 100000 + start.tv_usec;
			diff.tv_sec--;
		}
		else
			diff.tv_usec = m.phdr.ts_usec - start.tv_usec;
		inet_ntop(AF_INET,&m.ip->saddr,src_ip,BUFLEN);
		inet_ntop(AF_INET,&m.ip->daddr,dst_ip,BUFLEN);
		printf("FROM %s:%u		TO  %s:%u	OFP_TYPE %d	TIME %lu.%.6lu\n",
				src_ip,
				ntohs(m.tcp->source),
				dst_ip,
				ntohs(m.tcp->dest),
				m.ofph->type,
				diff.tv_sec,
				diff.tv_usec
				);
	}
	fprintf(stderr,"Total OpenFlow Messages: %d\n",count);
	return count;
}

/**********************************************************
 * int read_pcap_header(FILE * pcap);
 * 	parse the global header of the pcap file
 * 	(mostly to get it out of the way)
 */
int read_pcap_header(FILE * pcap)
{
	struct pcap_hdr_s ghdr;
	int err = fread(&ghdr, sizeof(ghdr),1,pcap);
	if(err != 1)
	{
		fprintf(stderr," Short file read on pcap global header!\n");
		perror("fread");
		return 0;
	}
	if(ghdr.magic_number != PCAP_MAGIC)	// make sure the magic number is right
	{
		if(ghdr.magic_number == PCAP_BACKWARDS_MAGIC)
		{
			fprintf(stderr,"The pcap magic number is backwards: byte ordering issues?\n");
		}
		else
		{
			fprintf(stderr,"Got %u for pcap magic number: are you sure this is a pcap file?\n",
					ghdr.magic_number);
		}
		return 0;
	}
	assert(ghdr.network == DLT_EN10MB);	// currently, we only handle ethernet :-(
	return 1;
}
/**************************************************************************
 * int get_next_openflow_msg(FILE * pcap, int port,struct openflow_msg * msg);
 * 	keep reading until end_of_file or we find an openflow message;
 * 	if we find an openflow message, copy it into the databuf and fixup
 * 	the utility pointers
 */
int get_next_openflow_msg(FILE * pcap, uint32_t ip, int port,struct openflow_msg * msg)
{
	int found=0;
	int tries = 0;
	int err;
	int index;
	while(found == 0)
	{
		tries++;
		err= fread(&msg->phdr,sizeof(msg->phdr),1, pcap);	// grab a header
		if (err < 1)
		{
			fprintf(stderr,"short file reading header -- terminating\n");
			perror("fread");
			return 0;	// not found; stop
		}
		msg->captured = msg->phdr.incl_len;
		err = fread(msg->data,1,msg->phdr.incl_len,pcap);
		if (err < msg->captured)
		{
			fprintf(stderr,"short file reading packet (%d bytes instead of %d) -- terminating\n",
					err, msg->phdr.incl_len); 
			perror("fread");
			return 0;	// not found; stop
		}
		index = 0;
		// ethernet parsing
		msg->ether = (struct ether_header *) &msg->data[index];
		if(msg->ether->ether_type != htons(ETHERTYPE_IP))
			continue;		// ether frame doesn't contain IP
		index+=sizeof(struct ether_header);
		if( msg->captured < index)
		{
			fprintf(stderr, "captured partial ethernet frame -- skipping (but weird)\n");
			continue;
		}
		// IP parsing
		msg->ip = (struct iphdr * ) &msg->data[index];
		if(msg->ip->version != 4)
		{
			fprintf(stderr, "captured non-ipv4 ip packet (%d) -- skipping (but weird)\n",msg->ip->version);
			continue;
		}
		if(msg->ip->protocol != IPPROTO_TCP)
			continue; 	// not a tcp packet
		index += 4 * msg->ip->ihl;
		if( msg->captured < index)
		{
			fprintf(stderr, "captured partial ip packet -- skipping (but weird)\n");
			continue;
		}
		// TCP parsing
		msg->tcp = (struct tcphdr * ) &msg->data[index];
		index += msg->tcp->doff*4;
		if(msg->captured <= index)
			continue;	// tcp packet has no payload (e.g., an ACK)
		// Is this to or from the controller?
		if((!(msg->ip->saddr == ip && msg->tcp->source == htons(port))) &&
				(! (msg->ip->daddr == ip && msg->tcp->dest == htons(port))))
			continue;	// not to/from the controller
		// OFP parsing
		msg->ofph = (struct ofp_header * ) &msg->data[index];
		msg->type.packet_in = (struct ofp_packet_in * ) &msg->data[index];	// use the packet_in entry, even though
		found=1;
											// it doesn't really matter
	}
	return found;
}
