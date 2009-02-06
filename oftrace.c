#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
	char more_messages_in_packet;	// are there multiple openflow messages in the same packet?
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
	char * controller = "0.0.0.0";
	int port = OFP_TCP_PORT;
	uint32_t controller_ip;
	// FIXME: parse options from cmdline
	if(argc>1)
		filename=argv[1];
	if(argc>2)
		controller=argv[2];
	if(argc>3)
		port=atoi(argv[3]);
	if(!strcmp(controller,"0.0.0.0"))
		fprintf(stderr,"Reading from pcap file %s for any controller ip on port %d\n",
				filename,port);
	else
		fprintf(stderr,"Reading from pcap file %s for controller %s on port %d\n",
				filename,controller,port);
	inet_pton(AF_INET,controller,&controller_ip);	// FIXME: use getaddrinfo
	pcap = fopen(filename,"r");
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
	start.tv_sec = start.tv_usec= 0;	
	memset(&m,sizeof(m),0);	// zero msg contents
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
 *
 * 	expects the caller to zero the message on first call (memset/bzero)
 *
 * 	expects the caller not to modify info stored in mesg between calls
 */
int get_next_openflow_msg(FILE * pcap, uint32_t ip, int port,struct openflow_msg * msg)
{
	int found=0;
	int tries = 0;
	int err;
	int index;

	if(msg->more_messages_in_packet==1)	// from previous call, are there multiple mesgs in this one tcp packet?
	{
		index = sizeof(struct ether_header) + 
				4 * msg->ip->ihl + 
				4 * msg->tcp->doff +
				ntohs(msg->ofph->length);
		msg->ofph = (struct ofp_header *) &msg->data[index];
		msg->type.packet_in = (struct ofp_packet_in *) &msg->data[index];
		if((index+sizeof(struct ofp_header))<= msg->captured)
		{
			index+=ntohs(msg->ofph->length);
			if(index<= msg->captured)
				found=1;
			else 	// we didn't get all of the message
			{
				found=0;	// we thought we found a new msg, but it was truncated
				fprintf(stderr,"OpenFlow message truncated -- skipping\n");
			}
		}
		else
			fprintf(stderr,"OpenFlow header truncated -- skipping\n");
	}

	while(found == 0)
	{
		tries++;
		err= fread(&msg->phdr,sizeof(msg->phdr),1, pcap);	// grab a header
		if (err < 1)
		{
			if(!feof(pcap))
			{
				fprintf(stderr,"short file reading header -- terminating\n");
				perror("fread");
			}
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
		if ( ip == 0 ) // do we care about the controller's ip?
		{
			if((msg->tcp->source != htons(port)) &&
					(msg->tcp->dest != htons(port)))
				continue;	// not to/from the controller
		}
		else 
		{
			if((!(msg->ip->saddr == ip && msg->tcp->source == htons(port))) &&
					(! (msg->ip->daddr == ip && msg->tcp->dest == htons(port))))
				continue;	// not to/from the controller
		}
		// OFP parsing
		msg->ofph = (struct ofp_header * ) &msg->data[index];
		// use the packet_in entry, even though
		// it doesn't really matter
		msg->type.packet_in = (struct ofp_packet_in * ) &msg->data[index];	
		found=1;
		index+=ntohs(msg->ofph->length);	// advance the index pointer
	}
	// assumes the index pointer is pointting just beyond the current openflow message
	if(index< msg->captured)
		msg->more_messages_in_packet=1;
	else
		msg->more_messages_in_packet=0;
	return found;
}
