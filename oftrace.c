#include <assert.h>
#include <strings.h>

#include "oftrace.h"
#include "tcp_session.h"
#include "utils.h"

struct oftrace {
	int packet_count;
	char * filename;
	FILE * file;
	int n_sessions;
	int max_sessions;
	tcp_session ** sessions;
	tcp_session * curr;
	struct pcap_hdr_s ghdr;
	int byte_format; 	// unused!
};

/**********************************************************
 * int read_pcap_header(FILE * pcap);
 * 	parse the global header of the pcap file
 * 	(mostly to get it out of the way)
 */
oftrace * oftrace_open(char * filename)
{
	oftrace * oft;
	FILE * pcap;
	int err;
	oft = malloc_and_check(sizeof(oftrace));
	bzero(oft,sizeof(oftrace));
	pcap = fopen(filename,"r");
	if(!pcap)
	{
		fprintf(stderr,"Failed to open %s ; exiting\n",filename);
		perror("fopen");
		return NULL;
	}
	err = fread(&oft->ghdr, sizeof(oft->ghdr),1,pcap);
	if(err != 1)
	{
		fprintf(stderr," Short file read on pcap global header!\n");
		perror("fread");
		return NULL;
	}
	if(oft->ghdr.magic_number != PCAP_MAGIC)	// make sure the magic number is right
	{
		if(oft->ghdr.magic_number == PCAP_BACKWARDS_MAGIC)
		{
			fprintf(stderr,"The pcap magic number is backwards: byte ordering issues?\n");
		}
		else
		{
			fprintf(stderr,"Got %u for pcap magic number: are you sure this is a pcap file?\n",
					oft->ghdr.magic_number);
		}
		return NULL;
	}
	assert(oft->ghdr.network == DLT_EN10MB);	// currently, we only handle ethernet :-(
	oft->max_sessions = 10;			// will dynamically re-allocate - don't worry
	oft->sessions = malloc_and_check(oft->max_sessions * sizeof(tcp_session));
	oft->file=pcap;
	return oft;
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
int oftrace_next_msg(oftrace * oft, uint32_t ip, int port,struct openflow_msg * msg)
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
		err= fread(&msg->phdr,sizeof(msg->phdr),1, oft->file);	// grab a header
		if (err < 1)
		{
			if(!feof(oft->file))
			{
				fprintf(stderr,"short file reading header -- terminating\n");
				perror("fread");
			}
			return 0;	// not found; stop
		}
		msg->captured = msg->phdr.incl_len;
		err = fread(msg->data,1,msg->phdr.incl_len,oft->file);
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
