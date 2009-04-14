/***********************************************************
Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior
University

We are making the OpenFlow specification and associated documentation
(Software) available for public use and benefit with the expectation
that others will use, modify and enhance the Software and contribute
those enhancements back to the community. However, since we would
like to make the Software available for broadest use, with as few
restrictions as possible permission is hereby granted, free of charge,
to any person obtaining a copy of this Software to deal in the Software
under the copyrights without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
THE USE OR OTHER DEALINGS IN THE SOFTWARE.

The name and trademarks of copyright holder(s) may NOT be used in
advertising or publicity pertaining to the Software or any derivatives
without specific, written prior permission.
*****************************************************************/

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>


#include "oftrace.h"
#include "tcp_session.h"
#include "utils.h"

typedef struct pcap_hdr_s {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
} pcap_hdr_t;


struct oftrace {
	int packet_count;
	char * filename;
	FILE * file;
	int n_sessions;
	int max_sessions;
	tcp_session ** sessions;
	tcp_session * curr;
	struct pcap_hdr_s ghdr;
	openflow_msg msg;	// where the current message is actually allocated
};

/**********************************************************
 * oftrace * oftrace_open(char * filename)
 * 	open and parse the global header of the pcap file
 * 	(mostly to get it out of the way)
 * 	and return a pointer to our oftrace context
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
	oft->filename=strdup(filename);
	return oft;
}
/**************************************************************************
 * int get_next_openflow_msg(oftrace *oft, int port)
 * 	keep reading until end_of_file or we find an openflow message;
 * 	if we find an openflow message, copy it into the databuf and fixup
 * 	the utility pointers
 *
 * 	if we get an out-of-order packet, enqueue it on the session and keep going
 *
 * 	expects the caller not to modify info stored in mesg between calls
 * 	(that's why we have the const)
 *
 * 	if ip == 0.0.0.0 ; acts as a wildcard and matches all ips
 */
const openflow_msg * oftrace_next_msg(oftrace * oft, uint32_t ip, int port)
{
	int found=0;
	int err;
	int index;
	openflow_msg * msg = &oft->msg;
	struct ofp_header * ofph;
	char tmp[BUFLEN];
	int tmplen = 0;
	int ip_packet_len=0;
	int payload_len=0;

	if(oft->curr)	// from previous call, are there multiple mesgs in this one tcp session?
	{
		tmplen = sizeof(struct ofp_header);
		if(tcp_session_peek(oft->curr,tmp,tmplen)==1)		// check to see if there is another ofp header queued in the session
		{
			ofph = (struct ofp_header * ) tmp;
			tmplen = ntohs(ofph->length);
			if(tcp_session_peek(oft->curr,tmp,tmplen)==1)
			{
				tcp_session_pull(oft->curr,tmplen);
				index = sizeof(struct ether_header) + (msg->ip->ihl + msg->tcp->doff) * 4;
				found = 1;
				msg->captured = -1; 	// indicate that the true captured amount was lost in reconstruction
			}
		}
	}
	// go into this loop if we didn't find anything in the previous test
	while(found == 0)
	{
		oft->packet_count++;
		err= fread(&msg->phdr,sizeof(msg->phdr),1, oft->file);	// grab a header
		if (err < 1)
		{
			if(!feof(oft->file))
			{
				fprintf(stderr,"short file reading header -- terminating\n");
				perror("fread");
			}
			return NULL;	// not found; stop
		}
		msg->captured = msg->phdr.incl_len;
		err = fread(msg->data,1,msg->phdr.incl_len,oft->file);
		if (err < msg->captured)
		{
			fprintf(stderr,"short file reading packet (%d bytes instead of %d) -- terminating\n",
					err, msg->phdr.incl_len); 
			perror("fread");
			return NULL;	// not found; stop
		}
		index = 0;
		// ethernet parsing
		msg->ether = (struct oft_ethhdr *) &msg->data[index];
		if(msg->ether->ether_type != htons(ETHERTYPE_IP))
			continue;		// ether frame doesn't contain IP
		index+=sizeof(struct ether_header);
		if( msg->captured < index)
		{
			fprintf(stderr, "captured partial ethernet frame -- skipping (but weird)\n");
			continue;
		}
		// IP parsing
		msg->ip = (struct oft_iphdr * ) &msg->data[index];
		if(msg->ip->version != 4)
		{
			fprintf(stderr, "captured non-ipv4 ip packet (%d) -- skipping (but weird)\n",msg->ip->version);
			continue;
		}
		if(msg->ip->protocol != IPPROTO_TCP)
			continue; 	// not a tcp packet
		ip_packet_len = ntohs(msg->ip->tot_len);
		index += 4 * msg->ip->ihl;
		if( msg->captured < index)
		{
			fprintf(stderr, "captured partial ip packet -- skipping (but weird)\n");
			continue;
		}
		// TCP parsing
		msg->tcp = (struct oft_tcphdr * ) &msg->data[index];
		index += msg->tcp->doff*4;
		payload_len = ip_packet_len - 4*(msg->ip->ihl + msg->tcp->doff);
		if(msg->captured <= index)
			continue;	// tcp packet has no payload (e.g., an ACK)
		if(payload_len <=0)
			continue;	// skip if the only thing left is an ethernet trailer
		// Is this to or from the controller?
		if ( ip == 0 ) // do we care about the controller's ip?
		{
			if(port!= 0 && msg->tcp->source != htons(port) &&
					msg->tcp->dest != htons(port))
				continue;	// not to/from the controller
		}
		else 
		{
			if((port == 0) && (msg->ip->saddr != ip) && (msg->ip->daddr != ip))
				continue;	// not to/from the controller; port = wildcard
			else if((!(msg->ip->saddr == ip && msg->tcp->source == htons(port))) &&
					(! (msg->ip->daddr == ip && msg->tcp->dest == htons(port))))
				continue;	// not to/from the controller; port = specified
		}
		oft->curr = tcp_session_find(oft->sessions,oft->n_sessions,msg->ip, msg->tcp);
		if(oft->curr == NULL)
		{
			// new session
			oft->curr = tcp_session_new(msg->ip,msg->tcp);
			oft->sessions[oft->n_sessions++]=oft->curr;	// add to list
			if(oft->n_sessions>= oft->max_sessions)		// grow list if need be
			{
				oft->max_sessions*=2;
				oft->sessions=realloc_and_check(oft->sessions, sizeof(tcp_session*)*oft->max_sessions);
			}
		}
		// add this data to the sessions' tcp stream
		tcp_session_add_frag(oft->curr,ntohl(msg->tcp->seq),
				&msg->data[index],	
				MIN(payload_len,msg->captured-index),
				payload_len);
		tmplen = sizeof(struct ofp_header);
		if(tcp_session_peek(oft->curr,tmp,tmplen)!=1)		// check to see if there is another ofp header queued in the session
			continue;
		ofph = (struct ofp_header * ) tmp;
		tmplen = ntohs(ofph->length);
		if(tcp_session_peek(oft->curr,tmp,tmplen)!=1)		// does there exist a full openflow msg buffered?
			continue;
		found =1;
		tcp_session_pull(oft->curr,tmplen);
	}
	assert(found==1);
	assert(tmplen>0);
	// OFP parsing; new mesg is in tmp[] of length tmpbuf; index is set to the point to write the
	// 	next packet
	memcpy(&msg->data[index],tmp,tmplen);	// put new data into place
	msg->ofph = (struct ofp_header * ) &msg->data[index];	// set convenience ptr
	// use the packet_in entry, even though
	// it doesn't really matter; it works for all openflow msg types b/c it's a union
	msg->ptr.packet_in = (struct ofp_packet_in * ) &msg->data[index];	
	msg->type = msg->ofph->type;	// redundant, but useful
	// find any embedded packets
	switch(msg->type)
	{
		case OFPT_PACKET_IN:
			msg->embedded_packet = (struct oft_ethhdr * ) msg->ptr.packet_in->data;
			break;
		case OFPT_PACKET_OUT:
			msg->embedded_packet = (struct oft_ethhdr * ) &msg->data[index + sizeof(struct ofp_packet_out) + 
				ntohs(msg->ptr.packet_out->actions_len)];
			break;
		default:
			msg->embedded_packet=NULL;
	};
	// done parsing; found a msg to return!
	return msg;
}


/******************************************************
 * int oftrace_rewind(oftrace * oft);
 * 	rewind to the top of the file
 */

int oftrace_rewind(oftrace * oft)
{
	assert(oft);
	rewind(oft->file);
	oft->curr=NULL;
	oft->n_sessions=0;
	return 0;
}


/************************************************
 * double oftrace_progress(oftrace *oft);
 * 	return the fraction of the file processed
 */

double oftrace_progress(oftrace *oft)
{
	struct stat sbuf;
	long fpos = ftell(oft->file);
	assert(oft);
	if(stat(oft->filename,&sbuf))
		return -2.0;	// stat failed for some reason.. which is pretty weird
	return (double)fpos/ (double) sbuf.st_size;
}

