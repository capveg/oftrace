
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>	// alternative location for handy time macro
#include <time.h>	// for handy macro


#include "oftrace.h"
#include "utils.h"

typedef struct buffer_id 
{
	uint32_t sip;	// of the packet_in
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
	uint32_t b_id;
	struct timeval ts;
	char data[BUFLEN];
	int datalen;
	struct buffer_id * next;
} buffer_id;

/************************
 * main()
 *
 */
int calc_stats(oftrace * oft, uint32_t ip, int port);
int count_list(buffer_id *b);

int main(int argc, char * argv[])
{
	char * filename = "openflow.trace";
	char * controller = "0.0.0.0";
	int port = OFP_TCP_PORT;
	uint32_t controller_ip;
	oftrace *oft;
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
	oft= oftrace_open(filename);
	if(!oft)
	{
		fprintf(stderr,"Problem openning %s; aborting....\n",filename);
		return 0;
	}
	return calc_stats(oft,controller_ip, port);
}
/************************************************************************
 * calc_stats:
 * 	match packet_in to packet_out or flow_mod statements that release the buffer
 */

int calc_stats(oftrace * oft, uint32_t ip, int port)
{
	const openflow_msg *m;
	char dst_ip[BUFLEN];
	char src_ip[BUFLEN];
	struct timeval diff;
	int etype;
	struct ether_header * eth;
	uint32_t id;
	buffer_id * b, *b_list, *b_prev;
	b_list = NULL;
	memset(&m, 0, sizeof(m));	// zero msg contents
	// for each openflow msg
	while( (m = oftrace_next_msg(oft, ip, port)) != NULL)
	{
		fprintf(stderr,"------------ %f done\r", oftrace_progress(oft));
		switch(m->type)
		{
			case OFPT_PACKET_IN:
				// create a new buffer_id struct and track this buffer_id
				eth = (struct ether_header * ) m->ptr.packet_in->data;
				etype = ntohs(eth->ether_type);
				if(etype != 0x88cc ) // don't record LLDP
				//if(etype != 0x88cc && etype != ETHERTYPE_ARP) // don't record LLDP or ARP
				// if(ntohs(eth->ether_type) == ETHERTYPE_IP) // don't record anything but IP
				{
					b = malloc_and_check(sizeof(buffer_id));
					b->sip = m->ip->saddr;
					b->dip = m->ip->daddr;
					b->sport = m->tcp->source;
					b->dport = m->tcp->dest;
					b->b_id = m->ptr.packet_in->buffer_id;
					b->ts.tv_sec = m->phdr.ts_sec;
					b->ts.tv_usec = m->phdr.ts_usec;
					b->datalen = ntohs(m->ofph->length) - offsetof(struct ofp_packet_in,data);
					memcpy(b->data,m->ptr.packet_in->data,b->datalen);
					b->next=b_list;
					b_list = b;
					if(etype != ETHERTYPE_IP && etype != ETHERTYPE_ARP && etype!= ETHERTYPE_VLAN)
						fprintf(stderr,"ADDING packet_in ether_type=%.4x\n",etype);
				}
				break;
			case OFPT_PACKET_OUT:
			case OFPT_FLOW_MOD:
				inet_ntop(AF_INET,&m->ip->saddr,src_ip,BUFLEN);
				inet_ntop(AF_INET,&m->ip->daddr,dst_ip,BUFLEN);
				if(m->type == OFPT_PACKET_OUT)
					id = m->ptr.packet_out->buffer_id;
				else
					id = m->ptr.flow_mod->buffer_id;
				// now find this buffer_id in the list
				b_prev=NULL;
				b= b_list;
				while(b)
				{
					if(b->b_id == id)
						break;
					else
					{
						b_prev=b;
						b=b->next;
					}
				}
				if(!b)
				{
					if(id != -1)
						fprintf(stderr,"WEIRD: unmatched buffer_id %u in flow %s:%u -> %s:%u\n",
								id,
								src_ip, ntohs(m->tcp->source),
								dst_ip, ntohs(m->tcp->dest));
				}
				else	// found it
				{
					diff.tv_sec = m->phdr.ts_sec;
					diff.tv_usec = m->phdr.ts_usec;
					timersub(&diff,&b->ts,&diff);	// handy macro
					if(b_prev)
						b_prev->next=b->next;
					else
						b_list=b->next;
					printf("%ld.%.6ld 	secs_to_resp buf_id=%d in flow %s:%u -> %s:%u - %s - %d queued\n",
							diff.tv_sec, diff.tv_usec,
							id,
							src_ip, ntohs(m->tcp->source),
							dst_ip, ntohs(m->tcp->dest),
							m->type==OFPT_PACKET_OUT? "packet_out":"flow_mod",
							count_list(b_list));
					free(b);
				}
				break;
		};
	}
	return 0;
}


int count_list(buffer_id *b)
{
	int count=0;
	while(b)
	{
		count++;
		b=b->next;
	}
	return count;
}
