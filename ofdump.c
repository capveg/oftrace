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


#include "oftrace.h"

#ifndef MIN
#define MIN(x,y) ((x)<(y)?(x):(y))
#endif

/************************
 * main()
 *
 */
int do_analyze(oftrace * oft, uint32_t ip, int port);

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
	return do_analyze(oft,controller_ip, port);
}
/************************************************************************
 * do_analyze:
 * 	analyze openflow msgs from the given file
 */

int do_analyze(oftrace * oft, uint32_t ip, int port)
{
	int count = 0;
	int tcp_list[BUFLEN];
	int n_sessions,i;
	const openflow_msg *m;
	char dst_ip[BUFLEN];
	char src_ip[BUFLEN];
	struct timeval start,diff;
	start.tv_sec = start.tv_usec= 0;	
	memset(&m, 0, sizeof(m));	// zero msg contents
	// for each openflow msg
	while( (m = oftrace_next_msg(oft, ip, port)) != NULL)
	{
		count ++;
		if((count%10000)==0)
		{
			n_sessions =oftrace_tcp_stats(oft,BUFLEN,tcp_list);
			fprintf(stderr," --- %d sessions: ",n_sessions);
			for(i=0;i<MIN(n_sessions,BUFLEN);i++)
				fprintf(stderr, " %d",tcp_list[i]);
		 	fprintf(stderr,"\n");
		}
		if(start.tv_sec == 0)
		{
			start.tv_sec = m->phdr.ts_sec;
			start.tv_usec = m->phdr.ts_usec;
		}
		diff.tv_sec = m->phdr.ts_sec - start.tv_sec;
		if(m->phdr.ts_usec < start.tv_usec)
		{
			diff.tv_usec = m->phdr.ts_usec + 100000 + start.tv_usec;
			diff.tv_sec--;
		}
		else
			diff.tv_usec = m->phdr.ts_usec - start.tv_usec;
		inet_ntop(AF_INET,&m->ip->saddr,src_ip,BUFLEN);
		inet_ntop(AF_INET,&m->ip->daddr,dst_ip,BUFLEN);
		printf("FROM %s:%u		TO  %s:%u	OFP_TYPE %d	LEN %d	TIME %lu.%.6lu\n",
				src_ip,
				ntohs(m->tcp->source),
				dst_ip,
				ntohs(m->tcp->dest),
				m->ofph->type,
				ntohs(m->ofph->length),
				diff.tv_sec,
				diff.tv_usec
				);
	}
	fprintf(stderr,"Total OpenFlow Messages: %d\n",count);
	return count;
}

