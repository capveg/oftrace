#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include "oftrace.h"

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
	const openflow_msg *m;
	char dst_ip[BUFLEN];
	char src_ip[BUFLEN];
	struct timeval start,diff;
	start.tv_sec = start.tv_usec= 0;	
	memset(&m,sizeof(m),0);	// zero msg contents
	// for each openflow msg
	while( (m = oftrace_next_msg(oft, ip, port)) != NULL)
	{
		count ++;
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
		printf("FROM %s:%u		TO  %s:%u	OFP_TYPE %d	TIME %lu.%.6lu\n",
				src_ip,
				ntohs(m->tcp->source),
				dst_ip,
				ntohs(m->tcp->dest),
				m->ofph->type,
				diff.tv_sec,
				diff.tv_usec
				);
	}
	fprintf(stderr,"Total OpenFlow Messages: %d\n",count);
	return count;
}

