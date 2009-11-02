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

#include "tcp_session.h"
#include "utils.h"

static int pcap_dropped_segment_test(tcp_session * ts);
static char * data2hexstr(char * data, int n_bytes,char * buf, int buflen);

/********************************************************
 * Return whether seq1 came before or after seq2
 * 	use PAWS-like hack to address wrapping
 * 	return -1 if seq1 happens before seq2
 * 	return 1 if seq1 happens after seq2
 * 	return 0 if seq1 equals seq2
 */

#define PAWS_FUDGE_FACTOR (1<<20)
int seqno_cmp(uint32_t seq1,uint32_t seq2)
{
	uint32_t diff;
	if(seq1 == seq2)
		return 0;
	if(seq1 < seq2)
	{
		diff = seq2 - seq1;
		if(diff < PAWS_FUDGE_FACTOR)
			return -1;	// normal, non-wrapped case
		else 
			return 1;	// must have wrapped
	}
	else
	{
		diff = seq1 - seq2;
		if(diff < PAWS_FUDGE_FACTOR)
			return 1;	// normal, non-wrapped case
		else 
			return -1;	// must have wrapped
	}
}

/***********************
 * malloc and create a new tcp_session
 */

tcp_session * tcp_session_new(struct oft_iphdr * ip, struct oft_tcphdr * tcp)
{
	char srcaddr[BUFLEN], dstaddr[BUFLEN];
	tcp_session * ts = malloc_and_check(sizeof(tcp_session));
	ts->sip=ip->saddr;
	ts->n_segs=0;
	ts->dip=ip->daddr;
	ts->sport=tcp->source;	// network byte order!
	ts->dport=tcp->dest;	// network byte order!
	ts->isn = ts->seqno = ntohl(tcp->seq);	// host byte order (we do arith on this)
	ts->close_on_empty= 0;
	ts->skipped_count=0;
	ts->next=NULL;	
	inet_ntop(AF_INET,&ts->sip,srcaddr,BUFLEN);

	inet_ntop(AF_INET,&ts->dip,dstaddr,BUFLEN);
	fprintf(stderr,"DBG: tracking NEW stream : %s:%u-> %s:%u \n",
			srcaddr, ntohs(ts->sport),
			dstaddr, ntohs(ts->dport));

	return ts;
}

/***************************
 * 	find the session matching the passes parameters
 * 	return NULL if not found
 */
tcp_session * tcp_session_find(tcp_session ** sessions, int n_sessions,struct oft_iphdr * ip, struct oft_tcphdr * tcp)
{
	int i;
	tcp_session *ts;
	for(i=0; i < n_sessions; i++)
	{	
		ts = sessions[i];
		if( ts->sip == ip->saddr &&
				ts->dip == ip->daddr &&
				ts->sport == tcp->source &&
				ts->dport == tcp->dest)
			return ts;
	}
	return NULL;
}

/****************************
 * 	does this session have at least len contiguous bytes queued?
 * 	if yes, copy them to data, but don't dequeue, return 1
 * 	if not enough buffer, return -1
 * 	else return 0
 */
int tcp_session_peek(tcp_session * ts, char * data, int len)
{
	tcp_frag *curr;
	int index=0;
	uint32_t seqno;
	int min;
	assert(ts);

	pcap_dropped_segment_test(ts);
	curr = ts->next;
	seqno = ts->seqno;
	while(curr)
	{
		if(seqno != curr->start_seq)	// is the new fragment contiguous with the last?
			return 0;
		min = MIN(curr->len,len-index);
		memcpy(&data[index],curr->data,min);
		seqno +=min;		// this will autowrap, no worries about PAWS
		index+=min;
		if(index>=len)		// did we find all that we were looking for?
		{
			ts->skipped_count=0;
			return 1;
		}
		curr=curr->next;
	}
	return 0;	// ran out of fragments before finding len bytes
}

int tcp_session_close(tcp_session ** sessions, int * n_sessions,tcp_session * ts)
{
	assert(ts);
	if(ts->next == NULL )
		 return tcp_session_delete(sessions,n_sessions,ts);	// just delete now; is empty
	ts->close_on_empty = 1;
	return 0;
}

/****************************
 * 	add this fragment to this session
 */
int tcp_session_add_frag(tcp_session * ts, uint32_t seqno , char * tmpdata, int cap_len, int full_len)
{
	char srcaddr[BUFLEN],srcbuf[BUFLEN];
	char dstaddr[BUFLEN],dstbuf[BUFLEN];
	char *data,*orig_data;
	tcp_frag *curr, *prev, *neo;
	uint32_t start_overlap, end_overlap;

	// malloc some space
	orig_data=data = malloc_and_check(BUFLEN);
	// fill in uncaptured data with zeros; kinda have to do this for packet reconstruction
	assert(cap_len <= full_len);
	assert(full_len < BUFLEN);
	bzero(data,BUFLEN);
	memcpy(data,tmpdata,cap_len);
	// setup initial pointers
	prev=NULL;
	inet_ntop(AF_INET,&ts->sip,srcaddr,BUFLEN);
	inet_ntop(AF_INET,&ts->dip,dstaddr,BUFLEN);
	curr = ts->next;
	/* fprintf(stderr,"DBG: adding seg of size %d to "
			"%s:%u-> %s:%u \n",
			cap_len,
			srcaddr, ntohs(ts->sport),
			dstaddr, ntohs(ts->dport)); */

	if(cap_len< full_len)
		fprintf(stderr,"WARN: incomplete capture (filling with zeros- hope that's okay!) for flow  "
				"%s:%u-> %s:%u \n",
				srcaddr, ntohs(ts->sport),
				dstaddr, ntohs(ts->dport));

	while(curr)	// search for where this frag fits into the stream
	{
		if((seqno +full_len) < curr->start_seq)	// have we gone too far?	// FIXME: PAWS!
			break;
		else if(seqno >= (curr->start_seq + curr->len) )	// not far enough; next
		{
			prev=curr;
			curr=curr->next;
		}
		else
		{
			// if we are here, there is some level of (partial?) overlap
			start_overlap = MAX(seqno,curr->start_seq);	// FIXME: PAWS!
			end_overlap   = MIN(seqno+full_len, curr->start_seq + curr->len);	// FIXME: PAWS!
			if(memcmp(&curr->data[curr->start_seq-start_overlap], 
						&data[start_overlap-seqno],
						end_overlap - start_overlap) != 0)
			{
				fprintf(stderr,"WEIRD: ignoring inconsistant overlapping segments for "
						"%s:%u-> %s:%u start_overlap %u end %u\n",
						srcaddr, ntohs(ts->sport),
						dstaddr, ntohs(ts->dport),
						start_overlap, end_overlap - start_overlap);
				fprintf(stderr,"before:	%s\nafter:	%s\n",
						data2hexstr(&data[start_overlap-seqno],10,srcbuf,BUFLEN),
						data2hexstr(&curr->data[curr->start_seq-start_overlap],10,dstbuf,BUFLEN));
			}
			if(seqno < start_overlap)	// is there something new before the overlap?	// FIXME: PAWS!
			{
				// create a new frag just for the new part before the current frag
				// FIXME: this is duplicated code from outside the while(); not obvious how to fix
				neo = malloc_and_check(sizeof(tcp_frag));
				neo->start_seq = seqno;
				neo->len = start_overlap - seqno;
				ts->n_segs++;
				memcpy(neo->data,data,neo->len);
				data+=neo->len;		// move our new data pointer forward the amount we added
				full_len -= neo->len;
				neo->next = curr;
				if(prev)
					prev->next = neo;
				else
				{
					ts->next = neo;
					ts->seqno = neo->start_seq;
				}
			}
			if((seqno+full_len) > end_overlap)	// is there something new *after* the overlap?
			{
				// advance our new data pointer past the overlap and loop again to keep adding
				data+= end_overlap - start_overlap;	// jump past the overlap
				full_len -= end_overlap - start_overlap;
			}
			else
			{
				free(orig_data);
				return 0;	// if there is nothing after the overlap, we're done
			}
		}
	}
	// now, insert the (remaining) new data between prev and curr
	neo = malloc_and_check(sizeof(tcp_frag));
	neo->start_seq = seqno;
	neo->len = full_len;
	memcpy(neo->data,data,neo->len);
	neo->next = curr;
	ts->n_segs++;
	if(prev)
		prev->next = neo;
	else
	{
		ts->next = neo;
		ts->seqno = neo->start_seq;
	}
	free(orig_data);
	return 0;
}

/****************************
 * 	remove/dequeue len bytes from this session
 * 		if there are holes in the space, erase the holes as well
 * 			(used by pcap_dropped_segment_test() as well)
 * 		don't bother copying it, b/c the tcp_session_peek pretty
 * 		much already does that
 */
int tcp_session_pull(tcp_session * ts, int len)
{
	tcp_frag * curr, * neo;
	assert(ts);
	while(len > 0)
	{
		curr = ts->next;
		if(curr == NULL)
		{
			fprintf(stderr,"WARNING: tried to tcp_session_pull() more than was there :-(\n");
			break;
		}
		if(curr->start_seq != ts->seqno)	// is there a hole?
		{
			len -= curr->start_seq - ts->seqno;	// skip the hole: FIXME PAWS
			ts->seqno = curr->start_seq;
			if(len<=0)			
				break;
		}
		if(curr->len <= len) 	// do we erase the whole fragment?
		{
			len -= curr->len;
			ts->next = curr->next;
			ts->seqno = curr->start_seq+curr->len;
			assert(ts->n_segs>0);
			ts->n_segs--;
			free(curr);
		}
		else
		{
			// just erase the first part of the current fragment
			// todo this: create a new fragment with what's left
			neo = malloc_and_check(sizeof(tcp_frag));
			neo->start_seq = curr->start_seq + len;
			neo->len = curr->len-len;
			// don't increment or decrement ts->n_segs
			// we just removed one and added one
			memcpy(neo->data,&curr->data[len],neo->len);
			neo->next = curr->next;
			ts->next = neo;
			ts->seqno = neo->start_seq;
			free(curr);
			len= 0;
		}
	}
	if(ts->close_on_empty || (ts->skipped_count > OFTRACE_SKIP_LIMIT))
		return OFTRACE_DELETE_FLOW;
	else
		return OFTRACE_OK;
}


/*************************************************************
 * int tcp_session_count_frags(tcp_session *ts);
 * 	count the number of fragments
 */

int tcp_session_count_frags(tcp_session *ts)
{
	assert(ts);
	assert(ts->n_segs>=0);
	return ts->n_segs;
}

/*********************************************************
 * test to see if pcap dropped a packet and we are blocking on
 * it; pretty hackish but apparently necessary
 */
static int pcap_dropped_segment_test(tcp_session * ts)
{
	char srcaddr[BUFLEN];
	char dstaddr[BUFLEN];
	tcp_frag *curr;
	struct ofp_header * ofph;
	char * what_skipped;

	assert(ts);
	if(ts->n_segs < OFTRACE_QUEUE_LIMIT)	// make sure we have ~200+ queued segments 
		return 0;	// before we even think about this test
	curr = ts->next;
	ofph = (struct ofp_header * ) curr->data;
	inet_ntop(AF_INET,&ts->sip,srcaddr,BUFLEN);
	inet_ntop(AF_INET,&ts->dip,dstaddr,BUFLEN);
	if( (curr->len>=sizeof(struct ofp_header))
			&& ( ofph->version == OFP_VERSION ) 	// version is sane
			&& ( ofph->type <= OFPT_STATS_REPLY)	// type is sane
			&& ( ntohs(ofph->length) <= 6000))	// length is sane (arbitary)
	{
		// we have a valid openflow header
		tcp_session_pull(ts,ntohs(ofph->length));	// just skip this message
		what_skipped = "an openflow message";
	}
	else
	{
		ts->next = curr->next;
		ts->seqno = ts->next->start_seq;
		free(curr);
		what_skipped = "a tcp segment";
	}
	ts->skipped_count++;
	fprintf(stderr,"WARN: corrupted trace for flow %s:%d->%s:%d : too many segments queued; skipping %s to pray we fix it\n",
			srcaddr,ntohs(ts->sport),dstaddr,ntohs(ts->dport),what_skipped);
	return 1;
}
/********************************************************
 * print the first n bytes of data into a static string 
 * 	and return it
 */
static char * data2hexstr(char * data, int n_bytes,char * buf, int buflen)
{
	int i;
	int min = MIN(n_bytes,buflen/2);
	buf[0]='0';
	buf[1]='x';
	for(i=0;i< min; i++)
		sprintf(&buf[2*i+2],"%.2x",data[i]); 
	buf[2*min+2]=0;	
	return buf;
}

/******************************************************
 * delete this session and free its resources
 * 	throw an assert if not found
 */

int tcp_session_delete(tcp_session ** sessions, int * n_sessions, tcp_session * ts)
{
	int i;
	char srcbuf[BUFLEN], dstbuf[BUFLEN];
	tcp_frag * curr, * prev;
	int tcp_session_not_found=0;
	for(i=0;i<(*n_sessions);i++)
		if(sessions[i] == ts)
			break;
	if(i>=*n_sessions)
		assert(tcp_session_not_found);
	assert(*n_sessions>0);
	inet_ntop(AF_INET,&ts->sip,srcbuf,BUFLEN);
	inet_ntop(AF_INET,&ts->dip,dstbuf,BUFLEN);
	fprintf(stderr, "DELETING %s:%d --> %s:%d with %d segments left at index %d \n",
			srcbuf, ntohs(ts->sport), 
			dstbuf, ntohs(ts->dport),
			ts->n_segs, i);
	(*n_sessions)--;
	sessions[i]=sessions[*n_sessions];
	curr = ts->next;
	while(curr)
	{
		prev=curr;
		bzero(curr,sizeof(*curr));
		curr = curr->next;
		free(prev);
	}
	bzero(ts,sizeof(*ts));
	free(ts);	
	return 0;
}
/********************************************************************
 * static mk_test_packet(char * buf,int buflen, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);
 */
static int mk_test_packet(char * buf,int buflen, uint32_t sip, uint32_t dip, uint32_t seq, uint16_t sport, uint16_t dport, char *data, int datalen,
		struct oft_tcphdr ** r_tcp, struct oft_iphdr ** r_ip)
{
	struct oft_tcphdr * tcp;
	struct oft_iphdr * ip;
	int size;
	assert(BUFLEN > ( sizeof(*ip) + sizeof(*tcp) + datalen));

	bzero(buf,BUFLEN);
	size = 0;
	ip = (struct oft_iphdr *) &buf[size];
	size+=sizeof(*ip);
	tcp= (struct oft_tcphdr *) &buf[size];
	ip->saddr = sip;
	ip->daddr = dip;
	ip->ihl=5;

	tcp->source = sport;
	tcp->dest  = dport;
	tcp->seq = htonl(seq);
	tcp->doff = 5;
	size+=sizeof(*tcp);
	memcpy(&buf[size], data, datalen);
	size+= datalen;
	*r_tcp=tcp;
	*r_ip = ip;
	ip->tot_len = htons(size);
	return size;
	
}

/********************************************************************
 * 	unitests
 */

int unittest_do_tcp_session_delete(void)
{
	int success=1;
	tcp_session ** tcp_sessions;
	int max=10;
	int n_sessions=0;
	char p1[BUFLEN];
	int i,j;
	struct oft_tcphdr * tcp;
	struct oft_iphdr * ip;
	char * data = "blah blah!";

	tcp_sessions  = malloc( max * sizeof(tcp_session *));
	
	for(i = 0 ; i < 10 ; i ++ )  // make ten connections and add some data
	{
		mk_test_packet(p1, BUFLEN, i, 2 , // src ip, dst ip
				0, 	// ISN
				6633, 12345, 
				data, strlen(data), &tcp, &ip);
		tcp_sessions[i] = tcp_session_new(ip,tcp);
		for( j = 0 ; j < 10 ; j ++)
			tcp_session_add_frag(tcp_sessions[i], j * strlen(data) , data, strlen(data), strlen(data));
	}
	n_sessions=10;
	tcp_session_delete(tcp_sessions, &n_sessions, tcp_sessions[0]);
	tcp_session_delete(tcp_sessions, &n_sessions, tcp_sessions[9]);
	tcp_session_delete(tcp_sessions, &n_sessions, tcp_sessions[6]);
	tcp_session_delete(tcp_sessions, &n_sessions, tcp_sessions[4]);
	tcp_session_delete(tcp_sessions, &n_sessions, tcp_sessions[1]);
	tcp_session_delete(tcp_sessions, &n_sessions, tcp_sessions[3]);
	tcp_session_delete(tcp_sessions, &n_sessions, tcp_sessions[5]);
	tcp_session_delete(tcp_sessions, &n_sessions, tcp_sessions[7]);
	tcp_session_delete(tcp_sessions, &n_sessions, tcp_sessions[2]);
	tcp_session_delete(tcp_sessions, &n_sessions, tcp_sessions[8]);

	assert(n_sessions == 0);


	return success;
}

