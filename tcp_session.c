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
	tcp_session * ts = malloc_and_check(sizeof(tcp_session));
	ts->sip=ip->saddr;
	ts->dip=ip->daddr;
	ts->sport=tcp->source;	// network byte order!
	ts->dport=tcp->dest;	// network byte order!
	ts->seqno = ntohl(tcp->seq);	// host byte order (we do arith on this)
	ts->next=NULL;	

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
			return 1;
		curr=curr->next;
	}
	return 0;	// ran out of fragments before finding len bytes
}

/****************************
 * 	add this fragment to this session
 */
int tcp_session_add_frag(tcp_session * ts, uint32_t seqno , char * tmpdata, int cap_len, int full_len)
{
	char srcaddr[BUFLEN];
	char dstaddr[BUFLEN];
	char *data,*orig_data;
	int count=0;
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
	curr = ts->next;

	while(curr)	// search for where this frag fits into the stream
	{
		count++;
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
				inet_ntop(AF_INET,&ts->sip,srcaddr,BUFLEN);
				inet_ntop(AF_INET,&ts->dip,dstaddr,BUFLEN);
				fprintf(stderr,"WEIRD: ignoring inconsistant overlapping segments for "
						"%s:%u-> %s:%u start_overlap %u end %u\n",
						srcaddr, ts->sport,
						dstaddr, ts->dport,
						start_overlap, end_overlap - start_overlap);
			}
			if(seqno < start_overlap)	// is there something new before the overlap?	// FIXME: PAWS!
			{
				// create a new frag just for the new part before the current frag
				// FIXME: this is duplicated code from outside the while(); not obvious how to fix
				neo = malloc_and_check(sizeof(tcp_frag));
				neo->start_seq = seqno;
				neo->len = start_overlap - seqno;
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
 * 		return 0 if len continuguous bytes not available
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
			return -1;
		}
		if(curr->start_seq != ts->seqno)
		{
			fprintf(stderr,"WARNING: tried to tcp_session_pull() non-contiguous data\n");
			return -1;
		}
		if(curr->len <= len) 	// do we erase the whole fragment?
		{
			len -= curr->len;
			ts->next = curr->next;
			ts->seqno = curr->start_seq+curr->len;
			free(curr);
		}
		else
		{
			// just erase the first part of the current fragment
			// todo this: create a new fragment with what's left
			neo = malloc_and_check(sizeof(tcp_frag));
			neo->start_seq = curr->start_seq + len;
			neo->len = curr->len-len;
			memcpy(neo->data,&curr->data[len],neo->len);
			neo->next = curr->next;
			ts->next = neo;
			ts->seqno = neo->start_seq;
			free(curr);
			len= 0;
		}
	}
	return 0;
}


/*************************************************************
 * int tcp_session_count_frags(tcp_session *ts);
 * 	count the number of fragments
 */

int tcp_session_count_frags(tcp_session *ts)
{
	tcp_frag * curr;
	int count=0;
	assert(ts);
	curr = ts->next;
	while(curr)
	{
		count++;
		curr=curr->next;
	}
	return count;
}

