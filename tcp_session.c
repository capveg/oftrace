#include <assert.h>
#include <string.h>

#include "tcp_session.h"
#include "utils.h"


/***********************
 * malloc and create a new tcp_session
 */

tcp_session * tcp_session_new(struct iphdr * ip, struct tcphdr * tcp)
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
tcp_session * tcp_session_find(tcp_session ** sessions, int n_sessions,struct iphdr * ip, struct tcphdr * tcp)
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
	tcp_frag *tf;
	int index=0;
	uint32_t seqno;
	assert(ts);

	tf = ts->next;
	seqno = ts->seqno;
	while(tf)
	{
		if(seqno != tf->start_seq)	// is the new fragment contiguous with the last?
			return 0;
		if(len<(index+tf->len))
			return -1;	// not enough buffer sent to copy next fragment
		memcpy(&data[index],tf->data,tf->len);
		seqno +=len;		// this will autowrap, no worries about PAWS
		index+=len;
		if(index>=len)		// did we find all that we were looking for?
			return 1;
		tf=tf->next;
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
		if((seqno +full_len) < curr->start_seq)	// have we gone too far?
			break;
		else if(seqno > (curr->start_seq + curr->len) )	// not far enough; next
		{
			prev=curr;
			curr=curr->next;
		}
		else
		{
			// if we are here, there is some level of (partial?) overlap
			start_overlap = MAX(seqno,curr->start_seq);
			end_overlap   = MIN(seqno+full_len, curr->start_seq + curr->len);
			if(memcmp(&curr->data[curr->start_seq-start_overlap], 
						&data[seqno-start_overlap],
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
			if(seqno < start_overlap)	// is there something new before the overlap?
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
					ts->next = neo;
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
		ts->next = neo;
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
		if(curr->start_seq != ts->seqno)
		{
			fprintf(stderr,"WARNING: tried to tcp_session_pull() non-contiguous data\n");
			return -1;
		}
		if(curr == NULL)
		{
			fprintf(stderr,"WARNING: tried to tcp_session_pull() more than was there :-(\n");
			return -1;
		}
		if(curr->len <= len) 	// do we erase the whole fragment?
		{
			len -= curr->len;
			ts->next = curr->next;
			ts->seqno = curr->start_seq;
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

