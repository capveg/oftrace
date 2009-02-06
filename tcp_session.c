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
	ts->seqno = tcp->seq;
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
 * 	else return 0
 */
int tcp_session_peek(tcp_session * ts, char * data, int len);

/****************************
 * 	add this fragment to this session
 */
int tcp_session_add_frag(tcp_session * ts, char * data, int cap_len, int full_len);

/****************************
 * 	remove/dequeue len bytes from this session
 * 		return 0 if len continuguous bytes not available
 * 		don't bother copying it, b/c the tcp_session_peek pretty
 * 		much already does that
 */
int tcp_session_pull(tcp_session * ts, int len);

/****************************
 * 	return the current seqno
 */
uint32_t tcp_session_seqno(tcp_session * ts);

