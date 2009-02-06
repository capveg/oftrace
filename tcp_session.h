#ifndef TCP_SESSION_H
#define TCP_SESSION_H

// hack to get uint32_t etc..
#include "oftrace.h"
typedef struct tcp_frag {
	uint32_t start_seq;
	uint16_t len;
	char * data;
	struct tcp_frag * next;
} tcp_frag;

typedef struct tcp_session {
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;	// stored in network byte order!
	uint16_t dport;	// stored in network byte order!
	uint32_t seqno;
	tcp_frag * next;
} tcp_session;


tcp_session * tcp_session_new(struct iphdr * ip, struct tcphdr * tcp);

/***************************
 * 	find the session matching the passes parameters
 * 	return NULL if not found
 */
tcp_session * tcp_session_find(tcp_session ** sessions, int n_sessions,struct iphdr * ip, struct tcphdr * tcp);

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

#endif
