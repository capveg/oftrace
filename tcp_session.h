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

#ifndef TCP_SESSION_H
#define TCP_SESSION_H

// hack to get uint32_t etc..
#include "oftrace.h"
typedef struct tcp_frag {
	uint32_t start_seq;
	uint16_t len;
	char data[BUFLEN];
	struct tcp_frag * next;
} tcp_frag;

typedef struct tcp_session {
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;	// stored in network byte order!
	uint16_t dport;	// stored in network byte order!
	uint32_t seqno;	// stored in HOST byte order
	tcp_frag * next;
} tcp_session;


tcp_session * tcp_session_new(struct oft_iphdr * ip, struct oft_tcphdr * tcp);

/***************************
 * 	find the session matching the passes parameters
 * 	return NULL if not found
 */
tcp_session * tcp_session_find(tcp_session ** sessions, int n_sessions,struct oft_iphdr * ip, struct oft_tcphdr * tcp);

/****************************
 * 	does this session have at least len contiguous bytes queued?
 * 	if yes, copy them to data, but don't dequeue, return 1
 * 	else return 0
 */
int tcp_session_peek(tcp_session * ts, char * data, int len);

/****************************
 * 	add this fragment to this session
 */
int tcp_session_add_frag(tcp_session * ts, uint32_t seqno, uint8_t * data, int cap_len, int full_len);

/****************************
 * 	remove/dequeue len bytes from this session
 * 		return 0 if len continuguous bytes not available
 * 		don't bother copying it, b/c the tcp_session_peek pretty
 * 		much already does that
 */
int tcp_session_pull(tcp_session * ts, int len);

#endif
