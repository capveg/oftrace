#ifndef TCP_SESSION_H
#define TCP_SESSION_H

typedef struct tcp_session {
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;	// stored in host byte order!
	uint16_t dport;	// stored in host byte order!
	uint32_t seqno;
	char * buffer;
	int buffer_size;
	int buffer_start;
	int buffer_end;
} tcp_session;


tcp_session * tcp_session_new(uint32_t sip,uint32_t dip,uint16_t sport, uint16_t dport, int32_t seqno);
// FIXME: add accessor func()s
#endif
