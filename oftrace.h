#ifndef OFTRACE_H
#define OFTRACE_H

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#include <pcap.h>
//#include <pcap-bpf.h>

#include <openflow/openflow.h>


#define PCAP_MAGIC 		0xa1b2c3d4
#define PCAP_BACKWARDS_MAGIC 	0xd4c3b2a1

#ifndef BUFLEN
// max packetsize * fudge factor of two
#define BUFLEN (65536<<1)
#endif


// #include <pcap.h>	// Ha! Fools.. pcap.h doesn't document any of this :-(
// Grabbed from http://wiki.wireshark.org/Development/LibpcapFileFormat#head-d5fe7311203e1a2d569fd9de521699150c44f708
//
typedef struct pcaprec_hdr_s {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

// convenience pointers for some openflow messages

typedef union openflow_msg_ptr {
	struct ofp_packet_in * packet_in;
	struct ofp_packet_out * packet_out;
	struct ofp_flow_mod * flow_mod;
} openflow_msg_ptr;

/*********************************************************
 * Actual openflow message structure
 * 	- all data is stored in data
 * 	- everthing else is just a convenience pointer
 */

typedef struct openflow_msg
{
	// where the data is stored
	char data[BUFLEN];
	int captured;
	struct pcaprec_hdr_s phdr;	// when the packet was received; for fragments, this actually the packet that 
					// 	filled in the whole that cause this message to be pushed to the application
					// 	- subtle but important distinction
	// OFPT_something
	uint16_t type;		
	// convenience pointers
	struct ether_header * ether;
	struct iphdr * ip;
	struct tcphdr * tcp;
	struct ofp_header * ofph;
	union openflow_msg_ptr ptr;
} openflow_msg;

struct oftrace;
typedef struct oftrace oftrace;

/******************************************************
 * main interface
 */

// pass a string to the pcap file location
// 	return an opaque pointer to the oftrace info on success
// 	or NULL on failure
oftrace * oftrace_open(char * pcapfile);

// pass an oftrace, and an IP and PORT to look for,
// 	and a reference to an openflow_msg struct
// 	return 1 if found, 0 otherwise 
const openflow_msg * oftrace_next_msg(oftrace * oft, uint32_t ip, int port);

// restart tracing from the beginning of the pcap file (implicit on open) 
int oftrace_rewind(oftrace * oft);

#endif
