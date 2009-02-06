#ifndef OFTRACE_H
#define OFTRACE_H

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#include <pcap.h>
#include <pcap-bpf.h>

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
typedef struct pcap_hdr_s {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
} pcap_hdr_t;


typedef struct pcaprec_hdr_s {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef union openflow_msg_type {
	struct ofp_packet_in * packet_in;
	struct ofp_packet_out * packet_out;
	struct ofp_flow_mod * flow_mod;
} openflow_msg_type;

/*********************************************************
 * Actual openflow message structure
 * 	- all data is stored in data
 * 	- everthing else is just a convenience pointer
 */

typedef struct openflow_msg
{
	// where the data is stored
	unsigned char data[BUFLEN];
	int captured;
	char more_messages_in_packet;	// are there multiple openflow messages in the same packet?
	struct pcaprec_hdr_s phdr;
	// convenience pointers
	struct ether_header * ether;
	struct iphdr * ip;
	struct tcphdr * tcp;
	struct ofp_header * ofph;
	union openflow_msg_type type;
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
int oftrace_next_msg(oftrace * oft, uint32_t ip, int port,openflow_msg * msg);

// restart tracing from the beginning of the pcap file (implicit on open) 
int oftrace_rewind(oftrace * oft);

#endif
