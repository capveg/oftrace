#ifndef OFTRACE_H
#define OFTRACE_H

#include <pcap.h>
#include <pcap-bpf.h>

// #include <pcap.h>	// Ha! Fools.. pcap.h doesn't document any of this :-(
// Grabbed from http://wiki.wireshark.org/Development/LibpcapFileFormat#head-d5fe7311203e1a2d569fd9de521699150c44f708
//


#define PCAP_MAGIC 		0xa1b2c3d4
#define PCAP_BACKWARDS_MAGIC 	0xd4c3b2a1

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

#endif
