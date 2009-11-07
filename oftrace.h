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

#ifndef OFTRACE_H
#define OFTRACE_H

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#include <features.h>

#include <pcap.h>
//#include <pcap-bpf.h>

#include <openflow/openflow.h>


#define PCAP_MAGIC 		0xa1b2c3d4
#define PCAP_BACKWARDS_MAGIC 	0xd4c3b2a1

#ifndef DLT_EN10MB
#define DLT_EN10MB      1       /* Ethernet (10Mb) */
#endif
#ifndef DLT_LINUX_SSL 
#define DLT_LINUX_SLL   113
#endif


#ifndef BUFLEN
// max packetsize * fudge factor of two
#define BUFLEN (65536<<1)
#endif


struct dlt_linux_sll	// copied from http://www.mail-archive.com/tcpdump-workers@lists.tcpdump.org/msg00944.html
{
	uint16_t packet_type;
	uint16_t ARPHRD;
	uint16_t slink_length;
	uint8_t  bytes[8];
	uint16_t ether_type;
};

// convenience pointers for some openflow messages

typedef union openflow_msg_ptr {
	struct ofp_packet_in * packet_in;
	struct ofp_packet_out * packet_out;
	struct ofp_flow_mod * flow_mod;
} openflow_msg_ptr;


// Manually include them here for portability and swig-happiness

struct oft_iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int ihl:4;
	unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int version:4;
	unsigned int ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
	/*The options start here. */
};

struct oft_tcphdr
{
	uint16_t source;
	uint16_t dest;
	uint32_t seq;
	uint32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t res1:4;
	uint16_t doff:4;
	uint16_t fin:1;
	uint16_t syn:1;
	uint16_t rst:1;
	uint16_t psh:1;
	uint16_t ack:1;
	uint16_t urg:1;
	uint16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t doff:4;
	uint16_t res1:4;
	uint16_t res2:2;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
	uint16_t window;
	uint16_t check;
	uint16_t urg_ptr;
};


/* 10Mb/s ethernet header */
struct oft_ethhdr
{
  uint8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
  uint8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
  uint16_t ether_type;		        /* packet type ID field	*/
};



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
	struct dlt_linux_sll *linux_sll;
	struct oft_ethhdr * ether;
	struct oft_iphdr * ip;
	struct oft_tcphdr * tcp;
	struct ofp_header * ofph;
	union openflow_msg_ptr ptr;
	struct oft_ethhdr * embedded_packet;
} openflow_msg;

struct oftrace;
typedef struct oftrace oftrace;

/******************************************************
 * main interface
 */

/**
 * Create a oftrace context that parses openflow messages from a tcpdump file
 * 	that match filterstr
 * @param pcapfile	The filename of the tcpdump
 * @param filterstr	A pcap-style filter string to send to pcap_set_filter()
 * @return an oftrace context
 */
oftrace * oftrace_open_offline(char * pcapfile, char * filterstr);

/**
 * Create a oftrace context that parses openflow messages on device
 * 	that match filterstr
 * @param device	inferface, e..g., 'eth0'
 * @param filterstr	A pcap-style filter string to send to pcap_set_filter()
 * @return an oftrace context
 */
oftrace * oftrace_open_live(char * device, char * filterstr);

/**
 * pass an oftrace context and get the next openflow message in the trace
 * @param oft a oftrace context, as returned from oftrace_open_*
 * @return a pointer to an openflow_msg struct ;; do not free! \
 * 	if NULL, then an error occured (call oftrace_get_error()) or EOF (if no error)
 */
const openflow_msg * oftrace_next_msg(oftrace * oft);


/**
 * Change the filter set for the oftrace to filterstr
 * @param oft a oftrace context, as returned from oftrace_open_*
 * @param filterstr	A pcap-style filter string to send to pcap_set_filter()
 * @return 0 on success, -1 on error
 */
int oftrace_set_filter(oftrace *oft, char * filterstr);

/**
 * Return the file descriptor associated with the trace suitable for 
 * 	input into select() or poll()
 * Just a front end to pcap_get_selectable_fd()
 * @param oft a oftrace context, as returned from oftrace_open_*
 * @return -1 if an offline trace, or a valid fd otherwise
 */
int oftrace_get_fd(oftrace *oft);

/**
 * restart tracing from the beginning of the pcap file (implicit on open) 
 * 	only works for an offline oftrace; will return an error for live traces
 * @param oft	An oftrace context as returned by oftrace_open_offline()
 * @return 0 on success, -1 on error
 */
int oftrace_rewind(oftrace * oft);

/**
 * return the fraction of the file processed; only makes sense for 
 * 	an offline otrace
 * @param oft	An oftrace context as returned by oftrace_open_offline()
 * @return offline trace: the fraction of the file processed from 0 to 1; online return -1
 */
double oftrace_progress(oftrace *oft);

/**
 * return an integer array, where each element is the number of stored tcp fragments
 *  of each tcp session being tracked
 *  caller allocates list, and specifies its initial length via len
 *  elements into the array
 *  	- used mainly for debugging the tcp segment parsing mechanism
 *  @param oft An oftrace context as returned by oftrace_open_*()
 *  @param len The length of the list parameter
 *  @param list a caller-alloacted array of integers
 *  @return the total number of sessions tracked; fill in min(len,n_sessions)
 */
int oftrace_tcp_stats(oftrace *oft, int len, int *list);

/**
 * Pull the next error off of the oftrace error stack.
 * 	If no error, returns NULL and *err_code is undefined
 * 	If error, returns a human readable string and *err_code is one of OFTRACE_ERR_*
 * Note that non-fatal errors can be set by oftrace_next_msg() even though it returns
 * 	a valid otrace_msg
 * @param oft An oftrace context as returned by oftrace_open_*()
 * @param err_code  on return, set to one of OFTRACE_ERR_*
 * @return NULL if no error ; a human readable str if there exists an error
 */
const char * oftrace_get_error(oft, int *err_code);



#define OFTRACE_ERR_NONE	0x00
#define OFTRACE_ERR_PCAP	0x01

#endif
