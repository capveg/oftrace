#!/usr/bin/python

####################################################################
# Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior
# University
# 
# We are making the OpenFlow specification and associated documentation
# (Software) available for public use and benefit with the expectation
# that others will use, modify and enhance the Software and contribute
# those enhancements back to the community. However, since we would
# like to make the Software available for broadest use, with as few
# restrictions as possible permission is hereby granted, free of charge,
# to any person obtaining a copy of this Software to deal in the Software
# under the copyrights without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
# NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
# THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# 
# The name and trademarks of copyright holder(s) may NOT be used in
# advertising or publicity pertaining to the Software or any derivatives
# without specific, written prior permission.
####################################################################

# calculate the time between a link layer discovery protocol (lldp) message
#  and its response


import sys
import struct
from socket import *
from optparse import OptionParser
from oftrace import oftrace
import copy
import pdb

Infinity=10.0
MinProgress=0.001

def main():
    usage = "usage: %prog [options] arg"
    description = "A spimple program that prints the response time for lldp probes"
    parser = OptionParser(usage)
    parser.description = description
    parser.add_option("-f","--file",dest="filename",
                      default="hyper.trace",
                      help="read trace from file")
    parser.add_option("-c","--controller",dest="controller",
                      default="0.0.0.0",
                      help="controller from where to capture packets. Defaults to 0.0.0.0 (capture all controllers)")
    parser.add_option("-p","--port",dest="port",
                      default="6633",type=int,
                      help="tcp port for openflow messages")

    (options,args) = parser.parse_args()

    sys.stderr.write ("Reading %s from controller %s , port %d\n" % \
          (options.filename,options.controller,options.port))

    calc_stats(options.filename,options.controller,options.port)


def calc_stats(filename,controller,port):
	pending = {}

	ip = inet_pton(AF_INET,controller)
	ip = struct.unpack("I",ip)[0]

	oft = oftrace.oftrace_open(filename)
	m = oftrace.oftrace_next_msg(oft,ip,port)
	last_progress=-1.0
	while(m != None):
		progress = oftrace.oftrace_progress(oft)
		if ( progress > ( last_progress + MinProgress)) :
			sys.stderr.write( "--------- %f done ----\n" % (progress))
			last_progress=progress
		if m.type == oftrace.OFPT_PACKET_OUT:
			if m.ptr.packet_out.buffer_id != 4294967295L:	# skip if this packet_out 
				m = oftrace.oftrace_next_msg(oft,ip,port)
				continue				# is releasing a packet in a buffer
			eth = m.embedded_packet
			etype = ntohs(eth.ether_type)
			# capture only LLDP packets
			if(etype == 0x88cc):
				# don't store the whole message. python seems to trouble with
				# shallow and deep copies of swig objects...
				msg = {}
				msg["src_ip"] = inet_ntop(AF_INET,struct.pack("I",m.ip.saddr))
				msg["tcp_src"] = m.tcp.source
				msg["dst_ip"] = inet_ntop(AF_INET,struct.pack("I",m.ip.daddr))
				msg["tcp_dst"] = m.tcp.dest
				msg["sec"] = m.phdr.ts_sec
				msg["usec"] = m.phdr.ts_usec
				msg["type"] = m.type

				# enqueue packet in pending-response queue
				srcdst = srcdst2str(eth.ether_dhost , eth.ether_shost);
				if pending.has_key(srcdst):
					print_dropped(pending,srcdst)
				pending[srcdst] = msg
		elif(m.type == oftrace.OFPT_PACKET_IN):
			eth = m.embedded_packet
			etype = ntohs(eth.ether_type)
			# capture only LLDP packets
			if(etype == 0x88cc):
				srcdst = srcdst2str(eth.ether_dhost , eth.ether_shost);
		#		pdb.set_trace()
				if pending.has_key(srcdst):
					src_ip = inet_ntop(AF_INET,struct.pack("I",m.ip.saddr))
					dst_ip = inet_ntop(AF_INET,struct.pack("I",m.ip.daddr))
					diff_time = timesub(m,pending[srcdst])
					print ("%ld.%.6ld secs_to_resp %ld.%.6ld %s from %s:%u -> %s:%u (%d packets queued)") % \
						(diff_time["sec"],
						 diff_time["usec"],
						 pending[srcdst]['sec'],
						 pending[srcdst]['usec'],
						 srcdst,
						 src_ip,
						 ntohs(m.tcp.source),
						 dst_ip,
						 ntohs(m.tcp.dest),
						 len(pending))
					del pending[srcdst]
		# grab next message at bottom of loop b/c Python is brain dead
		# 	and doesn't allow this inside the conditional
		#print "----------- Grabbing next packet ----------"
		m = oftrace.oftrace_next_msg(oft,ip,port)
		#print "----------- DONE ----------"

def print_dropped(list,key):
	msg = list[key]
	print ("%ld.%.6ld secs_to_resp-dropped! %s from %s:%u -> %s:%u (%d packets queued)") % \
		(Infinity,
		 0,
		 key,
		 msg["src_ip"],
		 ntohs(msg['tcp_src']),
		 msg['dst_ip'],
		 ntohs(msg['tcp_dst']),
		 len(list))
	
def srcdst2str(srcC,dstC):
	src = oftrace.cdata(srcC,6)
	dst = oftrace.cdata(dstC,6)
	return "%s->%s" % ( src.encode("hex"), 
			dst.encode("hex"))


def timesub(m,msg):
    orig_time = {}
    orig_time["sec"] = msg["sec"]
    orig_time["usec"] = msg["usec"]
    
    curr_time = {}
    curr_time["sec"] = m.phdr.ts_sec
    curr_time["usec"] = m.phdr.ts_usec
    
    diff_time = {}
    diff_time["sec"] = m.phdr.ts_sec - orig_time["sec"]
    if(m.phdr.ts_usec < orig_time["usec"]):
        diff_time["usec"] = m.phdr.ts_usec + 1000000 - orig_time["usec"]
        diff_time["sec"] = diff_time["sec"] - 1
    else:
        diff_time["usec"] = m.phdr.ts_usec - orig_time["usec"]
    return diff_time

        
if __name__ == "__main__":
    main()
