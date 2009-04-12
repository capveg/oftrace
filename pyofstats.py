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



import sys
import struct
from socket import *
from optparse import OptionParser
from oftrace import oftrace
import copy

def main():
    usage = "usage: %prog [options] arg"
    description = "A spimple program that prints the response time for every packet-in and its respective response (packet-out/flow-mod)"
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

    print ("Reading %s from controller %s , port %d") % \
          (options.filename,options.controller,options.port)

    calc_stats(options.filename,options.controller,options.port)


def calc_stats(filename,controller,port):
    pending = {}

    ip = inet_pton(AF_INET,controller)
    ip = struct.unpack("I",ip)[0]

    oft = oftrace.oftrace_open(filename)
    m = oftrace.oftrace_next_msg(oft,ip,port)

    while(m != None):
        if(m.type == oftrace.OFPT_PACKET_IN):
            eth = oftrace.uint_to_oft_ethhdr(m.ptr.packet_in.data)
            etype = ntohs(eth.ether_type)

            # don't capture LLDP packets
            if(etype != 0x88cc):
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
                buf_id = m.ptr.packet_in.buffer_id
                pending[buf_id] = msg

        elif(m.type == oftrace.OFPT_PACKET_OUT or m.type == oftrace.OFPT_FLOW_MOD):
            if (m.type == oftrace.OFPT_PACKET_OUT):
                buf_id = m.ptr.packet_out.buffer_id
            else:
                buf_id = m.ptr.flow_mod.buffer_id
            if pending.has_key(buf_id):
                src_ip = inet_ntop(AF_INET,struct.pack("I",m.ip.saddr))
                dst_ip = inet_ntop(AF_INET,struct.pack("I",m.ip.daddr))

                diff_time = timesub(m,pending[buf_id])

                print ("%ld.%.6ld secs_to_resp buf_id:%x from %s:%u -> %s:%u (%d packets queued)") % \
                      (diff_time["sec"],
                       diff_time["usec"],
                       buf_id,
                       src_ip,
                       ntohs(m.tcp.source),
                       dst_ip,
                       ntohs(m.tcp.dest),
                       len(pending))
                # ok, now we can remove initial request (packet-in) from queue
                del pending[buf_id]
            elif(buf_id != 0xffffffff):
                print ("weird, bufid %x not found") % (buf_id)

        m = oftrace.oftrace_next_msg(oft,ip,port)


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
