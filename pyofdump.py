#!/usr/bin/python

import sys
import struct
from socket import *
from optparse import OptionParser
from oftrace import oftrace

def main():
    usage = "usage: %prog [options] arg"
    parser = OptionParser(usage)
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

    do_analyze(options.filename,options.controller,options.port)

def do_analyze(filename,controller,port):
    msg_count = 0
    start_time = {}
    # a bit ugly...
    ip = inet_pton(AF_INET,controller)
    ip = struct.unpack("I",ip)[0]

    oft = oftrace.oftrace_open(filename)
    m = oftrace.oftrace_next_msg(oft,ip,port)

    # save this for timestamp reference
    if (m != None):
        start_time["sec"] = m.phdr.ts_sec
        start_time["usec"] = m.phdr.ts_usec
    # dump all packets
    while ( m != None):
        msg_count = msg_count+1
        dump_msg(msg_count,m,start_time)
        m = oftrace.oftrace_next_msg(oft,ip,port)

def dump_msg(msg_count,m,start_time):
    curr_time = {}
    curr_time["sec"] = m.phdr.ts_sec - start_time["sec"]
    if(m.phdr.ts_usec < start_time["usec"]):
        curr_time["usec"] = m.phdr.ts_usec + 1000000 - start_time["usec"]
        curr_time["sec"] = curr_time["sec"] - 1
    else:
        curr_time["usec"] = m.phdr.ts_usec - start_time["usec"]

    src_ip = inet_ntop(AF_INET,struct.pack("I",m.ip.saddr))
    dst_ip = inet_ntop(AF_INET,struct.pack("I",m.ip.daddr))
    
    
    print("%d. %6d.%6d: FROM %s:%u\tTO %s:%u\t OFP_TYPE %d LEN %d") % \
               (msg_count,
                curr_time["sec"],
                curr_time["usec"],
                src_ip,
                ntohs(m.tcp.source),
                dst_ip,
                ntohs(m.tcp.dest),
                m.ofph.type,
                ntohs(m.ofph.length))
                      
if __name__ == "__main__":
    main()
