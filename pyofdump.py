#!/usr/bin/python

import sys,socket
from optparse import OptionParser


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


if __name__ == "__main__":
    main()
