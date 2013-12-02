#! /usr/bin/python2.7
# NOTE: Change the interpreter to correspond to your installation of Python 2.7

import argparse
import sys
from scanner import *
from config import COMMN_PORTS

Scanners = []
target = None
verbose = True
timeout = 2
ports = []

def argsparser():
   global Scanners, target, verbose, timeout, ports
   prog = __file__
   usage = "%s -t <target> [options]\n" % prog
   parser = argparse.ArgumentParser(usage=usage, prog=prog)
   parser.add_argument("-t", help="Target to scan", required=True,
                       dest="target")
   parser.add_argument("-sT", "--conn-scan", help="Perform a TCP Connect scan",
                       action="store_true", dest="conn_scan")
   parser.add_argument("-sS", "--half-scan", help="Perform a TCP Half (Stealth) scan",
                       action="store_true", dest="half_scan")
   parser.add_argument("-sX", "--xmas-scan", help="Perform a TCP Xmas scan",
                       action="store_true", dest="xmas_scan")
   parser.add_argument("-sN", "--null-scan", help="Perform a TCP Null scan",
                       action="store_true", dest="null_scan")
   parser.add_argument("-sF", "--fin-scan", help="Perform a TCP Fin scan",
                       action="store_true", dest="fin_scan")
   parser.add_argument("-v", help="Toggle verbosity", dest="verbose",
                       default=True, action="store_false")
   parser.add_argument("-W", help="Timeout", type=int,
                       default=2, dest="timeout")
   parser.add_argument("-p", help="Ports to scan", default=None,
                       dest="ports")

   args = parser.parse_args()
   
   target = args.target

   validarg = (args.conn_scan or args.half_scan or args.xmas_scan or
               args.null_scan or args.fin_scan)
   if not validarg:
      parser.error("Specify at least one of [-sT, -sS, -sX, -sN, -sF]")
   else:
      if args.conn_scan: Scanners.append(TCPConnScan)
      if args.half_scan: Scanners.append(TCPHalfScan)
      if args.xmas_scan: Scanners.append(TCPXmasScan)
      if args.null_scan: Scanners.append(TCPNullScan)
      if args.fin_scan: Scanners.append(TCPFinScan)
   
   verbose = args.verbose

   timeout = args.timeout

   if args.ports:
      ports = args.ports
   else:
      ports = COMMN_PORTS.keys()

if __name__ == "__main__":
   argsparser()
   for Scanner in Scanners:
      scanner = Scanner(target, timeout=timeout, verbose=verbose)
      scanner.scan(ports)

   print "Completed %d scans on %s." % (len(Scanners), target)
