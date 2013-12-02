#! /usr/bin/python2.7
# NOTE: Change the interpreter to correspond to your installation of Python 2.7

import argparse
from scanner import *

def argsparser():
   parser = argparse.ArgumentParser()
   parser.add_argument("-t", help="Target to scan")
   parser.add_argument("-sT", "--conn-scan", help="Performs a TCP Connect scan",
                       action="store_true")
   parser.add_argument("-sS", "--half-scan", help="Performs a TCP Half (Stealth) scan",
                       action="store_true")
   parser.add_argument("-sX", "--xmas-scan", help="Performs a TCP Xmas scan",
                       action="store_true")
   parser.add_argument("-sN", "--null-scan", help="Performs a TCP Null scan",
                       action="store_true")
   parser.add_argument("-sF", "--fin-scan", help="Performs a TCP Fin scan",
                       action="store_true")
   parser.add_argument("-q", "--quiet", help="Send any output to a log file",
                       default=None)
   
   return parser.parse_args()

def map_scanner_arg(arg):
   scanners = {
      'sT'  :  TCPConnScan,
      'sS'  :  TCPHalfScan,
      'sX'  :  TCPXmasScan,
      'sN'  :  TCPNullScan,
      'sF'  :  TCPFinScan,
   }

   try:
      return scanners[arg]
   except KeyError:
      return None

if __name__ == "__main__":
   args = argsparser()
   print args
