#! /usr/bin/python2.7
# NOTE: Change the interpreter to correspond to your installation of Python 2.7

import argparse
from scanner import *

def argparse():
   parser = argparse.ArgumentParser()
   parser.add_argument("-t", help="Target to scan")
   parser.add_argument("-sT", help="Performs a TCP Connect scan")
   parser.add_argument("-sS", help="Performs a TCP Half (Stealth) scan")
   parser.add_argument("-sX", help="Performs a TCP Xmas scan")
   parser.add_argument("-sN", help="Performs a TCP Null scan")
   parser.add_argument("-sF", help="Performs a TCP Fin scan")
   parser.add_argument("-q", "--quiet", help="Send any output to a log file",
                       action="log", default=None, type=str)
   
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
   pass
