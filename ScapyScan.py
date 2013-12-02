from scanner import *

def map_scanner_arg(arg):
   scanners = {
      'sT'  :  TCPConnScan,
      'sS'  :  TCPHalfScan,
      'sX'  :  TCPXmasScan,
      'sN'  :  TCPNullScan,
      'sF'  :  TCPFinScan,
   }

   return scanners[arg]
