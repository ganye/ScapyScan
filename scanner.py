from scapy.all import *
from logger import Logger
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

__all__ = ["TCPConnScan", "TCPHalfScan", "TCPXmasScan", "TCPFinScan", "TCPNullScan",]

class _PortScanner:
   """
   Base PortScanner object to inherit from.
   """
   __scanner__ = "Base Scanner"  # Used in the end report

   def __init__(self, target, timeout=10, verbose=True):
      self._target = target
      self._timeout = timeout
      self._log = Logger(verbose=verbose)
      self._results = {}

   def set_target(self, new_target):
      self._target = new_target
   
   def scan(self, ports):
      for port in list(ports):
         self._scan_port(port)
      self._report()

   def _scan_port(self, port):
      raise NotImplementedError()

   def _report(self):
      scanned = len(self._results)
      closed = 0
      print "%s results for %s" % (self.__scanner__, self._target)
      print "PORT\tSTATE"
      for key, value in sorted(self._results.iteritems()):
         if value is "closed":
            closed += 1
         print "%-7s %s" % (key, value)
      print "Scanned %d ports, of which %d were closed." % (scanned, closed)

class TCPConnScan(_PortScanner):
   __scanner__ = "TCP Connect Scan"

   def _scan_port(self, port):
      src_port = RandShort()
      # Sends a SYN 
      resp = sr1(IP(dst=self._target)/TCP(sport=src_port, dport=port, flags="S"), timeout=self._timeout, verbose=False)
      
      if resp is None:
         self._results[port] = "closed"
      
      elif resp.haslayer(TCP):
         if resp.getlayer(TCP).flags == 0x12:
            send_rst = sr(IP(dst=self._target)/TCP(sport=src_port, dport=port, flags="AR"), timeout=self._timeout, verbose=False)
            self._results[port] = "open"
         
         elif resp.getlayer(TCP).flags == 0x14:
            self._results[port] = "closed"

class TCPHalfScan(_PortScanner):
   __scanner__ = "TCP Half Scan"

   def _scan_port(self, port):
      src_port = RandShort()
      resp = sr1(IP(dst=self._target)/TCP(sport=src_port, dport=port, flags="S"), timeout=self._timeout, verbose=False)
      
      if resp is None:
         self._results[port] = "closed"
      
      elif resp.haslayer(TCP):   
         if resp.getlayer(TCP).flags == 0x12:
            rst = sr(IP(dst=self._target)/TCP(sport=src_port, dport=port, flags="R"), timeout=self._timeout, verbose=False)
            self._results[port] = "open"
         
         elif resp.getlayer(TCP).flags == 0x14:
            self._results[port] = "closed"

      elif resp.haslayer(ICMP):
         if int(resp.getlayer(ICMP).type) == 3 and \
            int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]:  # Destination Host Unreachable
            self._results[port] = "filtered"

class TCPXmasScan(_PortScanner):
   __scanner__ = "TCP Xmas Scan"

   def _scan_port(self, port):
      src_port = RandShort()
      resp = sr1(IP(dst=self._target)/TCP(sport=src_port, dport=port, flags="FPU"), timeout=self._timeout, verbose=False)
      if resp is None:
         self._results[port] = "open|filtered"

      elif resp.haslayer(TCP):
         if resp.getlayer(TCP).flags == 0x14:
            self._results[port] = "closed"

      elif resp.haslayer(ICMP):
         if int(resp.getlayer(ICMP).type) == 3 and \
            int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]:  # Destination Host Unreachable
            self._results[port] = "filtered"

class TCPFinScan(_PortScanner):
   __scanner__ = "TCP FIN Scan"

   def _scan_port(self, port):
      src_port = RandShort()
      resp = sr1(IP(dst=self._target)/TCP(sport=src_port, dport=port, flags="F"), timeout=self._timeout, verbose=False)
      if resp is None:
         self._results[port] = "open|filtered"

      elif resp.haslayer(TCP):
         if resp.getlayer(TCP).flags == 0x14:
            self._results[port] = "closed"

      elif resp.haslayer(ICMP):
         if int(resp.getlayer(ICMP).type) == 3 and \
            int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]: # Destination Host Unreachable
            self._results[port] = "filtered"

class TCPNullScan(_PortScanner):
   __scanner__ = "TCP Null Scan"

   def _scan_port(self, port):
      src_port = RandShort()
      resp = sr1(IP(dst=self._target)/TCP(sport=src_port, dport=port, flags=""), timeout=self._timeout, verbose=False)
      if resp is None:
         self._results[port] = "open|filtered"

      elif resp.haslayer(TCP):
         if resp.getlayer(TCP).flags == 0x14:
            self._results[port] = "closed"

      elif resp.haslayer(ICMP):
         if int(resp.getlayer(ICMP).type) == 3 and \
            int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]: # Destination Host Unreachable
            self._results[port] = "filtered"
