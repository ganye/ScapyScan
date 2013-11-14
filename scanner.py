from scapy.all import *

from types import NoneType
from logger import Logger
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

__all__ = ["TCPConnScan","TCPStealthScan",]

class _PortScanner:
   """
   Base PortScanner object to inherit from.
   """
   def __init__(self, target, timeout=10, verbose=True):
      self._target = target
      self._timeout = timeout
      self._log = Logger(verbose=verbose)
      self.open_ports = []

   def scan(self, ports):
      for port in ports:
         self._log.write("[*] Scanning port %d" % port)
         self._scan_port(port)

   def _scan_port(self, port):
      raise NotImplementedError()

   def set_target(self, new_target):
      self._target = new_target

class TCPConnScan(_PortScanner):
   def _scan_port(self, port):
      src_port = RandShort()
      resp = sr1(IP(dst=self._target)/TCP(sport=src_port, dport=port, flags="S"), timeout=self._timeout, verbose=False)
      if isinstance(resp, NoneType):
         self._log.write("[-] Port %d CLOSED" % port)
      elif resp.haslayer(TCP):
         if resp.getlayer(TCP).flags == 0x12:
            send_rst = sr(IP(dst=self._target)/TCP(sport=src_port, dport=port, flags="AR"), timeout=self._timeout, verbose=False)
            self._log.write("[+] Port %d OPEN" % port)
            self.open_ports.append(port)
         elif resp.getlayer(TCP).flags == 0x14:
            self._log.write("[-] Port %d CLOSED" % port)

class TCPStealthScan(_PortScanner):
   def _scan_port(self, port):
      src_port = RandShort()
      resp = sr1(IP(dst=self._target)/TCP(sport=src_port, dport=port, flags="S"), timeout=self._timeout, verbose=False)
      if isinstance(resp, NoneType):
         self._log.write("[-] Port %d CLOSED" % port)
      elif resp.haslayer(TCP):
         if resp.getlayer(TCP).flags == 0x12:
            rst = sr(IP(dst=self._target)/TCP(sport=src_port, dport=port, flags="R"), timeout=self._timeout, verbose=False)
            self._log.write("[+] Port %d OPEN" % port)
            self.open_ports.append(port)
         elif resp.getlayer(TCP).flags == 0x14:
            self._log.write("[-] Port %d CLOSED" % port)
      elif resp.haslayer(ICMP):
         if int(resp.getlayer(ICMP).type) == 3 and \
            int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            self._log.write("[-] Port %d FILTERED" % port)
