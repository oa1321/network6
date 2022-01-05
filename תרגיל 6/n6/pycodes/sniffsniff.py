#!/usr/bin/env python3
from scapy.all import *


def print_pkt(pkt):
	pkt.show()
"""
hear we choose the filter from the BPF syntex 
"""
pkt = sniff(iface="br-a1d845e270ca", filter="icmp", prn=print_pkt)
"""
pkt = sniff(iface="br-a1d845e270ca", filter="icmp", prn=print_pkt)
this is the first task in 1.1B
"""
"""
pkt = sniff(iface="br-a1d845e270ca", filter="icmp and src host 10.9.0.1 and dst port 23", prn=print_pkt)
this is the second task in 1.1.B
"""
"""
pkt = sniff(iface="br-a1d845e270ca", filter="dst net '192.168.0.0/16' or src net '192.168.0.0/16'", prn=print_pkt)
this is the third task in 1.1.B
"""
