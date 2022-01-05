#!/usr/bin/env python3
from scapy.all import *
"""
basicly we create a icmp-ip packet with the ip we choosed as dst
"""
a = IP()
a.dst = "10.9.0.6"
b = ICMP()
p = a/b
send(p)
