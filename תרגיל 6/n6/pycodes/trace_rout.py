#!/usr/bin/env python3
from scapy.all import *
import sys

"""
gets the ttl from the user and send ping to google with the ttl we choosed
"""
a = IP()
a.dst = "8.8.8.8"
a.ttl = int(sys.argv[1])
b = ICMP()
send(a/b)
