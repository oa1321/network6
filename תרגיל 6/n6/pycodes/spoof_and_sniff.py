#!/usr/bin/env python3
from scapy.all import *
import sys


def print_pkt(pkt):
    """
    show the packet
    """
    pkt.show()
    if IP in pkt and pkt[ICMP].type == 8:
        a = IP()
        """
        swipe between the dst and src and change the type to 0 ( respond )
        """
        a.dst = pkt[IP].src
        a.src = pkt[IP].dst
        b = ICMP()
        b.type = 0
        b.code = 0
        b.seq = pkt[ICMP].seq
        b.id = pkt[ICMP].id
        p = a / b
        p.show()
        send(p)
        print("sent!")

"""
the interface we can choose from 
"""
inter = ['br-a1d845e270ca', 'lo', 'enp0s3']
paket1 = sniff(iface=inter[0], filter="icmp", prn=print_pkt)

