#!/usr/bin/python3

from scapy.all import *

print("sniffing packets")

def print_pkt(pkt) :
	pkt.show()

pkt = sniff(filter='icmp and src host 10.0.2.15',prn=print_pkt) 
