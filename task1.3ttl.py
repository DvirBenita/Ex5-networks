#!/usr/bin/python

from scapy.all import *

a = IP(dst = '62.219.17.242',ttl = 1)

b = ICMP()

p = a/b

send(p)

