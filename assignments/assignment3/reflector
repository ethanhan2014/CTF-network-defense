#!/usr/bin/env python3
import sys
import getopt
import traceback
from scapy.all import *

global iface, ip_v, mac_v, ip_r, mac_r


def reflectorcallback(pkt):
	global iface, ip_v, mac_v, ip_r, mac_r
	try:
		if ARP in pkt:
			if pkt[ARP].pdst == ip_v:
				# arppkt = Ether(src = mac_v, dst = pkt[Ether].src) / ARP(op = 2, hwsrc = mac_v, psrc = ip_v, hwdst = pkt[ARP].hwsrc, pdst=pkt[ARP].psrc)
				pkt[Ether].dst = pkt[Ether].src
				pkt[Ether].src = mac_v
				pkt[ARP].op = 2
				pkt[ARP].hwdst = pkt[ARP].hwsrc
				pkt[ARP].pdst = pkt[ARP].psrc
				pkt[ARP].hwsrc = mac_v
				pkt[ARP].psrc = ip_v
				sendp(pkt, iface=iface)

			elif pkt[ARP].pdst == ip_r:
				pkt[Ether].dst = pkt[Ether].src
				pkt[Ether].src = mac_r
				pkt[ARP].op = 2
				pkt[ARP].hwdst = pkt[ARP].hwsrc
				pkt[ARP].pdst = pkt[ARP].psrc
				pkt[ARP].hwsrc = mac_r
				pkt[ARP].psrc = ip_r
				sendp(pkt, iface = iface)

		elif IP in pkt:		
			if pkt[IP].dst == ip_v:
				ip_a = pkt[IP].src
				mac_a = pkt[Ether].src
				pkt[Ether].dst = mac_a
				pkt[Ether].src = mac_r
				pkt[IP].dst = ip_a
				pkt[IP].src = ip_r
				del pkt.chksum
				if pkt.haslayer(TCP):
					del pkt[TCP].chksum
				elif pkt.haslayer(UDP):
					del pkt[UDP].chksum
				elif pkt.haslayer(ICMP):
					# pkt[ICMP].type = 0
					del pkt[ICMP].chksum
				pkt = pkt.__class__(bytes(pkt))
				# pkt.show2()
				sendp(pkt, iface = iface)
			
			elif pkt[IP].dst == ip_r:
				ip_a = pkt[IP].src
				mac_a = pkt[Ether].src
				pkt[Ether].dst = mac_a
				pkt[Ether].src = mac_v
				pkt[IP].dst = ip_a
				pkt[IP].src = ip_v
				del pkt.chksum
				if pkt.haslayer(TCP):
					del pkt[TCP].chksum
				elif pkt.haslayer(UDP):
					del pkt[UDP].chksum
				elif pkt.haslayer(ICMP):
					# pkt[ICMP].type = 0
					del pkt[ICMP].chksum
				pkt = pkt.__class__(bytes(pkt))
				# pkt.show2()
				sendp(pkt, iface = iface)

	except Exception as e:
		print(traceback.format_exc())
		print(e)		

try:
	opts, args = getopt.getopt(sys.argv[1:], "",['interface=', 'victim-ip=', 'victim-ethernet=', 'reflector-ip=', 'reflector-ethernet='])
except getopt.GetoptError as e:
	print(e)
for name,value in opts :
	if name in ("--interface"):
		iface = value
	if name in ("--victim-ip"):
		ip_v = value
	if name in ("--victim-ethernet"):
		mac_v = value
	if name in ("--reflector-ip"):
		ip_r = value
	if name in ("--reflector-ethernet"):
		mac_r = value
sniff(iface=iface, prn = reflectorcallback, store=0)