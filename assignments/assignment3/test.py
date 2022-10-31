#!/usr/bin/env python3
from scapy.all import *
import sys
import logging
import os



def prn_callback(pkt):
    print(pkt.show())
    wrpcap('temp.cap', pkt, append=True)
    # if ICMP in pkt:
    #     print(pkt.show())
    if ARP in pkt and pkt[ARP].pdst=='192.168.14.10':
        reply = Ether()/ARP()
        reply.dst = pkt[Ether].src
        reply.src    = '31:16:A9:63:FF:83'
        # reply.type   = 0x806
        # reply.hwtype = 0x1
        # reply.ptype = 0x800
        reply.hwlen	= 6
        reply.plen	= 4
        reply.op	= 2	#is-at
        reply.hwsrc	= '31:16:A9:63:FF:83'
        reply.hwdst = pkt[ARP].hwsrc
        reply.psrc	= '192.168.14.10'
        reply.pdst	= pkt.psrc
        sendp(reply, iface='eth0')
    elif TCP in pkt and pkt[IP].dst == '192.168.14.10' and pkt[TCP].flags == 'S':
        reply = IP()/TCP()
        reply[IP].src = pkt[IP].dst
        reply[IP].dst = pkt[IP].src
        reply[TCP].sport = pkt[TCP].dport
        reply[TCP].dport = pkt[TCP].sport
        reply[TCP].flags = 'SA'
        del reply[TCP].options
        del reply[IP].chksum
        del reply[TCP].chksum
        reply.show2()
        send(reply)
    elif TCP in pkt and pkt[IP].src == '192.168.14.10' and pkt[TCP].flags == 'PA':
        reply = IP()/TCP()
        reply[IP].src = pkt[IP].dst
        reply[IP].dst = pkt[IP].src
        reply[TCP].sport = pkt[TCP].dport
        reply[TCP].dport = pkt[TCP].sport
        reply[TCP].flags = 'A'
        del reply[TCP].options
        del reply[IP].chksum
        del reply[TCP].chksum
        reply.show2()
        send(reply)
    elif ICMP in pkt and pkt[IP].dst == '192.168.14.10' and pkt[ICMP].type == 8:
        packet = IP(src=pkt[IP].dst, dst=pkt[IP].src)/ICMP(type=0, seq=pkt[ICMP].seq, id=pkt[ICMP].id, chksum=pkt[ICMP].chksum, code=0)/Raw(load=pkt[Raw].load)
        send(packet, iface='eth0')

def main():
    #os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    sniff(iface='eth0', prn=prn_callback, store=0, filter='icmp')
    #os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')

if __name__ == "__main__":
    logging.getLogger("scapy").setLevel(logging.CRITICAL)
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting...")
        #os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
        sys.exit(0)