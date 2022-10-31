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
        self.seq_num = Counter(a_2_v=0, a_2_r=0, v=0, r=0)
        self.payloadLen = 0

# handle incoming packet
    def handle_packets(self, pkt):
        # ARP request for victim ip
        if ARP in pkt and pkt[ARP].pdst == self.v_ip and pkt[ARP].op == 1:
            reply = Ether()/ARP()
            reply.dst = pkt[Ether].src
            reply.src    = self.v_mac
            reply.type   = 0x806
            reply.hwtype = 0x1
            reply.ptype = 0x800
            reply.hwlen	= 6
            reply.plen	= 4
            reply.op	= 2	#is-at
            reply.hwsrc	= self.v_mac
            reply.hwdst = pkt[ARP].hwsrc
            reply.psrc	= self.v_ip
            reply.pdst	= pkt.psrc
            sendp(reply, iface=self.iface)
        # ARP request for reflector ip
        elif ARP in pkt and pkt[ARP].pdst == self.r_ip and pkt[ARP].op == 1:
            reply = Ether()/ARP()
            reply.dst = pkt[Ether].src
            reply.src    = self.r_mac
            reply.type   = 0x806
            reply.hwtype = 0x1
            reply.ptype = 0x800
            reply.hwlen	= 6
            reply.plen	= 4
            reply.op	= 2	#is-at
            reply.hwsrc	= self.r_mac
            reply.hwdst = pkt[ARP].hwsrc
            reply.psrc	= self.r_ip
            reply.pdst	= pkt.psrc
            sendp(reply, iface=self.iface)
        # attacker send TCP SYN for victim ip 
        elif TCP in pkt and pkt[IP].dst == self.v_ip and pkt[TCP].flags=='S':
            print("Attack TCP SYN con")
            #save attacker SYN seq
            self.seq_num['a_2_v'] = pkt[TCP].seq 
            #reflector send SYN to attacker
            #reply = Ether()/IP()/TCP()
            # reply[Ether].src = self.r_mac
            # reply[Ether].dst = pkt[Ether].src
            reply = IP()/TCP()   
            reply[IP].src = self.r_ip
            reply[IP].dst = pkt[IP].src
            reply[IP].flags = 'DF'
            reply[TCP].sport = pkt[TCP].dport
            reply[TCP].dport = pkt[TCP].sport
            reply[TCP].flags = 'S'
            #reply[TCP].seq = self.seq_num['r']
            reply[TCP].options = pkt[TCP].options
            del reply[IP].chksum
            del reply[TCP].chksum
            reply = reply.__class__(bytes(reply))
            send(reply, iface=self.iface)
        #attack send SYN-ACK to reflector
        elif TCP in pkt and pkt[IP].dst == self.r_ip and pkt[TCP].flags=='SA':
            print("Attack TCP SYNACK con")
            #save attacker synack seq
            self.seq_num['a_2_r'] = pkt[TCP].seq
            self.seq_num['r'] = pkt[TCP].ack
            #victim send SYN-ACK to attack
            reply = IP()/TCP()
            reply[IP].src = self.v_ip
            reply[IP].dst = pkt[IP].src
            reply[TCP].sport = pkt[TCP].dport
            reply[TCP].dport = pkt[TCP].sport
            reply[TCP].flags = 'SA'
            #reply[TCP].seq = self.seq_num['v']
            self.seq_num['a_2_v'] += 1
            reply[TCP].ack = self.seq_num['a_2_v']
            reply[TCP].options = pkt[TCP].options
            del reply[IP].chksum
            del reply[TCP].chksum
            reply = reply.__class__(bytes(reply))
            send(reply, iface=self.iface)
        #attack send ACK to victim
        elif TCP in pkt and pkt[IP].dst == self.v_ip and pkt[TCP].flags=='A':
            print("Attack ACK con")
            #save attack ack to victim
            self.seq_num['a_2_v'] = pkt[TCP].seq
            self.seq_num['v'] = pkt[TCP].ack
            #reflector send ACK to attack
            reply = IP()/TCP()
            reply[IP].src = self.r_ip
            reply[IP].dst = pkt[IP].src
            reply[TCP].sport = pkt[TCP].dport
            reply[TCP].dport = pkt[TCP].sport
            reply[TCP].flags = 'A'
            reply[TCP].seq = self.seq_num['r']
            self.seq_num['a_2_r'] += 1
            reply[TCP].ack = self.seq_num['a_2_r']
            reply[TCP].options = pkt[TCP].options
            del reply[IP].chksum
            del reply[TCP].chksum
            reply = reply.__class__(bytes(reply))
            send(reply, iface=self.iface)
        #attack send PA to victim
        elif TCP in pkt and pkt[IP].dst == self.v_ip and pkt[TCP].flags=='PA':
            print("Attack PA to v con")
            #save attack to victim seq  and payload
            self.seq_num['a_2_v'] = pkt[TCP].seq
            self.seq_num['v'] = pkt[TCP].ack
            self.payloadLen = len(pkt[Raw].load)
            #reflector send PA to attack
            reply = IP()/TCP()/Raw(load=pkt[Raw].load)
            reply[IP].src = self.r_ip
            reply[IP].dst = pkt[IP].src
            reply[TCP].sport = pkt[TCP].dport
            reply[TCP].dport = pkt[TCP].sport
            reply[TCP].flags = 'PA'
            reply[TCP].seq = self.seq_num['r']
            reply[TCP].ack = self.seq_num['a_2_r']
            del reply[IP].chksum
            del reply[TCP].chksum
            reply = reply.__class__(bytes(reply))
            send(reply, iface=self.iface)
        #attack send A to reflector
        elif TCP in pkt and pkt[IP].dst == self.v_ip and pkt[TCP].flags=='A':
            print("Attack A to reflector con")
            #save attack to reflect seq 
            self.seq_num['a_2_r'] = pkt[TCP].seq
            self.seq_num['r'] = pkt[TCP].ack
            #victim send A to attack
            reply = IP()/TCP()
            reply[IP].src = self.v_ip
            reply[IP].dst = pkt[IP].src
            reply[TCP].sport = pkt[TCP].dport
            reply[TCP].dport = pkt[TCP].sport
            reply[TCP].flags = 'A'
            reply[TCP].seq = self.seq_num['v']
            self.seq_num['a_2_v'] += self.payloadLen
            reply[TCP].ack = self.seq_num['a_2_v']
            del reply[IP].chksum
            del reply[TCP].chksum
            reply = reply.__class__(bytes(reply))
            send(reply, iface=self.iface)
        #attack send UDP to victim
        elif UDP in pkt and pkt[IP].dst == self.v_ip:
            reply = IP()/UDP()/Raw(load=pkt[Raw].load)
            # reply[IP].src = pkt[IP].dst
            reply[IP].src = self.r_ip
            reply[IP].dst = pkt[IP].src
            reply[UDP].sport = pkt[UDP].dport
            reply[UDP].dport = pkt[UDP].sport
            del reply[IP].chksum
            del reply[UDP].chksum
            reply = reply.__class__(bytes(reply))
            send(reply, iface=self.iface)
        elif ICMP in pkt and pkt[IP].dst == self.v_ip and pkt[ICMP].type == 8:
            #reply = IP(src=pkt[IP].dst, dst=pkt[IP].src)/ICMP(type=0, seq=pkt[ICMP].seq, id=pkt[ICMP].id, chksum=pkt[ICMP].chksum, code=0)/Raw(load=pkt[Raw].load)
            reply = IP()/ICMP()/Raw(load=pkt[Raw].load)
            reply[IP].dst = pkt[IP].src
            #reply[IP].src = pkt[IP].dst
            reply[IP].src = self.r_ip
            reply[ICMP].type = 0
            reply[ICMP].code = 0
            reply[ICMP].seq = pkt[ICMP].seq
            reply[ICMP].id = pkt[ICMP].id 
            del reply[IP].chksum
            del reply[ICMP].chksum
            reply = reply.__class__(bytes(reply))
            send(reply, iface=self.iface)
    
    def run(self):
        sniff(iface=self.iface, prn=self.handle_packets, store=0)

def main():
    parser = argparse.ArgumentParser(description="reflector")
    parser.add_argument('--interface', help="listening network interface", dest='interface', required=True)
    parser.add_argument('--victim-ip', type=ipaddress.ip_address, help="victim ip address", dest='v_ip', required=True)
    parser.add_argument('--victim-ethernet', help="victim MAC address", dest='v_mac', required=True)
    parser.add_argument('--reflector-ip', type=ipaddress.ip_address, help="reflector ip address", dest='r_ip', required=True)
    parser.add_argument('--reflector-ethernet', help="reflector MAC address", dest='r_mac', required=True)
    args = parser.parse_args()
    print(f"interface is {args.interface}, victim ip is {args.v_ip}, victim mac is {args.v_mac}, reflector ip is {args.r_ip}, reflector mac is {args.r_mac}")
    # enabling ip forwarding
    #os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    # sniff incoming packets
    reflector = Reflector(str(args.interface), str(args.v_ip), str(args.v_mac), str(args.r_ip), str(args.r_mac))
    reflector.run()

if __name__ == "__main__":
    logging.getLogger("scapy").setLevel(logging.INFO)
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting...")
        #disabling ip forwarding
        #os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
        sys.exit(0)