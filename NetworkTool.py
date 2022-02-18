from scapy.all import *
from PacketPayloadEngine import *

'''
Class: NetworkTool
Description: Packet Sniffing and processing
'''


class NetworkTool:

    def __init__(self, iface, pcapfile):
        self.iface = iface
        self.pcapfile = pcapfile

    def pkt_callback(self, pkt):
        "write pkt into pcap file"
        wrpcap(self.pcapfile, pkt, append=True)
        pass

    def run(self):
        sniff(iface=self.iface, prn=self.pkt_callback, store=0)
