from scapy.all import *
from PacketPayloadEngine import *

'''
Class: NetworkTool
Description: Packet Sniffing and processing
'''

class NetworkTool:

    def __init__(self, iface):
        self.iface = iface

    def pkt_callback(self, pkt):
        pass

    def run(self):
        sniff(iface=self.iface, prn=self.pkt_callback, store=0)