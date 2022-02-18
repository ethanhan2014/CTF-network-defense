from scapy.all import *
from PacketPayloadEngine import PacketPayloadEngine
from message_bot import Bot

'''
Class: NetworkTool
Description: Packet Sniffing and processing
'''


class NetworkTool:

    def __init__(self, iface, pcapfile):
        self.iface = iface
        self.pcapfile = pcapfile
        self.slack_bot = Bot()
        self.packet_engine = PacketPayloadEngine(weight_to_drop_packet_on=100, dflt_word_weight=10, dflt_syntax_weight=0)

    def pkt_callback(self, pkt):
        "write pkt into pcap file"
        wrpcap(self.pcapfile, pkt, append=True)
        send_message, message = self.packet_engine.validate_packet(pkt)
        if send_message:
            self.send_slack_message(pkt, message)

    def send_slack_message(self, pkt, message):
        slack_message = message
        if IP in pkt:
            slack_message = str(pkt[IP].src) + ": " + message
        self.slack_bot.alert_channel(message=slack_message)

    def run(self):
        sniff(iface=self.iface, prn=self.pkt_callback, store=0)
