from scapy.all import *
from PacketPayloadEngine import PacketPayloadEngine
from message_bot import Bot
from datetime import datetime

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
            cur_time = datetime.now()
            time_str = "DATE: {}/{} -- TIME: {}:{}:{}".format(cur_time.month, cur_time.day, cur_time.hour, cur_time.minute, cur_time.second)
            slack_message = "{} -- IP={}:{}".format(time_str, str(pkt[IP].src), message)
        self.slack_bot.alert_channel(message=slack_message)

    def run(self):
        sniff(iface=self.iface, prn=self.pkt_callback, store=0)

"""

### Test Code ###

"""

class NetworkTool_TestSuite:
    def __init__(self):
        success = True
        success = self.run_simple_callback_test() and success
        if success:
            print("Network Tool Test Suite Result: All Tests Passed")
        else:
            print("Network Tool Test Suite Result: Tests Failed")

    def run_simple_callback_test(self) -> bool:
        success = False
        test_str = "GET /var/server/secret/password.txt?user=admin HTTP/1.1"
        packet = Ether() / IP() / TCP() / Raw(test_str)
        try:
            detector = NetworkTool(iface="eth0", pcapfile="test.txt")
            detector.pkt_callback(packet)
            success = True
        except:
            success = False
            print("Failed to send slack message")

        if success:
            print("PASS: run simple callback test")
        else:
            print("FAIL: run simple callback test")

        return success