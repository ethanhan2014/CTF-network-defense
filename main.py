#! /usr/bin/python3

'''
PCTF project Team 4
Team member: 
Description:
    Network Defense tool
    Set up firewall policy, packet sniffing -> packet pre-processor -> detection engine 
    -> generates alert/log message -> process alert/log msg
'''

from scapy.all import *
import iptc
from PacketPayloadAnalyzer import *
from PacketPayloadEngine import *

def main():
    print("Firewall starting up...")
    NetworkTool().run()
    #testSuite = PacketPayloadAnalyzer_TestSuite()

if __name__ == '__main__':
    main()

