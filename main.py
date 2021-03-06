#! /usr/bin/python3

"""
PCTF project Team 4
Team member:
Description:
    Network Defense tool
    Set up firewall policy, packet sniffing -> packet pre-processor -> detection engine
    -> generates alert/log message -> process alert/log msg
"""

from scapy.all import *
import argparse
from PacketPayloadAnalyzer import *
from PacketPayloadEngine import *
from NetworkTool import *
from IptableSetup import *

def main():
    parser = argparse.ArgumentParser(description="NetworkDefenseTool")
    parser.add_argument(
        '--interface', help="listening network interface", dest='interface', required=True)
    parser.add_argument(
        '--pcapfile', help="output pcap file path", dest='pcapfile', required=True)

    args = parser.parse_args()
    interface = str(args.interface)
    pcapfile = str(args.pcapfile)

    print("Configuring initial iptables rules...")
    IptableSetup().firewall_setup()
    print("Starting up Network Defense Tool...")
    NetworkTool(interface, pcapfile).run()
    # networkTestSuite = NetworkTool_TestSuite()
    # engineTestSuite = PacketPayloadEngine_TestSuite()
    # testSuite = PacketPayloadAnalyzer_TestSuite()

if __name__ == '__main__':
    main()
