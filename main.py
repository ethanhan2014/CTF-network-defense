#! /usr/bin/python3

## PCTF project Team 4
## Team member: 
## Description
#  Network Defense tool
##
from scapy.all import *


class NetworkTool:

    def __init__(self):
        pass

    def pkt_callback(self, pkt):
        pass

    def firewall_setup():
        pass

    def run(self):
        pass

def main():
    print("Firewall starting up...")
    NetworkTool().run()

"""
Class: PacketPayloadAnalayzer

Descripton: 
    Encapsulates a list of suspicious words and a corresponding weight of suspiciousness.
    Will assist in payload verification by tallying up each suspicious word found and its weight and return the result.
    This will allow for more flexibility in how packets are dropped when there is overlap between
    legitimate use-case for a service which must stay open and more suspicous requests.

    Example:
        Packet contains a request to configure some settings in the format: "myname.setting newsetting"
        if we drop packets simply by the existance of a period, we would drop this legitimate request.
        On the other hand lets say '.' has a weight of 10 suspiciousness, and we drop packets when we hit 30,
        then we would still handle the legitimate request, but drop a more suspicious packet like "../../etc/password"
        since on the period alone we would hit 40 points of suspiciousness.
""" 
class PacketPayloadAnalayzer:
    # Method: constructor
    # Description:
    #   Takes a dictionary of words and their corresponding weight of suspiciousness
    #   Or creates an empty dictionary if null
    def __init__(self, words: dict, syntax: dict):
        self.words  = words
        self.syntax = syntax
    
    # Method: add_word
    # Description:
    #   Adds a word to the library if it does not already exist
    def add_word(self, word: str, weight: int) -> bool:
        if word in self.words.keys():
            return False
        else:
            self.words[word] = weight
            return True

    # Method: remove_word
    # Description:
    #   Removes word from library if it exists
    def remove_word(self, word: str) -> bool:
        if word in self.words:
            self.words.pop(word)
            return True
        else:
            return False

    # Method: analyze
    # Description:
    #   Analyzes a packet payload in a string format
    #   by tallying up each word and syntax it finds.
    #   Returns the total weight of suspiciousness and the list of words
    #   found which can be used for debugging purposes
    def analyze(self, payload: str) -> tuple:
        return 0, list()

def run_packet_payload_analyzer_tests() -> bool:
    analyzer = PacketPayloadAnalayzer()
    analyzer.analyze("")
    return True

# end class PacketPayloadAnalayzer


if __name__ == '__main__':
    main()

