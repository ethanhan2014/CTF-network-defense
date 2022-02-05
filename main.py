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
    # constructor
    def __init__(
                self, 
                dflt_word_weight: int,   # Default weight to associate with a word if not specified when word is added
                dflt_syntax_weight: int, # Default weight to associate with a syntax if not specified when syntax is added
                words: dict, # Dictionary of black listed words to filter through: ( Key: string word, Value: int weight )
                syntax: dict # Dictionary of syntax to break up an expression; can also be used to filter through ( Key: string syntax, Value: int weight )
                ):
        self.word_dictionary    = words.copy()
        self.syntax_dictionary  = syntax.copy()
        self.dflt_word_weight   = dflt_word_weight
        self.dflt_syntax_weight = dflt_syntax_weight
        # end constructor()
    
    """
    Method: analyze

    Description:
        Analyzes a packet payload in a string format
        by tallying up each word and syntax it finds.
        Returns the total weight of suspiciousness and the list of words
        found which can be used for debugging purposes
    """
    def analyze(self, payload: str) -> tuple:
        return 0, list()
    # end analyze()

    """
    Method: add_word
    
    Description:
        Adds a word to the library if it does not already exist
    """
    def add_word(self, word: str, weight: int) -> bool:
        if word in self.word_dictionary.keys():
            return False
        else:
            self.word_dictionary[word] = weight
            return True
    # end add_word()

    """
    Method: remove_word
    
    Description:
        Removes word from library if it exists
    """
    def remove_word(self, word: str) -> bool:
        if word in self.word_dictionary.keys():
            self.word_dictionary.pop(word)
            return True
        else:
            return False
    # end remove_word()

    """
    Method: add_syntax

    Description:
        Adds a syntax string to the dictionary and its weight to filter through if applicable
    """
    def add_syntax(self, syntax_str: str, weight: int) -> bool:
        if syntax_str in self.syntax_dictionary.keys():
            return False
        else:
            self.syntax_dictionary[syntax_str] = weight
    # end add_syntax()

    """
    Method: remove_syntax
    
    Description:
        Remove a syntax string from the dictionary if it exists
    """
    def remove_syntax(self, syntax_str: str) -> bool:
        if syntax_str in self.syntax_dictionary.keys():
            self.syntax_dictionary.pop(syntax_str)
            return True
        else:
            return False
    # end remove_syntax()

# end class PacketPayloadAnalayzer

# Test code #
def run_packet_payload_analyzer_tests() -> bool:
    analyzer = PacketPayloadAnalayzer(dflt_word_weight=2, dflt_syntax_weight=0)
    analyzer.analyze("")
    return True


if __name__ == '__main__':
    main()

