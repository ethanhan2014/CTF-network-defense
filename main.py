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

class NetworkTool:

    def __init__(self):
        self.allow_tcp_ports = [22,80,443]

    def pkt_callback(self, pkt):
        pass

    @staticmethod
    def add_rule(chain, protocol, flags, action):
        rule = iptc.Rule()
        rule.protocol = protocol
        match = iptc.Match(rule, protocol)
        match.tcp_flags = flags
        rule.target = iptc.Target(rule, action)
        chain.insert_rule(rule)

    '''
        Method: set up whitelist firewall policy
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT DROP
        open ssh and port 80 443
    '''
    def firewall_setup(self):
        filter_table = iptc.Table(iptc.Table.FILTER)
        filter_table.autocommit = False
        
        for chain in filter_table.chains:
            chain.flush()
            chain.set_policy(iptc.Policy("DROP"))
            if chain.name == 'INPUT':
                for tcp_port in self.allow_tcp_ports:
                    rule = iptc.Rule()
                    rule.protocol = 'tcp'
                    match = iptc.Match(rule, "tcp")
                    match.dport = str(tcp_port)
                    rule.add_match(match)
                    rule.target = iptc.Target(rule, "ACCEPT")
                    chain.insert_rule(rule)

                #drop unknown pkt
                rule = iptc.Rule()
                rule.protocol = 'tcp'
                match = iptc.Match(rule, 'tcp')
                match.tcp_flags = ['FIN,SYN,RST,ACK','!SYN']
                match = iptc.Match(rule, "state")  # TODO: this is overwriting what is happening in line 59. Did you mean to add 2 rules here instead of just one?
                match.state = "NEW"
                rule.add_match(match)
                rule.target = iptc.Target(rule, "DROP")
                chain.insert_rule(rule)
                '''
                #Filter abnormal packets
                iptables -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
                iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP 
                iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
                iptables -A INPUT -p tcp --tcp-flags ALL SYN,FIN,RST -j DROP
                iptables -A INPUT -p tcp --tcp-flags ALL SYN,FIN,PSH -j DROP
                iptables -A INPUT -p tcp --tcp-flags ALL SYN,FIN,RST,PSH -j DROP
                iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 
                iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
                '''
                self.add_rule(chain, protocol='tcp', flags=['ALL','FIN,URG,PSH'], action="DROP")
                self.add_rule(chain, protocol='tcp', flags=['ALL','NONE'], action="DROP")
                self.add_rule(chain, protocol='tcp', flags=['ALL','SYN,RST,ACK,FIN,URG'], action="DROP")
                self.add_rule(chain, protocol='tcp', flags=['ALL','SYN,FIN,RST'], action="DROP")
                self.add_rule(chain, protocol='tcp', flags=['ALL','SYN,FIN,RST,PSH'], action="DROP")
                self.add_rule(chain, protocol='tcp', flags=['ALL','SYN,FIN,PSH'], action="DROP")
                self.add_rule(chain, protocol='tcp', flags=['SYN,RST','SYN,RST'], action="DROP")
                self.add_rule(chain, protocol='tcp', flags=['SYN,FIN','SYN,FIN'], action="DROP")

            elif chain.name == 'OUTPUT':
                for tcp_port in self.allow_tcp_ports:
                    rule = iptc.Rule()
                    rule.protocol = 'tcp'
                    match = iptc.Match(rule, "tcp")
                    match.sport = str(tcp_port)
                    rule.add_match(match)
                    match = iptc.Match(rule, "state")
                    match.state = "ESTABLISHED"
                    rule.add_match(match)
                    rule.target = iptc.Target(rule, "ACCEPT")
                    chain.insert_rule(rule)
                

            elif chain.name == 'FORWARD':
            #drop unknown pkt
                rule = iptc.Rule()
                rule.protocol = 'tcp'
                match = iptc.Match(rule, 'tcp')
                match.tcp_flags = ['FIN,SYN,RST,ACK','SYN']
                rule.add_match(match)
                match = iptc.Match(rule, "state")
                match.state = "NEW"
                rule.add_match(match)
                rule.target = iptc.Target(rule, "ACCEPT")
                chain.insert_rule(rule)

        filter_table.commit()
        filter_table.autocommit = True

    def run(self):
        self.firewall_setup()
        sniff(iface='eth0', prn=self.pkt_callback, store=0)

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
        syntax: dict # Dictionary of syntax to break up an expression; can also be used to filter through ( Key: str syntax, Value: int weight )
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
        total_suspicious_weight = 0
        black_list_words_found  = list()
        
        # Count syntax:
        i = 0
        payload_len = len(payload)
        while i < payload_len:
            syntax_check = payload[i]
            if syntax_check in self.syntax_dictionary.keys():
                total_suspicious_weight += self.syntax_dictionary[syntax_check]
                black_list_words_found.append(syntax_check)
            i += 1

        # Tokenize string:
        tokens = list([payload])
        for syntax in self.syntax_dictionary.keys():
            tokens = list(map(str.split(sep=syntax), tokens))
        
        # Count black listed words
        for token in tokens:
            if token in self.word_dictionary.keys():
                total_suspicious_weight += self.word_dictionary[token]
                black_list_words_found.append(token)

        return total_suspicious_weight, black_list_words_found
    # end analyze()

    """
    Method: add_word
    
    Description:
        Adds a word to the library if it does not already exist
    """
    def add_word(self, word: str, weight: int) -> bool:
        if word in self.word_dictionary.keys():
            return False
        # Force syntax to be 1 character
        elif len(word) != 1:
            return False
        else:
            weight_to_add = weight
            if weight is None or weight == 0:
                weight_to_add = self.dflt_word_weight
            self.word_dictionary[word] = weight_to_add
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
            weight_to_add = weight
            if weight is None or weight == 0:
                weight_to_add = self.dflt_syntax_weight
            self.syntax_dictionary[syntax_str] = weight_to_add
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
