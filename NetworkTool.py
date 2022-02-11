import iptc
from scapy.all import *

class NetworkTool:

    def __init__(self):
        self.allow_tcp_ports = [22,80,443]

    def pkt_callback(self, pkt):
        pass

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
                match = iptc.Match(rule, "state")
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
                rule = iptc.Rule()
                rule.protocol = 'tcp'
                match = iptc.Match(rule, 'tcp')
                match.tcp_flags = ['ALL','FIN,URG,PSH']
                rule.target = iptc.Target(rule, "DROP")
                chain.insert_rule(rule)

                rule = iptc.Rule()
                rule.protocol = 'tcp'
                match = iptc.Match(rule, 'tcp')
                match.tcp_flags = ['ALL','NONE']
                rule.target = iptc.Target(rule, "DROP")
                chain.insert_rule(rule)

                rule = iptc.Rule()
                rule.protocol = 'tcp'
                match = iptc.Match(rule, 'tcp')
                match.tcp_flags = ['ALL','SYN,RST,ACK,FIN,URG']
                rule.target = iptc.Target(rule, "DROP")
                chain.insert_rule(rule)

                rule = iptc.Rule()
                rule.protocol = 'tcp'
                match = iptc.Match(rule, 'tcp')
                match.tcp_flags = ['ALL','SYN,FIN,RST']
                rule.target = iptc.Target(rule, "DROP")
                chain.insert_rule(rule)

                rule = iptc.Rule()
                rule.protocol = 'tcp'
                match = iptc.Match(rule, 'tcp')
                match.tcp_flags = ['ALL','SYN,FIN,RST,PSH']
                rule.target = iptc.Target(rule, "DROP")
                chain.insert_rule(rule)

                rule = iptc.Rule()
                rule.protocol = 'tcp'
                match = iptc.Match(rule, 'tcp')
                match.tcp_flags = ['ALL','SYN,FIN,PSH']
                rule.target = iptc.Target(rule, "DROP")
                chain.insert_rule(rule)

                rule = iptc.Rule()
                rule.protocol = 'tcp'
                match = iptc.Match(rule, 'tcp')
                match.tcp_flags = ['SYN,RST','SYN,RST']
                rule.target = iptc.Target(rule, "DROP")
                chain.insert_rule(rule)

                rule = iptc.Rule()
                rule.protocol = 'tcp'
                match = iptc.Match(rule, 'tcp')
                match.tcp_flags = ['SYN,FIN','SYN,FIN']
                rule.target = iptc.Target(rule, "DROP")
                chain.insert_rule(rule)


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