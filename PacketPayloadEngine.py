from doctest import run_docstring_examples
from scapy.all import Raw, IP, Ether, TCP
from PacketPayloadAnalyzer import *
import csv
from message_bot import *

class PacketPayloadEngine:
    def __init__(self, weight_to_drop_packet_on, dflt_word_weight, dflt_syntax_weight):
        self.weight_to_drop_packet_on = weight_to_drop_packet_on
        self.dflt_word_weight         = dflt_word_weight
        self.dflt_syntax_weight       = dflt_syntax_weight

        # Setup http method get analyzer
        self.http_get_analyzer = self.setup_analyzer("http_method_get_blacklist_rules.csv")

        # Setup sql analyzer
        self.sql_analyzer      = self.setup_analyzer("sql_blacklist_rules.csv")
    
    """
    Method: Validate Packet

    Description:
        Primary entry point to validate a packet, whether it should be dropped or not
    """
    def validate_packet(self, packet) -> tuple:
        drop_payload = False
        message = ""
        if Raw in packet:
            drop_payload, message = self.validate_payload(str(packet[Raw]))
        return drop_payload, message

    """
    Method: Validate Payload

    Description:
        Primary function of class, returns a boolean value of whether the packet
        should be dropped or not.
    """
    def validate_payload(self, unparsed_str: str) -> tuple:
        drop_payload = False
        message = ""
        # Check for http message
        if "HTTP/" in unparsed_str:
            drop_payload, message = self.validate_http_payload(unparsed_str)
        
        return drop_payload, message
    # end validate_payload()

    """
    Method: validate_http_payload

    Description:
        Validates whether http payload is okay
    """
    def validate_http_payload(self, parsed_str: str) -> tuple:
        drop_payload = False
        message = ""

        parser_str_lines = parsed_str.split("\n")
        for line in parser_str_lines:
            header, preprocessed_str = self.preprocess_http_line(line, "%")
            if 'GET' == header:
                weight, words = self.http_get_analyzer.analyze(preprocessed_str)
                drop_payload = weight < self.weight_to_drop_packet_on
                if drop_payload:
                    str_words = str(words)
                    message = "SUSPICOUS PACKET! HTTP GET: Weight = {weight}: Sucpicious packet content: {str_words}"
            elif 'POST' == header:
                post_weight, post_words = self.http_get_analyzer.analyze(preprocessed_str)
                sql_weight, sql_words   = self.sql_analyzer.analyze(preprocessed_str)
                drop_payload = ( post_weight + sql_weight ) < self.weight_to_drop_packet_on
                str_words = str(post_words) + str(sql_words)
                message = "SUSPICOUS PACKET! HTTP POST: Post Weight, SQL Weight = {post_weight},{sql_weight}: content: {str_words}"

        return drop_payload, message
    # end validate_http_payload()

    """
    Method: preprocess_http_line

    Description:
        Preprocess an http line by grapping the header, and resolving special characters
    """
    def preprocess_http_line(self, unparsed_line: str, escape_char) -> tuple:
        processed_line = unparsed_line
        method = ""
        words = unparsed_line.split(" ")
        if words[0] == 'GET' or words[0] == 'POST':
            method = words[0]
            if len(words) > 1:
                # Parse Special Characters
                i = 0
                processed_line = ""
                line_len = len(words[1])
                while i < line_len:
                    next_c = unparsed_line[i]
                    if unparsed_line[i] == escape_char and i + 2 < line_len:
                        c_1 = unparsed_line[i + 1]
                        c_2 = unparsed_line[i + 2]
                        if c_1 == '2':
                            if c_2 == '0':
                                next_c = ' '
                            elif c_2 == '3':
                                next_c = '#'
                            elif c_2 == '4':
                                next_c = '$'
                            elif c_2 == '5':
                                next_c = '%'
                            elif c_2 == '6':
                                next_c = '&'
                            elif c_2.capitalize() == 'B':
                                next_c = '+'
                            elif c_2.capitalize() == 'F':
                                next_c = '/'
                            else:
                                i -= 2
                        elif c_1 == '3':
                            if c_2.capitalize() == 'A':
                                next_c = ':'
                            elif c_2.capitalize() == 'B':
                                next_c = ';'
                            elif c_2.capitalize() == 'C':
                                next_c = '<'
                            elif c_2.capitalize() == 'D':
                                next_c = '='
                            elif c_2.capitalize() == 'E':
                                next_c = '>'
                            elif c_2.capitalize() == 'F':
                                next_c = '?'
                            else:
                                i -= 2
                        elif c_1 == '4':
                            if c_2 == '0':
                                next_c = '@'
                            else:
                                i -= 2
                        elif c_1 == '5':
                            if c_2.capitalize() == 'B':
                                next_c = '['
                            elif c_2.capitalize() == 'C':
                                next_c = '\\'
                            elif c_2.capitalize() == 'D':
                                next_c = ']'
                            elif c_2.capitalize() == 'E':
                                next_c = '^'
                            else:
                                i -= 2
                        elif c_1 == '6':
                            if c_2 == '0':
                                next_c = '`'
                            else:
                                i -= 2
                        elif c_1 == '7':
                            if c_2.capitalize() == 'B':
                                next_c = '{'
                            elif c_2.capitalize() == 'C':
                                next_c = '|'
                            elif c_2.capitalize() == 'D':
                                next_c = '}'
                            elif c_2.capitalize() == 'E':
                                next_c = '~'
                            else:
                                i -= 2
                        else:
                            i -= 2
                        i += 3
                    else:
                        i += 1
                    processed_line.join(next_c)
        return method, processed_line
    # end preprocess_http_line()

    """
    Method: read_csv_blacklist_dictionary

    Description:
        Reads from a csv file that has the form:
            Column A: Black listed words
            Column B: Black listed words weight
            Column C: Black listed syntax
            Columb D: Black listed syntax weight
    """
    def read_csv_blacklist_dictionary(self, filename: str) -> tuple:
        blacklist_words = dict()
        blacklist_syntax = dict()
        try:
            f = open(filename)
            file_reader = csv.reader(f)
            header_row  = next(file_reader)
            rows = []
            for row in file_reader:
                rows.append(row)
            
            # Parse each row
            word_column = 0
            syntax_column = 2
            i = 0
            while i < len(rows):
                if len(rows[i]) > 4:
                    # Parse Words
                    if rows[i][word_column] != '':
                        if rows[i][word_column + 1] != '':
                            blacklist_words[rows[i][word_column]] = int(rows[i][word_column + 1])
                            
                        else:
                            blacklist_words[rows[i][word_column]] = 0

                    # Parse Syntax
                    if rows[i][syntax_column] != '':
                        if rows[i][syntax_column + 1] != '':
                            blacklist_syntax[rows[i][syntax_column]] = int(rows[i][syntax_column + 1])
                        else:
                            blacklist_syntax[rows[i][syntax_column]] = 0                    
                i += 1
            f.close()
        except:
            print("WARNING! Failed during parse csv file for %s" % (filename) )
            try:
                f.close()
            except:
                print("WARNING! File couldn't be opened %s" % (filename) )
        
        return blacklist_words, blacklist_syntax
    # end read_csv_blacklist_dictionary()

    """
    Method: setup_analyzer

    Description:
        Sets up an analyzer with rules specified in the csv file
    """
    def setup_analyzer(self, filename: str) -> PacketPayloadAnalyzer:
        words, syntax = self.read_csv_blacklist_dictionary(filename)
        analyzer = PacketPayloadAnalyzer(dflt_word_weight=self.dflt_word_weight, dflt_syntax_weight=self.dflt_syntax_weight)
        analyzer.load_syntax_dictionary(syntax)
        analyzer.load_word_dictionary(words)
        return analyzer
    # end setup_analyzer

class PacketPayloadEngine_TestSuite:
    def __init__(self):
        success = True
        #success = self.run_simple_message_test() and success
        success = self.run_test_http_message_one_line() and success
        if success:
            print("Packet Payload Engine: All Tests Passed.")
        else:
            print("Packet Payload Engine: Tests Failed")

    def run_simple_message_test(self) -> bool:
        success = False
        try:
            message = "This is a test 2!"
            bot = Bot()
            pkt = Ether() / IP(src="10.0.0.2")
            slack_message = message
            if IP in pkt:
                slack_message = str(pkt[IP].src) + ": " + message
            bot.alert_channel(message=slack_message)
        except:
            success = False
        return success

    def run_test_http_message_one_line(self) -> bool:
        success = True
        test_str = "GET /var/server/password.txt?user=admin HTTP/1.1"
        expect_test_str_weight = 10*4 + 10 + 50 + 10
        engine = PacketPayloadEngine(weight_to_drop_packet_on=100, dflt_word_weight=10, dflt_syntax_weight=0)
        weight, message = engine.validate_http_payload(test_str)
        if expect_test_str_weight != weight:
            success = False
            print("Expected weight: %d, but recieved %d" % (expect_test_str_weight, weight))
        
        if success:
            print("PASS: Test http message one line")
        else:
            print("FAIL: Test http message one line")
        
        return success
    
