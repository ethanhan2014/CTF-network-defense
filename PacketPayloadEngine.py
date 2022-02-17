from PacketPayloadAnalyzer import *
import csv

class PacketPayloadEngine:
    def __init__(self, weight_to_drop_packet_on, dflt_word_weight, dflt_syntax_weight):
        self.weight_to_drop_packet_on = weight_to_drop_packet_on
        self.dflt_word_weight         = dflt_word_weight
        self.dflt_syntax_weight       = dflt_syntax_weight

        # Setup http method get analyzer
        self.http_get_analyzer = self.setup_analyzer("http_get_blacklisted_words.csv")
    
    """
    Method: Validate Payload

    Description:
        Primary function of class, returns a boolean value of whether the packet
        should be dropped or not.
    """
    def validate_payload(self, unparsed_str: str) -> bool:
        drop_payload = False
        # To Do
        http_request = False
        if http_request:
            drop_payload = self.validate_http_payload(unparsed_str)
        
        return drop_payload
    # end validate_payload()

    """
    Method: validate_http_payload

    Description:
        Validates whether http payload is okay
    """
    def validate_http_payload(self, parsed_str: str) -> bool:
        drop_payload = False
        # To Do
        parser_str_lines = list()
        for line in parser_str_lines:
            header, preprocessed_str = self.preprocess_http_line(line)

            if 'GET' == header:
               weight, words = self.http_get_analyzer(preprocessed_str)
               drop_payload = weight < self.weight_to_drop_packet_on

        return drop_payload
    # end validate_http_payload()

    """
    Method: preprocess_http_line

    Description:
        Preprocess an http line by grapping the header, and resolving special characters
    """
    def preprocess_http_line(self, unparsed_line: str) -> tuple:
        # To Do - need to parse out escape charcter &#20 etc. into normal form
        return "", unparsed_line
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
            header_row = next(csv_file)
            rows = []
            for row in csv_file:
                rows.append(row)
            # Parse each row
            i = 0
            while i < len(rows):
                row_len = len(rows[i])

                if row_len == 1:
                    # Add word with weight 0
                    blacklist_words[rows[i][0]] = 0
                elif row_len > 1:
                    # Add word with set weight
                    blacklist_words[rows[i][0]] = int(rows[i][1])
                    if row_len == 3:
                        # Add syntax with weight 0
                        blacklist_syntax[row[i][2]] = 0
                    elif row_len > 3:
                        # Add syntax with set weight
                        blacklist_syntax[row[i][2]] = int(rows[i][3])
                i += 1
            f.close()
        except:
            print("WARNING! Failed during parse csv file for %s" % (filename) )
            try:
                f.close()
            except:
                print("WARNING! File couldn't be opened %s" % (filename))
        
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
