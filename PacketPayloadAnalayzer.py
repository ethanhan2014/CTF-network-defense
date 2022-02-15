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
from ast import AnnAssign
from mimetypes import suffix_map


class PacketPayloadAnalyzer:
    # constructor
    def __init__(
                self, 
                dflt_word_weight: int,   # Default weight to associate with a word if not specified when word is added
                dflt_syntax_weight: int # Default weight to associate with a syntax if not specified when syntax is added
                ):
        self.word_dictionary    = dict() # Dictionary of black listed words to filter through: ( Key: string word, Value: int weight )
        self.syntax_dictionary  = dict() # Dictionary of syntax to break up an expression; can also be used to filter through ( Key: str syntax, Value: int weight )
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
            if syntax_check in self.syntax_dictionary.keys() and self.syntax_dictionary[syntax_check] > 0:
                total_suspicious_weight += self.syntax_dictionary[syntax_check]
                # only add unique values
                if syntax_check not in black_list_words_found:
                    black_list_words_found.append(syntax_check)
            i += 1

        # Tokenize string:
        tokens = list([payload])
        for syntax in self.syntax_dictionary.keys():
            new_list = list()
            for token in tokens:
                split_list = str(token).split(sep=syntax)
                for split_item in split_list:
                    if split_item != '':
                        new_list.append(str(split_item))
                
            tokens = new_list
        
        # Count black listed words
        for token in tokens:
            if str(token) in self.word_dictionary.keys():
                total_suspicious_weight += self.word_dictionary[str(token)]
                if str(token) not in black_list_words_found:
                    black_list_words_found.append(str(token))

        return total_suspicious_weight, black_list_words_found
    # end analyze()

    """
    Method: load_word_dictionary

    Description:
        Loads a dictionary of words, where there are not duplicates
    """
    def load_word_dictionary(self, words: dict):
        for word in words:
            self.add_word(word, words[word])
    # end load_word_dictionary
    
    """
    Method load_syntax_dictionary

    Description:
        Loads a dictionary of syntax, where there are not duplicates
    """
    def load_syntax_dictionary(self, syntaxes: dict):
        for syntax in syntaxes:
            self.add_syntax(syntax, syntaxes[syntax])
    # end load_syntax_dictionary

    """
    Method: add_word
    
    Description:
        Adds a word to the library if it does not already exist
    """
    def add_word(self, word: str, weight: int) -> bool:
        if word in self.word_dictionary.keys():
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
        # Force syntax to be 1 character
        elif (len(syntax_str) != 1):
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

# end class PacketPayloadAnalyzer

"""
Test Code
"""

class PacketPayloadAnalyzer_TestSuite:
    def __init__(self):
        self.run_all_tests()

    def run_all_tests(self):
        success = True
        success = self.run_add_syntax() and success
        success = self.run_remove_syntax() and success
        success = self.run_add_word() and success
        success = self.run_remove_word() and success
        success = self.run_analyze() and success
        success = self.run_analyze2() and success
        if success:
            print("Packet Payload Analyzer: All Tests Passed")
        else:
            print("Packet Payload Analyzer: Test Suite Failed")


    """
    run_add_syntax
    """
    def run_add_syntax(self) -> bool:
        success = True
        analyzer = PacketPayloadAnalyzer(0, 0)
        if analyzer.add_syntax("-", 50) == False:
            print("Add syntax failed to add -\n")
            success = False

        if analyzer.add_syntax("+", 20) == False:
            print("Add syntax failed to add +\n")
            success = False

        if analyzer.add_syntax("-", 30) == True:
            print("Add syntax incorrectly added duplicate -\n")
            success = False

        if analyzer.add_syntax("gibberish", 30) == True:
            print("Add syntax incorrectly added a long string")
            success = False

        if success:
            print("PASS: Add syntax test result")
        else:
            print("FAIL: Add syntax test result")

        return success

    """
    run_remove_syntax
    """
    def run_remove_syntax(self) -> bool:
        success = True
        analyzer = PacketPayloadAnalyzer(0, 0)
        analyzer.add_syntax(".", 40)
        analyzer.add_syntax("*", 40)
        if analyzer.remove_syntax(".") == False:
            print("Failed to remove syntax .")
            success = False

        if analyzer.remove_syntax(".") == True:
            print("Remove syntax removed . twice")
            success = False

        if analyzer.remove_syntax(")") == True:
            print("Incorrectly removed ) when it doesn't exist")
            success = False

        if success:
            print("PASS: Remove syntax test result")
        else:
            print("FAIL: Remove syntax test restult")

        return success

    """
    run_add_word
    """
    def run_add_word(self) -> bool:
        success = True
        analyzer = PacketPayloadAnalyzer(0, 0)
        if analyzer.add_word("bin", 50) == False:
            print("Add word failed to add bin")
            success = False

        if analyzer.add_word("sh", 20) == False:
            print("Add word failed to add sh")
            success = False

        if analyzer.add_word("bin", 30) == True:
            print("Add word incorrectly added duplicate bin")
            success = False

        if success:
            print("PASS: Add word test result")
        else:
            print("FAIL: Add word test result")

        return success

    """
    run_remove_word
    """
    def run_remove_word(self) -> bool:
        success = True
        analyzer = PacketPayloadAnalyzer(0, 0)
        analyzer.add_word("bin", 40)
        analyzer.add_word("sh", 40)
        if analyzer.remove_word("bin") == False:
            print("Failed to remove word bin")
            success = False

        if analyzer.remove_word("bin") == True:
            print("Remove word removed bin twice")
            success = False

        if analyzer.remove_word("random") == True:
            print("Incorrectly removed random when it doesn't exist")
            success = False

        if success:
            print("PASS: Remove word test result")
        else:
            print("FAIL: Remove word test restult")

        return success

    """
    run_analyze()
    """
    def run_analyze(self) -> bool:
        success = True
        analyzer = PacketPayloadAnalyzer(dflt_word_weight=10, dflt_syntax_weight=0)
        syntax_dict = { ' ':0, '+':0, '-':0, '.':5,'/':10 }
        word_dict = { 'bin':10, 'sh':20 }
        analyzer.load_syntax_dictionary(syntax_dict)
        analyzer.load_word_dictionary(word_dict)

        test_string = "GET ../../bin/sh"
        expect_val = 20 + 30 + 10 + 20
        expect_words = [".","/","bin","sh"]
        weight, words = analyzer.analyze(test_string)
        if weight != expect_val:
            print("Analyze calculated incorrect weight of %d" % (weight))
            success = False

        if len(words) != len(expect_words):
            print("Analyzer returned wrong number of words.")
            print("Words returned:")
            print(words)
        else:
            i = 0
            while i < len(expect_words):
                if words[i] != expect_words[i]:
                    print("Unexpected word %s at %d, expected word %s" % (words[i], i, expect_words[i]) )
                    success = False
                i += 1
        
        if success:
            print("PASS: Analyze Test Results")
        else:
            print("FAIL: Analyze Test Results")
        return success

    """
    run_analyze2()
    """
    def run_analyze2(self) -> bool:
        success = True
        analyzer = PacketPayloadAnalyzer(dflt_word_weight=10, dflt_syntax_weight=0)
        syntax_dict = { ' ':0, '+':0, '-':0, '.':5,'/':10 }
        word_dict = { 'bin':10, 'sh':20 }
        analyzer.load_syntax_dictionary(syntax_dict)
        analyzer.load_word_dictionary(word_dict)

        test_string = "GET normalFileAccess/index.html"
        expect_val = 10 + 5
        expect_words = ["/","."]
        weight, words = analyzer.analyze(test_string)
        if weight != expect_val:
            print("Analyze calculated incorrect weight of %d" % (weight))
            success = False

        if len(words) != len(expect_words):
            print("Analyzer returned wrong number of words.")
            print("Words returned:")
            print(words)
        else:
            i = 0
            while i < len(expect_words):
                if words[i] != expect_words[i]:
                    print("Unexpected word %s at %d, expected word %s" % (words[i], i, expect_words[i]) )
                    success = False
                i += 1
        
        if success:
            print("PASS: Analyze Test 2 Results")
        else:
            print("FAIL: Analyze Test 2 Results")
        return success
        