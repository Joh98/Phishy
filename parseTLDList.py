# Quick script which takes a txt file of tlds and cctlds from
# http://data.iana.org/TLD/tlds-alpha-by-domain.txt and parses them to a list


class ParseTLD:

    def __init__(self):

        tld_text_file = open('tlds-alpha-by-domain.txt', 'r')
        self.read_result = [line.split(',') for line in tld_text_file.readlines()]

    def parse(self):

        tldlist = []

        for item in self.read_result:
            item = str(item)
            item = item.replace("\\n", "")
            item = item.replace("]", "")
            item = item.replace("[", "")
            item = item.replace("'", "")
            item = item.lower()

            tldlist.append(item)

        return tldlist

