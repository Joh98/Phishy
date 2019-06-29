import csv
import re
from difflib import get_close_matches
import dns.resolver
from urllib.parse import urlparse
from termcolor import colored
from tldextract import tldextract


# python class for whitelist and blacklist testing (uses urls submitted by the app)
class WhiteBlackApp:

    # Constructor
    def __init__(self, url, domain):

        self.url = url  # get url

        # initialise white/blacklists and other variables
        self.whitelist_url = []
        self.whitelist_ip = []
        self.blacklist_url = []
        self.blacklist_ip = []

        self.IP = []
        self.top_domains = []
        self.domain = domain
        self.populate_lists()  # call function to populate the white and blacklists via csv files
        # Find corresponding IPs from the url via dns resolves
        resolver = dns.resolver.Resolver()
        query = resolver.query(urlparse(self.url).netloc, "A")


        for IP in query:  # for each response
            self.IP.append(IP)  # add to list

    # function which reads through the blacklists and determines if the IP or url is contained within
    def blacklist_test(self):

        verdict = False  # set initial verdict as False

        for blacklist_url_item in self.blacklist_url:  # for each list item in blacklist of urls
            # if item at position 0 equals the url set verdict to True and return ("phishy")
            if blacklist_url_item[0] == self.url:
                verdict = True
                print("[*]  URL in blacklist: " + colored(blacklist_url_item[0], 'red') + "  [*]")  # UI
                return verdict

        for IP in self.IP:  # for each item in list of IPs resolved via DNS

            for blacklist_ip_item in self.blacklist_ip:  # for each list item in blacklist of IPs

                # if item at position 0 is equal to current position of IP set verdict to True and return ("phishy")
                if blacklist_ip_item[0] == str(IP):
                    verdict = True
                    print("[*] IP in blacklist: " + colored(blacklist_ip_item[0], 'red') + "  [*]")  # UI
                    return verdict

        return verdict  # return verdict as False (Unknown if "phishy" or not)

    # function which reads each line of a csv and saves it to a whitelist or blacklist via a list of lists
    def populate_lists(self):

        with open('whitelistURL.csv', 'r') as file:  # whitelist of urls
            read = csv.reader(file)
            self.whitelist_url = list(read)

        file.close()

        with open('whitelistIP.csv', 'r') as file:  # whitelist of IPs
            read = csv.reader(file)
            self.whitelist_ip = list(read)

        file.close()

        with open('blacklistURL.csv', 'r') as file:  # blacklist of urls
            read = csv.reader(file)
            self.blacklist_url = list(read)

        file.close()

        with open('blacklistIP.csv', 'r') as file:  # blacklist of IPs
            read = csv.reader(file)
            self.blacklist_ip = list(read)

        file.close()

        with open('domains.csv', 'r') as file:  # whitelist of top domains
            read = csv.reader(file)
            top_domains_csv = list(read)

        file.close()

        for listwithin in top_domains_csv:  # populate domain whitelist
            for item in listwithin:
                self.top_domains.append(item)

    # main function
    def run(self):

        verdict_bool = self.blacklist_test()  # call function which carries out the blacklist tests

        if verdict_bool:  # if the returned value is true i.e. the url or IP is in the blacklist

            # save and return verdict
            verdict_array = [True, "N/A"]
            return verdict_array

        verdict_bool = self.whitelist_test()  # call function which carries out the whitelist tests

        # save and return verdict
        if verdict_bool:
            verdict_array = [False, True]
            return verdict_array

        # call function to determine whether a variation of any of the top domains are contained within the subdomain(s) of the url.
        # If it is return "phishy" verdict
        verdict_bool = self.similar_domains()

        if verdict_bool:
            verdict_array = [True, "N/A"]
            return verdict_array

        return [False, False]  # return "False" verdict i.e. the url wasn't in the black or whitelists and passed the other tests

    # function which determines if a "misspelling" of a known top domain is in either the url's domain or subdomains
    def similar_domains(self):

        subdomain = tldextract.extract(self.url).subdomain  # extract subdomain

        verdict = False  # set verdict to false

        # use 'get_close_matches' to extract all domains in the top domains list that are similar to the url's domain
        matches = get_close_matches(self.domain, self.top_domains)

        for item in matches:  # loop through the list of similar domains 'get_close_matches' generated

            if item != self.domain:  # if the domain doesn't match the similar domain, return "phishy" verdict

                print("[*]  Variation of, or top domain in the URL's domain: " + colored(item, 'red') + "  [*]")  # UI
                verdict = True
                return verdict

        # split each subdomain into a list  by splitting at ".". In addition split at use of "_" and "-"
        split_list = re.split('_|-|\.', subdomain)

        # for each extracted/split subdomain use 'get_close_matches' to determine if any subdomains are similar to any of the top domains
        for item in split_list:

            matches = get_close_matches(item, self.top_domains)

            # if there are any close matches (i.e. length of the resulting list > 0) return "phishy" verdict
            if len(matches) > 0:
                print("[*]  Variation of, or top domain in the URL's subdomain(s): " + colored(str(matches),
                                                                                               'red') + "  [*]")  # UI
                verdict = True
                return verdict

        return verdict  # return verdict as False (unknown if "phishy" or not)

    # function which reads through the whitelists and determines if the IP or url is contained within
    def whitelist_test(self):

        verdict = False  # set initial verdict as False

        for whitelist_url_item in self.whitelist_url:  # for each list item in whitelist of urls

            # if item at position 0 equals the url set verdict to True and return ("not phishy")
            if whitelist_url_item[0] == self.url:
                verdict = True
                print("[*]  URL in whitelist: " + colored(whitelist_url_item[0], 'red') + "  [*]")  # UI
                return verdict

        for IP in self.IP:  # for each item in list of IPs resolved via DNS

            for whitelist_ip_item in self.whitelist_ip:  # for each list item in whitelist of IPs

                # if item at position 0 is contained within current position of IP set verdict to True and return ("not phishy")
                if whitelist_ip_item[0] == str(IP):
                    verdict = True
                    print("[*] IP in whitelist: " + colored(whitelist_ip_item[0], 'red') + "  [*]")  # UI
                    return verdict

            # check if the url's domain is that of a top domain. If that is the case set verdict to True and return ("not phishy")
            for domain_item in self.top_domains:
                if self.domain == domain_item:
                    verdict = True
                    print("[*]  Domain in whitelist: " + colored(domain_item, 'red') + "  [*]")  # UI
                    return verdict

        return verdict  # return verdict as False (unknown if "phishy" or not)
