import csv
import os
import time

import arff
from urllib.parse import urlparse
import tldextract
from parseTLDList import ParseTLD
from search_engine_parser.core.engines import GoogleSearch, YahooSearch
import urllib.request
from bs4 import BeautifulSoup
import requests
from urllib.request import socket


# python class for the creation of an .arff file using features extracted from the submitted URL
class FeatureExtraction:

    # Constructor
    def __init__(self):

        # initialise variables
        self.url = ""
        self.scheme = ""
        self.domain = ""
        self.path = ""
        self.query = ""
        self.arff_List = []
        self.url_list = []
        self.tld_list = ParseTLD().parse()  # call class function within parseTLDlist.py to create list of all tlds

    # function which determines if the links within the url's corresponding page are characteristic of a phishing page
    def href_check(self):

        href_results = []
        count_of_bad_instances = 0

        head = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'}

        # try and use BeautifulSoup to grab the url's corresponding page and get all of the links (hrefs)
        try:

            request = urllib.request.Request(self.url, headers=head)
            page = urllib.request.urlopen(request)
            soupy = BeautifulSoup(page, 'html.parser')

            for a in soupy.find_all('a', href=True):
                href_results.append(a['href'])

            # if there are links
            if len(href_results) > 0:

                # for each link
                for item in href_results:

                    items_domain = tldextract.extract(item).domain  # extract the domain from the link

                    # if the link doesn't go anywhere increase bad instance metric
                    if item == "#":
                        count_of_bad_instances += 1

                    # if the link goes to a different domain increase bad instance metric
                    elif not items_domain == self.domain:
                        count_of_bad_instances += 1

                    # if the link goes to a page on the same domain via ../ or / then decrease bad instance metric
                    elif item.startswith("../"):
                        count_of_bad_instances -= 1

                    elif item.startswith("/"):
                        count_of_bad_instances -= 1

                    # if more than half of the links on the page have been marked as bad
                    if count_of_bad_instances > (0.5 * len(href_results)):
                        self.arff_List.append("BadHREFs")  # append bad to feature list with regards to the links
                        break

                    # else append good to feature list with regards to the links
                    else:
                        self.arff_List.append("GoodHREFs")
                        break

            else:  # else (there are no links) also append bad to feature list with regards to the links
                self.arff_List.append("BadHREFs")

        # if an error occurs append error to the feature list
        except Exception as e:
            self.arff_List.append("ErrorHREFs")

    # function which determines if the url's domain is an IP address via the use of python sockets
    def ip_check(self):

        # if an error is raised i.e. sockets doesn't understand the data, then the domain is not an IP address
        try:

            socket.inet_aton(self.domain)
            self.arff_List.append("IP")  # append IP to the feature list

        except socket.error:  # if an error is thrown append not IP to the feature list

            self.arff_List.append("NotIP")

    # function which extracts features dependent on characteristics regarding numbers and special characters in the url
    def num_and_special_characters(self):

        char_list_count = ['.', '-', "_", "%", "&", "#"]  # initialise list of characters to search for

        count = 0  # set count of numbers in the url to zero

        # for each item in the list of characters, append the number of occurrences of said character to the feature list
        for character in char_list_count:
            self.arff_List.append(self.url.count(character))

        # if tilde is present in the url append yes to the feature list, else append no
        if "~" in self.url:
            self.arff_List.append("Yes~")

        else:
            self.arff_List.append("No~")

        # if the at symbol is present in the url append yes to the feature list, else append no
        if "@" in self.url:
            self.arff_List.append("Yes@")

        else:
            self.arff_List.append("No@")

        # loop through each character in the url and determine if it is a number
        for character in self.url:

            if character.isdigit():
                count += 1

        self.arff_List.append(count)  # append the number of numbers to the feature list

    # function which extracts features based on on the url's path
    def path_checks(self):

        # if the length of the path > 0 i.e. the url has a path
        if len(self.path) > 0:

            #  if there is a double slash in the path append yes to feature list, else append no
            if "//" in self.path:
                self.arff_List.append("YesDoubleSlashInPath")

            else:
                self.arff_List.append("NoDoubleSlashInPath")

        # else (if the url doesn't have a path) append no path to the feature list for the previous test
        else:
            self.arff_List.append("NoPath")

    # function which extracts features from a url within a csv file
    def run(self):

        csv_file = "url.csv"
        identifier = "?"

        # open the .csv file, iterate through and add the url to a list
        with open(csv_file, 'r') as file:
            read = csv.reader(file)
            self.url_list = list(read)

            # for the url
            for url in self.url_list:
                # grab url and call function to determine the url's final destination
                self.url = url[0]
                self.url_parsing()

                # append the depth of path, number of dashes in the domain and number of query parameters to the feature list
                self.arff_List.append(self.path.count("/"))
                self.arff_List.append(self.domain.count("-"))
                self.arff_List.append(self.query.count("="))

                self.scheme_check()  # call function to append the url's scheme to the feature list

                self.ip_check()  # call function to determine if the url is an IP

                self.num_and_special_characters()  # call function to extract features based on special characters and numbers

                self.path_checks()  # call function to extract features based on the url's path

                self.subdomain_checks()  # call function to extract features based on the url's subdomain(s)

                self.search_engine_check()  # call function to determine if the url appears in a Google search

                self.arff_List.append(identifier)  # append ? to the feature list so that WEKA can predict that value later down the line

        self.write_arff()  # call function to write the .arff file

    # function which determines if the url's corresponding website uses https or http and appends the result to the list for features
    def scheme_check(self):

        if str(self.scheme) == "https":

            self.arff_List.append("YesHttps")

        elif str(self.scheme) == "http":

            self.arff_List.append("NoHttps")

        else:
            self.arff_List.append("ErrorHttps")

    # function which determines if the url appears in search results when Googled
    def search_engine_check(self):

        try:
            count = 0

            time.sleep(0.5)
            # search for the url (without its path) in Google and parse into a list
            search_google = GoogleSearch().search(self.domain + "." + tldextract.extract(self.url).suffix)["links"]

            search_results = [search_google]

            parsed_results = [item for inner_list in search_results for item in inner_list]

            # for each Google result returned
            for item in parsed_results:
                count += 1

                # if the result starts with the url then it is in the Google search
                if item.startswith(self.url):

                    # append in Google, and href test not required to the feature list
                    self.arff_List.append("YesInSE")
                    self.arff_List.append("N/AHREFs")
                    break

                # if the end of the results list has been reached then the url isn't in the Google search
                if count == len(parsed_results):

                    # append not in Google to the feature list, and call the function to carry out href tests
                    self.arff_List.append("NotInSE")
                    self.href_check()
                    break

        # if an error occurs append error to the feature list, and call the function to carry out href tests
        except Exception as e:
            print(e)
            self.arff_List.append("ErrorSE")
            self.href_check()

    # function which extracts features dependent on the url's subdomain(s)
    def subdomain_checks(self):

        # extract subdomain from url and split into individual parts
        sd = tldextract.extract(self.url)
        subdomains = sd.subdomain
        subdomain_list = subdomains.split(".")

        # disregard www. or an empty value as a subdomain
        if subdomain_list[0] == "www" or subdomain_list[0] == "":
            subdomain_list.pop(0)

        found = False  # set loop breaker to False

        # add number of subdomains to the feature list
        self.arff_List.append(len(subdomain_list))

        # determine if any of the top tlds are contained within the subdomain(s)
        if len(subdomain_list) > 0:

            #  loop through the list of all tlds (top level domains)
            for tld in self.tld_list:

                # loop through each subdomain and determine if a tld contained within. If that's the case append yes to feature list
                for subdomain in subdomain_list:

                    if tld == subdomain:
                        found = True
                        self.arff_List.append("YesTLDInSubdomain")
                        break

                if found:  # if a tld has been found in the subdomain then break
                    break

            if not found:  # if a tld is not contained in any of the subdomains append no to the feature list
                self.arff_List.append("NoTLDInSubdomain")

        else:  # else (if the url doesn't have a subdomain(s)) append no subdomain to the feature list for the previous test
            self.arff_List.append("NoSubdomain")

    #  function which determines the final location of the supplied url. Designed so that if re-directs are in use they can be circumvented.
    def url_parsing(self):

        #  create an http header to make it appear that requests aren't coming from python. This may help to bypass
        #  countermeasures to put in place to avoid grabbing the correct url.
        head = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'}

        #  try to determine the final url location using the requests library, and extract the domain from the result.
        try:
            request = requests.get(self.url, headers=head)
            self.domain = tldextract.extract(request).domain

            self.url = request.url  # set url to the final destination

        except Exception as e:
            pass

        # grab url and work out it's domain and path
        parsed_url = urlparse(str(self.url))
        self.domain = tldextract.extract(self.url).domain
        self.path = parsed_url.path

        # if the url's path is /, remove it
        if self.path == "/":
            self.path = ""

        # if the path ends in slash reduce the number of paths by 1
        if self.path.endswith("/"):
            self.path = self.path[:-1]

        # determine the url's scheme and query
        self.scheme = parsed_url.scheme
        self.query = parsed_url.query

        # append the lengths of the url, domain and path to the feature list
        self.arff_List.append(len(self.url))
        self.arff_List.append(len(self.domain))
        self.arff_List.append(len(self.path))

    # function for writing the data from the extracted features to a .arff file
    def write_arff(self):

        count = 0
        filename = "url.arff"
        list_of_lists = []

        # arff.dump requires a list of lists as a parameter, so convert the list of extracted features to a list of lists
        while count < len(self.arff_List):
            list_of_lists.append(self.arff_List[count:count + 23])
            count += 23

        self.arff_List = list_of_lists

        # write .arff file
        file = open('temp.arff', 'w+')
        file.close()
        arff.dump(str("temp.arff"), self.arff_List, relation="url_features", names=["length_of_url", "length_of_domain", "length_of_path", "depth_of_path", "num_dashes_in_domain",
                                                                               "num_of_queries", "https {'YesHttps', 'NoHttps', 'ErrorHttps'}", "IP_check {'NotIP', 'IP'}", "num_of_dots", "num_of_dashes", "num_of_underscores", "num_of_percent", "num_of_amp", "num_of_hash" , "tilde_exist {'Yes~', 'No~'}", "at_exist {'Yes@', 'No@'}",
                                                                               "num_of_numbers", "whether_double_slash_in_path {'YesDoubleSlashInPath', 'NoDoubleSlashInPath', 'NoPath'}", "num_of_subdomains", "whether_tld_in_subdomains {'YesTLDInSubdomain', 'NoTLDInSubdomain', 'NoSubdomain'}", "search_engine {'YesInSE', 'NotInSE', 'ErrorSE'}", "hrefs {'BadHREFs', 'GoodHREFs', 'NoHREFs', 'ErrorHREFs', 'N/AHREFs'}", "phishy_or_not {'NotPhishy', 'Phishy'}"])

        #  fix formatting so that the .arff file can be used by WEKA straight away
        file = open('temp2.arff', 'w+')
        file.close()

        with open("temp.arff", "rt") as fin:
            with open("temp2.arff", "w+") as fout:
                for line in fin:
                    fout.write(line.replace('\'?\'', '?'))

        with open("temp2.arff", "rt") as fin:
            with open(filename, "w+") as fout:
                for line in fin:
                    fout.write(line.replace('string', ''))

            os.remove("temp2.arff")
            os.remove("temp.arff")

