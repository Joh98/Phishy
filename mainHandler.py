import os
import pyfiglet
import requests
from termcolor import colored
from tldextract import tldextract
from whiteBlacklist import WhiteBlackApp
from urlAnalysis import URLAnalysis


# python class for the handling of data, running of tests against urls and interacting with Firebase
class MainHandler:

    # Constructor
    def __init__(self, url):

        # initialise variables
        self.url = url
        self.domain = ""
        self.id = ""
        self.show_banner()


    # function which extracts the domain from the url using tldextract
    def extract_domain(self):

        self.domain = tldextract.extract(self.url).domain

    # function which works out the final destination of the URL
    def get_url(self):

        # add http:// on front of the url if it doesn't have a scheme (requried so that the final url's location can be determined)
        if not self.url.startswith("http"):
            self.url = "http://" + self.url

        # try to work out the final destination of the url using the requests library. A header has been added so that
        # websites believe that the request is legit traffic.
        head = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'}
        try:
            request = requests.get(self.url, headers=head)

            # set the url to that resolved by the requests library and call the run ("main") function
            self.url = request.url

        # if an exception is thrown it is unlikely that the website live, so exit program
        except Exception as e:

            os.system("clear")
            self.show_banner()
            print("URL: " + colored(self.url, 'white') + "\n")
            print(colored("[*]  AN ERROR OCCURRED. THE URL MIGHT NOT BE VALID OR LIVE  [*]\n", 'red'))
            exit()

    # main function
    def run(self):

        self.get_url()
        # print the url on UI
        print("URL: " + colored(self.url, 'white') + "\n")

        self.extract_domain()  # call function to determine the domain associated with the url

        # run white and blacklist tests from WhiteBlack class against the url
        white_black_test = WhiteBlackApp(self.url, self.domain)
        white_black_results = white_black_test.run()

        # if the blacklist test has been failed, print FAIL message
        if white_black_results[0]:

            # UI
            print(colored("\n[*] THE URL HAS BEEN DETERMINED AS PHISHY [*]\n", 'red', attrs=['bold']))

        # else if the whitelist test has been passed, print PASS message
        elif white_black_results[1]:

            # UI
            print(colored("\n[*] THE URL HAS BEEN DETERMINED AS NOT PHISHY [*]\n", attrs=['bold']))

        # else call URLAnalysis class and use its functions to determine if the url is "Phishy" or not via
        # feature extraction and machine learning
        else:

            result = URLAnalysis(self.url)
            ml_result = result.run()

            # if the result returned from URLAnalysis is 1.0 ("phishy"), print FAIL message
            if ml_result:

                # UI
                print(colored("\n[*] THE URL HAS BEEN DETERMINED AS PHISHY VIA MACHINE LEARNING [*]\n", 'red',
                              attrs=['bold']))

            # else print PASS message
            else:

                # UI
                print(colored("\n[*] THE URL HAS BEEN DETERMINED AS NOT PHISHY VIA MACHINE LEARNING [*]\n", attrs=['bold']))

        exit()
    # function which is used to show an ASCII banner on the console
    def show_banner(self):

        os.system("clear")
        print(pyfiglet.figlet_format("'Phishy'"))
        print("----------------------------------------------------------\n")
