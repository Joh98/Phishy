import time
import weka.core.jvm as jvm
import weka.core.serialization as serialization
from weka.core.converters import Loader
from weka.classifiers import Classifier
from featureExtraction import FeatureExtraction
from mainHandler import *


# python class which takes the supplied url and works out if it's "Phishy" or not using an already trained Random Tree algorithm
class URLAnalysis:

    #  Constructor
    def __init__(self, url):

        self.results_list = []
        self.weka_model = "trained-random-tree.model"
        self.dataset = "url.arff"
        self.url = url
        self.prediction = ""

    # function which calls a function from another class which will extract features from the url and save them to a .arff file
    def generate_arff(self):

        extract = FeatureExtraction()

        extract.run()

        time.sleep(0.5)  # sleep just so everything runs smoothly

    # function which generates a .csv and writes the url which will be tested into it
    def generate_csv(self):
        with open("url.csv", "w+") as file:
            file.write(self.url)

        file.close()

    # main function
    def run(self):
        jvm.start()  # start Java VM for WEKA

        self.show_banner()  # call function to draw the banner on the UI
        self.generate_csv()  # call function to generate the csv file which will contain the url which will be tested
        self.generate_arff()  # call function which will use another class to extract features from the url and save to a .arff file
        self.show_banner()  # call function to draw the banner on the UI
        self.weka_predict()  # call function to predict whether the url is "phishy" or not via the generated .arff file

        jvm.stop()

        return self.prediction  # return the predicted result back to MainHandler

    # function which is used to show an ASCII banner on the console
    # (would have used the function within MainHandler, but it caused the Java VM and WEKA to bug out)
    def show_banner(self):
        os.system("clear")
        print(pyfiglet.figlet_format("'Phishy'"))
        print("----------------------------------------------------------\n")
        print("URL: " + colored(self.url, 'white') + "\n")

    # function which determines if the url is "Phishy" or not by testing the .arff file on a trained Random Tree WEKA model
    def weka_predict(self):

        # grab WEKA model
        objects = serialization.read_all(self.weka_model)
        classifier = Classifier(jobject=objects[0])

        # load the dataset i.e. the .arff file generated for the supplied url
        loader = Loader(classname="weka.core.converters.ArffLoader")
        data = loader.load_file(self.dataset)
        data.class_is_last()

        # for each url tested predict whether "Phishy" or not by using the Random Tree model
        for item in data:
            self.prediction = classifier.classify_instance(item)
