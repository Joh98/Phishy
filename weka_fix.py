import os
import weka
import subprocess

path = os.path.dirname(weka.__file__)
command = "find " + path + "/ -type f -exec sed -i 's/Exception, /Exception as /g' {} \;"

subprocess.run(command, shell=True)
