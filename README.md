# SQL Extractor
## Description
This script is used to extract data from a web application vulnerable to SQL injection and that you know how to extract it. This is not a tool to find SQL injection.

## Installation
`python3 -m pip install requirements.txt`

## Usage
Modify only the content in the function `userInputs(kwargs)` and then run the script.
```
usage: sqlextractor.py [-h] [-r REQUEST] [-o DIRECTORY] [-l {debug,info,warning,error,critical}] [-c]

optional arguments:
  -h, --help            show this help message and exit
  -r REQUEST, --request REQUEST
                        File containing an HTTP request to set the URL, method, data, cookies and headers. Don't forget to setup the {payload} and
                        etc.

logging arguments:
  -o DIRECTORY, --output DIRECTORY
                        Directory where to put the logging file (default is 'results'.)
  -l {debug,info,warning,error,critical}, --logging-level {debug,info,warning,error,critical}
                        Default warning
  -c, --useColor        Use color for the logging in console.
```