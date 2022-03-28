# SQL Extractor
## Description

This script is used to extract data from a web application vulnerable to SQL injection and that you know how to extract it. This is not a tool to find SQL injection.

## Installation

`python3 -m pip install requirements.txt`

## Usage

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

Run the script once without parameters to create a configuration file. 

```
$ python3 sqlextractor.py
New configuration file created: configurations/20220328112628.py
Setup your configuration and then use:
  python3 sqlextractor.py configurations/20220328112628.py
```

Then, modify the newly created file to setup your configurations and then execute that configuration by running the script again with the file in parameter.

```
python3 sqlextractor.py configurations/20220328112628.py
```