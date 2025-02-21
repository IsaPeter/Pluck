from pluck.core import BaseModule, PayloadInjector, Finding
from httplib import HTTPRequest, HTTPResponse, HTTPRequestSender



class HttpMethodTester(BaseModule):
    def __init__(self, request):
        super().__init__(request)
        self.name = "Http Method Tester"
        self.sender = None
        self.safe_headers = ["OPTIONS", "GET", "HEAD", "POST"]
        self.baseline_data = {}


    def generate_payloads(self):
        http_verbs = ["GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT", 
                      "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", 
                      "VERSION-CONTROL", "REPORT", "CHECKOUT", "CHECKIN", "UNCHECKOUT", 
                      "MKWORKSPACE", "UPDATE", "LABEL", "MERGE", "BASELINE-CONTROL", 
                      "MKACTIVITY", "ORDERPATCH", "ACL", "PATCH", "SEARCH", "ARBITRARY",
                      ]
        return http_verbs
    def run(self):
        payloads = self.generate_payloads()

        request = HTTPRequest(self.original_reguest.rebuild_request())

        # Send a baseline request for data
        self.send_baseline_request()

        # Senf OPTIONS for the allowed Headers
        self.send_options()


        for verb in payloads:
            request.method = verb.upper()
            response = self.sender.send_request(request)
            self.analyze_response(request, response)

    def send_baseline_request(self):
        # Send a baseline request for informations
        response = self.sender.send_request(HTTPRequest(self.original_request.rebuild_request()))
        self.baseline_data["status_code"] = response.status_code
        self.baseline_data["response_length"] = len(response.body)
        self.baseline_data["headerslist"] = ",".join([h for h in response.headers.keys()])

    def send_options(self):
        # Send a baseline request for informations
        request = HTTPRequest(self.original_request.rebuild_request())
        request.method = "OPTIONS"
        response = self.sender.send_request(request)
        if "Allow" in response.headers:
            insecure_headers = []
            allowed_headers = [ h.strip() for h in response.headers['Allow'].split(',')]
            self.baseline_data["allowed_headers"] = allowed_headers
            for h in allowed_headers:
                if h not in self.safe_headers:
                    insecure_headers.append(h)
        # Az insecure headersben lévő headerek insecurenak tekinthetőek.
        
         

    def analyze_response(self, request, response):
        # Check the Allow header
        if "Allow" in response.headers:
            insecure_headers = []
            allowed_headers = [ h.strip() for h in response.headers['Allow'].split(',')]
            for h in allowed_headers:
                if h not in self.safe_headers:
                    insecure_headers.append(h)
        
