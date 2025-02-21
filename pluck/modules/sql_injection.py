
from pluck.core import BaseModule, PayloadInjector, Finding
import pluck.settings as settings
from httplib import HTTPRequest, HTTPResponse,  HTTPRequestSender
import issuelib as issuelib
from pluck.generators.sqli_generator import SQLIGenerator
from pluck.module import ActiveModule

class SQLInjectionTester(BaseModule):
    def __init__(self, request):
        super().__init__(request)
        self.name = "SQL INjection Tester"
        self.test_parameters = []
        self.injection_points = ["path", "query", "body", "headers", "cookies"]
        self.excluded_parameters = []
        self.generator = None
        self.sleep_timeout = 15
        
        # Define SQL error codes
        self.error_codes = [
            'You have an error in your SQL syntax',
            'SQLSTATE',
            'ERROR: syntax error at or near',
            'syntax error',
            'SQLite error',
            'Incorrect syntax near',
            'ORA-',
            'ORA-00933',
            'SQL command not properly ended',
            'ILLEGAL SYMBOL',
            'SQLCODE',
            'Invalid argument'
        ]



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

        print("Generated Requests: ", len(request_list))
        return request_list
    
    def send_requests(self, request_list):

        for payload, point, key, req in request_list:
            response = self.sender.send_request(req)
            if self.analyze_response(response):
                print(f"[!] SQL Injection Found in Point: {point} Parameter: {key}, Payload: {payload}. Request ID: {req.request_id}")
                break;

    def analyze_response(self, response):
        # Check the error messages in the response
        for error in self.error_codes:
            if error.lower() in response.body.lower():
                return True
            
        if response.elapsed_time > self.sleep_timeout:
            return True
        
        return False


    def run(self):
         # Generate payloads
        print(f"[*] Executing the {self.name} module")
        self.generator = SQLIGenerator()
        payloads = self.generator.generate_payloads()

        generated_requests = self.generate_requests(payloads)

        #print("Generated Requests Count: "+ str(len(generated_requests)))
        self.send_requests(generated_requests)



class SQLInjectionTester2(ActiveModule):
    def __init__(self, request):
        super().__init__(request)
        self.name = "SQL Injection Tester"
        self.test_parameters = []
        self.injection_points = ["path", "query", "body", "headers", "cookies"]
        self.excluded_parameters = []
        self.generator = SQLIGenerator()
        self.sleep_timeout = 15
        
        # Define SQL error codes
        self.error_codes = [
            'You have an error in your SQL syntax',
            'SQLSTATE',
            'ERROR: syntax error at or near',
            'syntax error',
            'SQLite error',
            'Incorrect syntax near',
            'ORA-',
            'ORA-00933',
            'SQL command not properly ended',
            'ILLEGAL SYMBOL',
            'SQLCODE',
            'Invalid argument'
        ]



  

    def analyze_response(self, response, request, payload, point, param):
        issue_found = False

        # Check the error messages in the response
        for error in self.error_codes:
            if error.lower() in response.body.lower():
                settings.finding_library.add_finding(name="SQL Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
                issue_found = True
              
            
        if response.elapsed_time > self.sleep_timeout:
            settings.finding_library.add_finding(name="SQL Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
            issue_found = True
              

        if issue_found and not self.continue_on_success:
            self.stop_test()      


    def run(self):
         # Generate payloads
        print(f"[*] Executing the {self.name} module")
        self.generator = SQLIGenerator()
        payloads = self.generator.generate_payloads()

        generated_requests = self.generate_requests(payloads)

        #print("Generated Requests Count: "+ str(len(generated_requests)))
        self.send_requests(generated_requests)

