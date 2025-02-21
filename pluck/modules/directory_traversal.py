
from pluck.core import BaseModule, PayloadInjector, Finding
import pluck.settings as settings
from httplib import HTTPRequest, HTTPResponse,  HTTPRequestSender
import issuelib as issuelib
from pluck.generators.traversal import DirectoryTraversalPayloadGenerator


class DirectoryTraversalTester(BaseModule):
    def __init__(self, request):
        super().__init__(request)
        self.name = "Directory Traversal Tester"
        self.test_parameters = []
        self.injection_points = ["path","query", "body", "headers", "cookies"]
        self.excluded_parameters = []
        self.generator = None

        self.success_strings = [
            'This is a sample HOSTS file used by Microsoft',
            'Copyright (c) 1993-2009 Microsoft Corp.',
            'root:x:0:0:root:/root',
        ]

        self.linux_success_files = ['resolv.conf', 'passwd', 'shadow']
        self.windows_success_files = ['ntdll.dll','ntdsapi.dll','winlogon.exe']


        
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
                print(f"[!] Directory Traversal Found in Point: {point} Parameter: {key}, Payload: {payload}. Request ID: {req.request_id}")
                break;

    def analyze_response(self, response):
        # check root in passwd
        for message in self.success_strings:
            if message.lower() in response.body.lower():
                return True

        if all([s.lower() in response.body.lower() for s in self.linux_success_files ]):
            return True
        
        if all([s.lower() in response.body.lower() for s in self.windows_success_files ]):
            return True
        
        
        return False


    def run(self):
         # Generate payloads
        print(f"[*] Executing the {self.name} module")
        self.generator = DirectoryTraversalPayloadGenerator()
        payloads = self.generator.generate_payloads()

        generated_requests = self.generate_requests(payloads)

        #print("Generated Requests Count: "+ str(len(generated_requests)))
        self.send_requests(generated_requests)


