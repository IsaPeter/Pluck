
from pluck.core import BaseModule, PayloadInjector, Finding
from pluck.generators.open_redirect_generator import OpenRedirectionPayloadGenerator
import pluck.settings as settings
from httplib import HTTPRequest, HTTPResponse,  HTTPRequestSender
import issuelib as issuelib
import random, string



class TestModule(BaseModule):
    def __init__(self, request):
        super().__init__(request)
        self.name="Test Module"
        self.generator = None
        self.random_domain = ""
        self.stop_testing = False

        self.test_parameters = []
        self.injection_points = ["path", "query", "body", "headers", "cookies"]
        self.excluded_parameters = []



    def run(self):
        
        # Generate payloads
        print(f"[*] Executing the {self.name} module")
        payloads = self.generate_payloads()


        generated_requests = self.generate_requests(payloads)

        for payload, point, key, req in generated_requests:
            print(f"Point: {point}, Param: {key}")

        

    def generate_requests(self, payloads):
        # Create an injector
        injector = PayloadInjector(HTTPRequest(self.original_request.rebuild_request()))
        
        # Injection dictionary létrehozása
        injection_dict = injector.find_injection_points() # This stores an injection dictionary
        
        # return back the points which have least 1 parameter
        available_injection_points = injector.get_available_injection_points()

        print(f"Generating requests for: Points: {str(self.injection_points)} and Parameters: {str(self.test_parameters)}")
        print("Available Injection Points: ", available_injection_points)
        print("Excluded Parameters: ", self.excluded_parameters)

        request_list = []
        # Minden feladat hozzáadása a queue-hoz
        for point in self.injection_points:
            if point in available_injection_points:
                print(f"Parameters for {point}: ", ', '.join(injector.get_injection_parameters(point)))
                for key in injection_dict[point]:
                    if key not in self.excluded_parameters:
                        if len(self.test_parameters) == 0 or key in self.test_parameters:
                            for payload in payloads:
                                new_request = HTTPRequest(self.original_request.rebuild_request())
                                injector = PayloadInjector(new_request)
                                injector.inject_payload(point, key, payload)
                                request_list.append((payload, point, key, new_request))

        return request_list

    def send_requests(self):
        pass

    def generate_payloads(self):
        
        
        self.generator = OpenRedirectionPayloadGenerator()
        return self.generator.generate_payloads(target_domain="127.0.0.1:9001")



    def analyze_response(self, response):
        if response.status_code == 302:
            if "Location" in response.headers or self.random_domain in response.body:
                return True
        if response.status_code >300 and response.statuc_code < 400:
            if "Location" in response.headers:
                addr = response.headers["Location"]
                if self.random_domain in addr:
                    return True
        elif "Location" in response.headers:
            addr = response.headers["Location"]
            if self.random_domain in addr:
                return True
        else:
            return False

    def record_finding(self, payload, point, key, request, response):
        f = Finding()
        f.name = "Open redirection Vulnerability"
        f.payload = payload
        f.injection_point = point
        f.parameter = key
        f.finding_type = "ored"
        f.module_name = self.name
        f.request = request
        f.response = response
        f.request_id = request.request_id
        issuelib.findings.append(f)

