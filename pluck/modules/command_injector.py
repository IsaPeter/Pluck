
from pluck.core import BaseModule, PayloadInjector, Finding
from pluck.generators.os_cigen import OSCommandInjectionPayloadGenerator
import pluck.settings as settings
from httplib import HTTPRequest, HTTPResponse,  HTTPRequestSender
import issuelib as issuelib
from pluck.module import ActiveModule


class OSCommandInjector(BaseModule):
    def __init__(self, request):
        super().__init__(request)
        self.name="OS Command Injector"
        self.generator = None
        self.default_injection_points = ["query", "body", "headers", "cookies"]

        self.stop_testing = False

    def run(self):
        if not self.sender:
            print("[!] Nincs sender beállítva.")
            return False

        print(f"[*] Executing the {self.name} module")
        payloads = self.generate_payloads()

        print(f"[+] Generated {len(payloads)} payloads.")

        injector = PayloadInjector(HTTPRequest(self.original_request.rebuild_request()))
        available_injection_dict = injector.find_injection_points() # This stores an injection dictionary
        
        injection_points = self.default_injection_points
        # Az összes nem üres kulcs listázása
        available_injection_points = [k for k, v in injector.find_injection_points().items() if len(v) > 0]
        #print("available_injection_points: ".upper()    ,available_injection_points)

        if len(settings.injection_points) > 0:
            injection_points = settings.injection_points  
        if "all" in self.default_injection_points:
            injection_points = ["path", "query", "body", "headers", "cookies"]


        request_list = []
        # Minden feladat hozzáadása a queue-hoz
        for point in injection_points:
            if point in self.default_injection_points and point in available_injection_points:
                for key in available_injection_dict[point]:
                    for payload in payloads:
                        #print(f"[+] Tesztelés: Point={point}, Paraméter={key}, Payload={payload}")
                        # Új kérés példányosítása
                        new_request = HTTPRequest(self.original_request.rebuild_request())
                        injector = PayloadInjector(new_request)
                        injector.inject_payload(point, key, payload)
                        request_list.append((payload, point, key, new_request))

        for _ in range(len(request_list)):
            if not self.stop_testing:
                payload, point ,key, request = request_list.pop()
                # Kérés elküldése és válasz elemzése
                response = self.sender.send_request(request)
                if self.analyze_response(response):
                    print(f"[!] Command Injection vulnerability found in Injection Point: {point}, Parameter: {key}, Payload: {payload}")
                    self.record_finding(payload, point, key, request, response)
                    self.stop_testing = True
                    break


    def generate_payloads(self):
        self.generator = OSCommandInjectionPayloadGenerator(target_address="127.0.0.1:9001")
        return self.generator.generate_payloads()
    
    def analyze_response(self, response):
        # BeautifulSoup segítségével keresés az ID alapján
        # Check Sleep timeout
        if response.elapsed_time >= self.generator.sleep_timeout:

            print("Reason: ", "Elapsed Time", str(response.elapsed_time))
            print("Generator Sleep: ", self.generator.sleep_timeout)
            return True
        # Check reflection string
        if self.generator.reflection_string in response.body:
            if "echo" not in response.body:
                print("Reason: ", "Reflected String")
                return True
        # Check os file reading & Check possible results
        for res in self.generator.possible_results:
            if res in response.body:
                print("Reason: ", "Possible Result in body")
                return True
    
        return False

    def record_finding(self, payload, point, key, request, response):
        f = Finding()
        f.name = "OS Command Injection Vulnerability"
        f.payload = payload
        f.injection_point = point
        f.parameter = key
        f.finding_type = "rce"
        f.module_name = self.name
        f.request = request
        f.response = response
        f.request_id = request.request_id
        issuelib.findings.append(f)



class OSCommandInjector2(ActiveModule):
    def __init__(self, request):
        super().__init__(request)
        self.name="OS Command Injector"
        self.generator = None
        self.default_injection_points = ["query", "body", "headers", "cookies"]

        self.generator = OSCommandInjectionPayloadGenerator()
        self.stop_testing = False

    
    def analyze_response(self, response, request, payload, point, param):
        # BeautifulSoup segítségével keresés az ID alapján
        # Check Sleep timeout
        issue_found = False


        if response.elapsed_time >= self.sleep_timeout:

            print("Reason: ", "Elapsed Time", str(response.elapsed_time))
            print("Generator Sleep: ", self.generator.sleep_timeout)
            settings.finding_library.add_finding(name="OS Command Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
            issue_found = True
        
        # Check reflection string
        elif self.unique_string in response.body:
            for line in response.body.splitlines():
                if self.unique_string in line and payload not in line and 'echo' not in line:
                    
                    settings.finding_library.add_finding(name="OS Command Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
                    issue_found = True
        
        elif (self.unique_string*3) in response.body:
            settings.finding_library.add_finding(name="OS Command Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
            issue_found = True


        # Check os file reading & Check possible results
        for res in self.evidence_strings:
            if res in response.body:
                settings.finding_library.add_finding(name="OS Command Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
                issue_found = True
    
        
        if issue_found and not self.continue_on_success:
            self.stop_test() 

