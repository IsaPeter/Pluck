
from pluck.core import BaseModule, PayloadInjector, Finding
from pluck.generators.open_redirect_generator import OpenRedirectionPayloadGenerator
import pluck.settings as settings
from httplib import HTTPRequest, HTTPResponse,  HTTPRequestSender
import issuelib as issuelib
import random, string
from pluck.module import ActiveModule


class OpenRedirectionInjector(BaseModule):
    def __init__(self, request):
        super().__init__(request)
        self.name="Open Redirection Injection"
        self.generator = None
        self.default_injection_points = ["query", "body", "headers"]
        self.random_domain = ""
        self.stop_testing = False

    def generate_random_domain(length=20):
        # Engedélyezett karakterek: kisbetűk és számok
        chars = string.ascii_lowercase + string.digits
        
        # Véletlenszerű karakterlánc létrehozása
        random_string = ''.join(random.choices(chars, k=length))
        
        # Véletlenszerű domain végződés (pl. .com, .net, .org)
        domain_suffix = random.choice(['.com', '.net', '.org', '.io', '.xyz'])
        
        return random_string + domain_suffix

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
        
        if settings.collaborator_domain:
            generator = OpenRedirectionPayloadGenerator(target_domain=settings.collaborator_domain)
            return generator.generate_payloads()
        else:
            self.random_domain = self.generate_random_domain()
            self.generator = OpenRedirectionPayloadGenerator(target_domain=self.random_domain)
            return self.generator.generate_payloads()



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


class OpenRedirectionInjector2(ActiveModule):
    def __init__(self, request):
        super().__init__(request)
        self.name="Open Redirection Injection"
        self.generator = OpenRedirectionPayloadGenerator()
        self.default_injection_points = ["query", "body", "headers"]
        self.random_domain = ""
        self.stop_testing = False

    def generate_random_domain(length=20):
        # Engedélyezett karakterek: kisbetűk és számok
        chars = string.ascii_lowercase + string.digits
        
        # Véletlenszerű karakterlánc létrehozása
        random_string = ''.join(random.choices(chars, k=length))
        
        # Véletlenszerű domain végződés (pl. .com, .net, .org)
        domain_suffix = random.choice(['.com', '.net', '.org', '.io', '.xyz'])
        
        return random_string + domain_suffix

    def execute_before(self):
        self.saved_state = self.request_sender.allow_redirects
        self.request_sender.allow_redirects = False

    def execute_after(self):
        self.request_sender.allow_redirects = self.saved_state

    def analyze_response(self, response, request, payload, point, param):

        issue_found = False

       

        if response.status_code == 302:
            if "Location" in response.headers or self.domain in response.body:
                settings.finding_library.add_finding(name="Open Redirection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
                issue_found = True
               

        if response.status_code >300 and response.status_code < 400:
            if "Location" in response.headers:
                addr = response.headers["Location"]
                if self.random_domain in addr:
                    settings.finding_library.add_finding(name="Open Redirection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
                    issue_found = True
                   

        if "Location" in response.headers:
            addr = response.headers["Location"]
            if self.random_domain in addr:
                settings.finding_library.add_finding(name="Open Redirection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
                issue_found = True
               
        
        
        if issue_found and not self.continue_on_success:
            self.stop_test() 

   