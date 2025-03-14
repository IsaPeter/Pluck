from pluck.generators.open_redirect_generator import OpenRedirectionPayloadGenerator
import pluck.settings as settings
import issuelib as issuelib
import random, string
from pluck.module import ActiveModule


class OpenRedirectionInjector(ActiveModule):
    def __init__(self, request):
        super().__init__(request)
        self.name="Open Redirection Tester"
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

   