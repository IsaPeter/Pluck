from pluck.generators.os_cigen import OSCommandInjectionPayloadGenerator
import pluck.settings as settings
from pluck.module import ActiveModule

class OSCommandInjector(ActiveModule):
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

