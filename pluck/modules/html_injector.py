from pluck.generators.htmli_generator import HTMLInjectionPayloadGenerator
from bs4 import BeautifulSoup
import pluck.settings as settings
from pluck.module import ActiveModule


class HTMLInjectionTester3(ActiveModule):
    def __init__(self, request):
        super().__init__(request)
        self.name = "HTML Injection Tester"
        self.test_parameters = []
        self.injection_points = ["query", "body", "headers", "cookies"]
        self.excluded_parameters = []
        self.generator = HTMLInjectionPayloadGenerator()

        
        
   
    def analyze_response(self, response, request, payload, point, param):
        # BeautifulSoup segítségével keresés az ID alapján
        soup = BeautifulSoup(response.body, 'html.parser')
        injected_element = soup.find(id=self.unique_string)
        issue_found = False
       

        if injected_element:
            settings.finding_library.add_finding(name="HTML Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
            issue_found = True
           
        else:
            # Ellenőrzés, hogy a possible_results listában lévő értékek megjelennek-e a válaszban
            for result in self.evidence_strings:
                if result in response.body:
                    settings.finding_library.add_finding(name="HTML Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
                    issue_found = True
                    break
                   
     


        if issue_found and not self.continue_on_success:
            self.stop_test()  

   

