
from pluck.core import PayloadInjector
import pluck.settings as settings
from httplib import HTTPRequest
from pluck.generators.templater import TemplateInjectionGenerator
from pluck.module import ActiveModule


class TemplateInjectionTester(ActiveModule):
    def __init__(self,request):
        super().__init__(request)
        self.name = "Template Injection Tester 2"
        self.generator = TemplateInjectionGenerator()
    
    def analyze_response(self, response, request, payload, point, param):
        
        issue_found = False

        for message in self.evidence_strings:
            if message.lower() in response.body.lower():
                settings.finding_library.add_fnding(name="Template Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
                issue_found = True
            
        # check sleep time
        if response.elapsed_time > self.generator.sleep_timeout:
            settings.finding_library.add_fnding(name="Template Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
            issue_found = True

        # check unique string in result
        
        if self.generator.unique_string in response.body:
            settings.finding_library.add_fnding(name="Template Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
            issue_found = True

        if issue_found and not self.continue_on_success:
            self.stop_test()

    

    