import pluck.settings as settings
from pluck.generators.ssi_generator import SSIPayloadGenerator
from pluck.module import ActiveModule

class SSIInjectionTester(ActiveModule):
    def __init__(self, request):
        super().__init__(request)
        self.name = "SSI Injection Tester"
        self.test_parameters = []
        self.injection_points = ["query", "body", "headers", "cookies"]
        self.excluded_parameters = []
        self.generator = SSIPayloadGenerator()
        
    def analyze_response(self, response, request, payload, point, param):
        issue_found = False

        # check root in passwd
        if "root:x:0:0:root:/root:" in response.body:
            settings.finding_library.add_finding(name="SSI Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
            issue_found = True

        # check sleep time
        if response.elapsed_time > self.sleep_timeout:
            settings.finding_library.add_finding(name="SSI Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
            issue_found = True

        # check unique string in result
        
        if self.unique_string in response.body:
            settings.finding_library.add_finding(name="SSI Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
            issue_found = True

        if issue_found and not self.continue_on_success:
            self.stop_test()