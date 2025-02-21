import pluck.settings as settings
import issuelib as issuelib
from pluck.generators.sqli_generator import SQLIGenerator
from pluck.module import ActiveModule



class SQLInjectionTester(ActiveModule):
    def __init__(self, request):
        super().__init__(request)
        self.name = "SQL Injection Tester"
        self.test_parameters = []
        self.injection_points = ["path", "query", "body", "headers", "cookies"]
        self.excluded_parameters = []
        self.generator = SQLIGenerator()
        self.sleep_timeout = 15
        
        # Define SQL error codes
        self.error_codes = [
            'You have an error in your SQL syntax',
            'SQLSTATE',
            'ERROR: syntax error at or near',
            'syntax error',
            'SQLite error',
            'Incorrect syntax near',
            'ORA-',
            'ORA-00933',
            'SQL command not properly ended',
            'ILLEGAL SYMBOL',
            'SQLCODE',
            'Invalid argument'
        ]



  

    def analyze_response(self, response, request, payload, point, param):
        issue_found = False

        # Check the error messages in the response
        for error in self.error_codes:
            if error.lower() in response.body.lower():
                settings.finding_library.add_finding(name="SQL Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
                issue_found = True
              
            
        if response.elapsed_time > self.sleep_timeout:
            settings.finding_library.add_finding(name="SQL Injection",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
            issue_found = True
              

        if issue_found and not self.continue_on_success:
            self.stop_test()      


    def run(self):
         # Generate payloads
        print(f"[*] Executing the {self.name} module")
        self.generator = SQLIGenerator()
        payloads = self.generator.generate_payloads()

        generated_requests = self.generate_requests(payloads)

        #print("Generated Requests Count: "+ str(len(generated_requests)))
        self.send_requests(generated_requests)

