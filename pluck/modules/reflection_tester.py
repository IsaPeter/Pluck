import pluck.settings as settings
import string, random
from pluck.module import ActiveModule


class ParameterReflectionTester(ActiveModule):
    def __init__(self, request):
        super().__init__(request)
        self.name = "Parameter Reflection Tester"
        self.test_parameters = []
        self.injection_points = ["path","query", "body", "headers", "cookies"]
        self.excluded_parameters = []
        self.unique_string = self.generate_unique_string()

    def generate_unique_string(self, length=16):
        return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(length))
    


    def generate_ip_header_requests(self):
        ip_headers = ["CF-Connecting-IP", "Client-IP", "Fastly-Client-IP", "Forwarded", "True-Client-IP", "X-Client-Host", "X-Client-IP", "X-Cluster-Client-IP", "X-Forwarded-By", 
                      "X-Forwarded-Client-IP", "X-Forwarded-For", "X-Forwarded-For-Original", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Proto", "X-Forwarded-Server", 
                      "X-Host", "X-HTTP-Client-IP", "X-HTTP-Forwarded-For", "X-Original-Forwarded-For", "X-Original-Host", "X-Original-IP", "X-Original-Remote-Addr", "X-Originating-IP", 
                      "X-Proxy-Client-IP", "X-Proxy-IP", "X-ProxyUser-IP", "X-Real-IP", "X-Real-Remote-IP", "X-Remote-Addr", "X-Remote-IP", "X-Scheme", "X-True-IP"]
        request_list = []

        for header in ip_headers:
            payload = self.generate_unique_string()
            new_request = HTTPRequest(self.original_request.rebuild_request())
            new_request.set_custom_header(header, payload)
            request_list.append((payload, "headers", header, new_request))
        
        return request_list
             

    def analyze_response(self, response, request, payload, point, param):
        if payload in response.body:
            settings.finding_library.add_finding(name="Reflected Parameter",payload=payload, point=point, param=param, module=self.name, request=request, response=response)


    def run(self):
         # Generate payloads
        print(f"[*] Executing the {self.name} module")
        payloads = [self.unique_string]

        generated_requests = self.generate_requests(payloads)

        header_requests = self.generate_ip_header_requests()

        #print("Generated Requests Count: "+ str(len(generated_requests)))
        self.send_requests(generated_requests)
        self.send_requests(header_requests)

