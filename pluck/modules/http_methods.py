from httplib import HTTPRequest
import pluck.settings as settings
from pluck.module import ActiveModule



class HttpMethodTester2(ActiveModule):
    def __init__(self, request):
        super().__init__(request)
        self.name = "HTTP Method Tester" 

        # Alap HTTP metódusok
        self.methods_to_test = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT', 'PATCH']
        
        # Verb tampering variációk hozzáadása
        self.verb_tampering_variants = [
            lambda method: method.lower(),            # Kisbetűs pl.: get
            lambda method: method.capitalize(),       # Első betű nagy pl.: Get
            lambda method: method.swapcase(),         # Vegyes betűk pl.: gET
        ]

        self.stop_testing = False
        

        # Baseline kérés válasza (összehasonlításhoz)
        self.baseline_response = None
        self.allowed_methods = []

    def run(self): 
        print(f"[*] Executing the {self.name} module")
        
        # Baseline kérés elküldése
        self.baseline_response = self.get_baseline_response()
        
        # OPTIONS kérés az engedélyezett metódusok lekéréséhez
        self.allowed_methods = self.get_allowed_methods()
        #print(f"[+] Engedélyezett metódusok (OPTIONS válasz alapján): {self.allowed_methods}")

        task_queue = []
        # Feladatok hozzáadása a queue-hoz
        for method in self.methods_to_test:
            # 1. Normál metódus body nélkül
            task_queue.append((method, False, False))  # (method, is_tampered, has_body)

            # 2. Ha metódus enged tartalmat, küldünk body-t is
            if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                task_queue.append((method, False, True))  # Body-val is teszteljük

            # Verb Tampering variációk
            for tampered_method_func in self.verb_tampering_variants:
                tampered_method = tampered_method_func(method)

                # 3. Verb tampered metódus body nélkül
                task_queue.append((tampered_method, True, False))

                # 4. Verb tampered metódus body-val
                if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                    task_queue.append((tampered_method, True, True))

        # testing phase
        for method, is_tampered, has_body in task_queue:
            test_request = HTTPRequest(self.original_request.rebuild_request())
            test_request.method = method

            # Ha kell body, adjuk hozzá
            if has_body:
                test_request.body = "test=data&check=1"

                     
            # Kérés elküldése
            response = self.request_sender.send_request(test_request)
           
               

            # Válasz elemzése
            self.analyze_response(method, response, test_request, has_body, is_tampered)

    def get_baseline_response(self):
        """Alapértelmezett (baseline) GET kérés válaszának lekérése összehasonlításhoz."""
        baseline_request = HTTPRequest(self.original_request.rebuild_request())
        baseline_request.method = 'GET'

        response = self.sender.send_request(baseline_request)
        return response

    # obtain the allowed methods from options request
    def get_allowed_methods(self):
        """OPTIONS kérés küldése az engedélyezett HTTP metódusok lekéréséhez."""
        options_request = HTTPRequest(self.original_request.rebuild_request())
        options_request.method = 'OPTIONS'

        #options_request.set_custom_header("Content-Length","0")
        
        response = self.sender.send_request(options_request)

        allow_header = response.headers.get('Allow', '')
        if allow_header:
            allowed_methods = [method.strip() for method in allow_header.split(',')]
            return allowed_methods
        else:
            #print("[!] Az OPTIONS válasz nem tartalmaz 'Allow' fejlécet.")
            return []

    def analyze_response(self, method, response, request, has_body, is_tampered):
        """A válasz elemzése és összehasonlítása a baseline kérés válaszával."""
        #print(f"[+] {method} válasz státusz: {response.status_code} "
        #      f"{'(body-val)' if has_body else '(body nélkül)'}")
        issue_found = False


        # Potenciálisan veszélyes metódusok
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        

        if method.strip().upper() in dangerous_methods and response.status_code < 400:
            settings.finding_library.add_finding(name="Dangerous HTTP Method",payload=method, point="query", param=method, module=self.name, request=request, response=response)
            issue_found = True
            description = f"{method} metódus engedélyezve!"

        if issue_found and not self.continue_on_success:
            self.stop_test()    

        # Verb tampering tesztelés
        #if is_tampered and response.status_code < 400:
        #    description = f"Verb tampering sikeres lehet: {method}"
        #    if has_body:
        #        description += " Body-val."
        #    self.record_finding(method, response, request, description)

        # Eltérés a baseline-hoz képest
        #if method != 'GET' and response.body != self.baseline_response.body:
        #    description = f"Eltérés a baseline-hoz képest {method} metódusnál."
        #    if has_body:
        #        description += " (Body-val)"
        #    self.record_finding(method, response, request, description)


   