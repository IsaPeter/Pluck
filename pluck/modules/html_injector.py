from pluck.core import BaseModule, PayloadInjector, Finding
from pluck.generators.htmli_generator import HTMLInjectionPayloadGenerator2
from bs4 import BeautifulSoup
import pluck.settings as settings
from httplib import HTTPRequest, HTTPResponse,  HTTPRequestSender
import issuelib as issuelib
from threading import Thread, Lock
from queue import Queue, Empty
from pluck.module import ActiveModule



class HtmlInjectionTester(BaseModule):
    def __init__(self, request):
        super().__init__(request)
        self.name="HTML Injector"
        self.generator = None
        self.default_injection_points = ["query", "body"]

        # Többszálúsításhoz szükséges változók
        self.task_queue = Queue()
        self.num_threads = 5  # Szálak száma, amit igény szerint módosíthatsz
        self.stop_testing = False
        self.lock = Lock()

    def run(self):
        if not self.sender:
            print("[!] Nincs sender beállítva.")
            return False

        print(f"[*] Executing the {self.name} module")
        payloads = self.generate_payloads()

        print(f"[+] Generated HTML {len(payloads)} payloads.")

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
                    self.record_finding(payload, point, key, request, response)
                    self.stop_testing = True
                    break

        

       

    def worker(self):
        """Ez a függvény dolgozza fel a queue elemeit."""
        while not self.stop_testing:
            try:
                point, key, payload = self.task_queue.get(timeout=1)

                # Ellenőrizzük, hogy közben talált-e már másik szál
                with self.lock:
                    if self.stop_testing:
                        break  # Kilépés, ha már volt találat

                print(f"[+] Tesztelés: Point={point}, Paraméter={key}, Payload={payload}")


                # Új kérés példányosítása
                new_request = HTTPRequest(self.original_request.rebuild_request())
                injector = PayloadInjector(new_request)
                injector.inject_payload(point, key, payload)

                # Kérés elküldése és válasz elemzése
                response = self.sender.send_request(new_request)

                # Újabb ellenőrzés a válasz elküldése után
                with self.lock:
                    if self.stop_testing:
                        break  # Kilépés a worker ciklusból, ha már volt találat

                if self.analyze_response(response):
                    self.record_finding(payload, point, key, new_request, response)

                    # Tesztelés leállítása találat esetén
                    with self.lock:
                        self.stop_testing = True
                        self.task_queue.task_done()

                    # Minden fennmaradó feladat törlése a queue-ból
                    while not self.task_queue.empty():
                        self.task_queue.get_nowait()
                        self.task_queue.task_done()

            except Empty:
                break
            except Exception as e:
                print(f"[!] Hiba történt a workerben: {e}")
                self.task_queue.task_done()



    def generate_payloads(self):
        self.generator = HTMLInjectionPayloadGenerator(target_address="127.0.0.1")
        return self.generator.generate_payloads()
    
    def analyze_response(self, response):
        # BeautifulSoup segítségével keresés az ID alapján
        soup = BeautifulSoup(response.body, 'html.parser')
        injected_element = soup.find(id=self.generator.unique_id)

        if injected_element:
            print(f"[+] Talált HTML elem az ID alapján: {self.generator.unique_id}")
            return True
        else:
            # Ellenőrzés, hogy a possible_results listában lévő értékek megjelennek-e a válaszban
            for result in self.generator.possible_results:
                if result in response.body:
                    print(f"[+] Lehetséges injektált érték megtalálva a DOM-ban: {result}.")
                    return False
        return False

    def record_finding(self, payload, point, key, request, response):
        f = Finding()
        f.name = "HTML Injection Vulnerability"
        f.payload = payload
        f.injection_point = point
        f.parameter = key
        f.finding_type = "htmli"
        f.module_name = self.name
        f.request = request
        f.response = response
        f.request_id = request.request_id
        issuelib.findings.append(f)

    def debug(self):
        import code
        code.interact(local=locals())





class HTMLInjectionTester2(BaseModule):
    def __init__(self, request):
        super().__init__(request)
        self.name = "HTML Injection Tester"
        self.test_parameters = []
        self.injection_points = ["query", "body", "headers", "cookies"]
        self.excluded_parameters = []
        self.generator = None
        
    def generate_requests(self, payloads):
        # Create an injector
        injector = PayloadInjector(HTTPRequest(self.original_request.rebuild_request()))
        
        # Injection dictionary létrehozása
        injection_dict = injector.find_injection_points() # This stores an injection dictionary
        
        # return back the points which have least 1 parameter
        available_injection_points = injector.get_available_injection_points()

        #print(f"Generating requests for: Points: {str(self.injection_points)} and Parameters: {str(self.test_parameters)}")
        #print("Available Injection Points: ", available_injection_points)
        #print("Excluded Parameters: ", self.excluded_parameters)
        #print("Available Parameters: ")

        request_list = []
        # Minden feladat hozzáadása a queue-hoz
        for point in self.injection_points:
            if point in available_injection_points:
                #print(f"Parameters for {point}: ", ', '.join(injector.get_injection_parameters(point)))
                for key in injection_dict[point]:
                    if key not in self.excluded_parameters:
                        if len(self.test_parameters) == 0 or key in self.test_parameters:
                            for p in payloads:
                                new_request = HTTPRequest(self.original_request.rebuild_request())
                                injector = PayloadInjector(new_request)
                                injector.inject_payload(point, key, p)
                                request_list.append((p, point, key, new_request))

        return request_list
    
    def send_requests(self, request_list):

        for payload, point, key, req in request_list:
            response = self.sender.send_request(req)
            if self.analyze_response(response, payload):
                print(f"[!] HTML Injection Found in Point: {point} Parameter: {key}, Payload: {payload}. Request ID: {req.request_id}")
                break;

    def analyze_response(self, response, payload):
        # BeautifulSoup segítségével keresés az ID alapján
        soup = BeautifulSoup(response.body, 'html.parser')
        injected_element = soup.find(id=self.generator.unique_id)

        if injected_element:
            print(f"[+] Talált HTML elem az ID alapján: {self.generator.unique_id}")
            return True
        else:
            # Ellenőrzés, hogy a possible_results listában lévő értékek megjelennek-e a válaszban
            for result in self.generator.possible_results:
                if result in response.body:
                    print(f"[+] Lehetséges injektált érték megtalálva a DOM-ban: {result}.")
                    return False
        return False


    def run(self):
         # Generate payloads
        print(f"[*] Executing the {self.name} module")
        self.generator = HTMLInjectionPayloadGenerator()
        payloads = self.generator.generate_payloads()

        generated_requests = self.generate_requests(payloads)

        #print("Generated Requests Count: "+ str(len(generated_requests)))
        self.send_requests(generated_requests)


class HTMLInjectionTester3(ActiveModule):
    def __init__(self, request):
        super().__init__(request)
        self.name = "HTML Injection Tester"
        self.test_parameters = []
        self.injection_points = ["query", "body", "headers", "cookies"]
        self.excluded_parameters = []
        self.generator = HTMLInjectionPayloadGenerator2()

        
        
   
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

   

