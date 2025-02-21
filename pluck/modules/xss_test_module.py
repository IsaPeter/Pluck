from pluck.core import BaseModule, PayloadInjector, Finding
from pluck.generators.xss_generator import XSSPayloadGenerator
import pluck.settings as settings
from httplib import HTTPRequest, HTTPResponse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import issuelib as issuelib
import uuid
from pluck.module import ActiveModule


from threading import Thread, Lock
from queue import Queue, Empty

class XssTester(BaseModule):
    def __init__(self, request):
        super().__init__(request)
        self.name = "XSSTester"
        self.default_injection_points = ["query", "body"]
        self.xss_popup_timeout = 1
        self.sender = None

        # Headless böngésző beállítása
        self.webdriver_options = Options()
        self.webdriver_options.add_argument("--headless=new")
        #self.webdriver_options.add_argument("--disable-gpu")  # GPU kikapcsolása
        self.webdriver_options.add_argument("--window-size=1920,1080")  # Ablak méretének beállítása
        self.webdriver_options.add_argument("--no-sandbox")  # Sandbox kikapcsolása bizonyos környezetekben
        
        #self.driver = webdriver.Edge(options=self.webdriver_options)

        # Több szálas feldolgozáshoz szükséges queue és kontroll változó
        self.task_queue = Queue()
        self.num_threads = 5  # Szálak száma
        self.stop_testing = False  # Ez jelzi, ha találat van
        self.lock = Lock()  # Szálbiztos változók módosításához

    def generate_payloads(self):
        generator = XSSPayloadGenerator()
        return generator.generate_payloads()

    def run(self):
        if not self.sender:
            print("[!] Nincs sender beállítva.")
            return False

        print(f"[*] Executing the {self.name} module")
        payloads = self.generate_payloads()

        if settings.xss_popup_timeout:
            self.xss_popup_timeout = settings.xss_popup_timeout 

        print(f"[+] Generated {len(payloads)} payloads.")

        injector = PayloadInjector(HTTPRequest(self.original_request.rebuild_request()))
        available_injection_dict = injector.find_injection_points() # This stores an injection dictionary


        injection_points = self.default_injection_points
        available_injection_points = [k for k, v in injector.find_injection_points().items() if len(v) > 0]

        if len(settings.injection_points) > 0:
            self.default_injection_points = settings.injection_points 
        if "all" in self.default_injection_points:
            self.default_injection_points = ["path", "query", "body", "headers", "cookies"]

        # Minden feladat hozzáadása a queue-hoz
        for point in injection_points:
            if point in self.default_injection_points and point in available_injection_points:
                for key in available_injection_dict[point]:
                    for payload in payloads:
                        self.task_queue.put((point, key, payload))

        # Szálak indítása
        threads = []
        for _ in range(self.num_threads):
            t = Thread(target=self.worker)
            t.start()
            threads.append(t)

        # Várakozás az összes feladat befejezésére vagy találatra
        self.task_queue.join()


    def worker(self):
        """Ez a függvény dolgozza fel a queue elemeit."""

        driver = webdriver.Edge(options=self.webdriver_options)

        while not self.stop_testing:
            try:
                point, key, payload = self.task_queue.get(timeout=1)

                # Ellenőrizzük, hogy közben talált-e már másik szál
                with self.lock:
                    if self.stop_testing:
                        self.task_queue.task_done()
                        break

                #print(f"[+] Tesztelés: Point={point}, Paraméter={key}, Payload={payload}")

                # Új kérés példányosítása
                new_request = HTTPRequest(self.original_request.rebuild_request())
                injector = PayloadInjector(new_request)
                injector.inject_payload(point, key, payload)

                # Kérés elküldése és válasz elemzése
                response = self.sender.send_request(new_request)

                with self.lock:
                    if self.stop_testing:
                        self.task_queue.task_done()
                        break  # Kilépés a worker ciklusból, ha már volt találat

                if self.analyze_response(response, driver):
                    #print(f"[!] XSS találat: {payload} @ {point}:{key}")
                    self.record_finding(payload, point, key, new_request, response)

                    # Tesztelés leállítása találat esetén
                    with self.lock:
                        self.stop_testing = True

                    # Minden fennmaradó feladat törlése a queue-ból
                    while not self.task_queue.empty():
                        self.task_queue.get_nowait()
                        self.task_queue.task_done()

                self.task_queue.task_done()

            except Empty:
                break
            except Exception as e:
                print(f"[!] Hiba történt a workerben: {e}")
                self.task_queue.task_done()
        driver.quit()

    def analyze_response(self, response, driver):
        try:
            
            driver.get("data:text/html;charset=utf-8," + response.body)
        
            WebDriverWait(driver, 5).until(EC.alert_is_present())
            fname = response.response_id+".png"
            driver.save_screenshot("/tmp/"+fname)
            alert = driver.switch_to.alert
            alert_text = alert.text
            print(f"Alert detektálva! Üzenet: {alert_text}")
            #fname = str(uuid.uuid4())+".png"
            #self.driver.save_screenshot("/tmp/"+fname)
            return True
        except:
            return False

    def record_finding(self, payload, point, key, request, response):
        f = Finding()
        f.name = "Reflected XSS Vulnerability"
        f.payload = payload
        f.injection_point = point
        f.parameter = key
        f.finding_type = "xss"
        f.module_name = self.name
        f.request = request
        f.response = response
        f.request_id = request.request_id
        issuelib.findings.append(f)

from pluck.generators.xgen import XssGen, XssGen2


class XssTester2(BaseModule):
    def __init__(self, request):
        super().__init__(request)
        self.name="Test XSS Module"
        self.generator = None
        self.random_domain = ""
        self.stop_testing = False

        self.test_parameters = []
        self.injection_points = ["path", "query", "body", "headers", "cookies"]
        self.excluded_parameters = []
        self.collect_request_count = 100

        # Headless böngésző beállítása
        self.webdriver_options = Options()
        self.webdriver_options.add_argument("--headless")
        #self.webdriver_options.add_argument("--disable-gpu")  # GPU kikapcsolása
        self.webdriver_options.add_argument("--window-size=1920,1080")  # Ablak méretének beállítása
        self.webdriver_options.add_argument("--no-sandbox")  # Sandbox kikapcsolása bizonyos környezetekben

    def run(self):
        # Generate payloads
        print(f"[*] Executing the {self.name} module")
        payloads = self.generate_payloads()

        generated_requests = self.generate_requests(payloads)

        print("Generated Requests Count: "+ str(len(generated_requests)))
        self.send_requests(generated_requests)


    def generate_requests(self, payloads):
        # Create an injector
        injector = PayloadInjector(HTTPRequest(self.original_request.rebuild_request()))
        
        # Injection dictionary létrehozása
        injection_dict = injector.find_injection_points() # This stores an injection dictionary
        
        # return back the points which have least 1 parameter
        available_injection_points = injector.get_available_injection_points()

        print(f"Generating requests for: Points: {str(self.injection_points)} and Parameters: {str(self.test_parameters)}")
        print("Available Injection Points: ", available_injection_points)
        print("Excluded Parameters: ", self.excluded_parameters)
        print("Available Parameters: ")

        request_list = []
        # Minden feladat hozzáadása a queue-hoz
        for point in self.injection_points:
            if point in available_injection_points:
                print(f"Parameters for {point}: ", ', '.join(injector.get_injection_parameters(point)))
                for key in injection_dict[point]:
                    if key not in self.excluded_parameters:
                        if len(self.test_parameters) == 0 or key in self.test_parameters:
                            for payload in payloads:
                                new_request = HTTPRequest(self.original_request.rebuild_request())
                                injector = PayloadInjector(new_request)
                                injector.inject_payload(point, key, payload)
                                request_list.append((payload, point, key, new_request))

        return request_list
    
    def generate_payloads(self):
        self.generator = XssGen()
        self.generator.waf_bypass = True
        self.generator.reverse_payload = True

        dom = self.generator.generate_dom_modify_payloads()
        log = self.generator.generate_logger_payloads()
        oast = []

        if settings.collaborator_domain:
            self.domain = "http://"+settings.collaborator_domain
            oast = self.generator.generate_oast_payloads()

        return dom + log + oast
    
    def send_requests(self, request_list):

       
        driver = webdriver.Chrome(options=self.webdriver_options)
        for payload, point, key, req in request_list:
            response = self.sender.send_request(req)
            if self.analyze_response(response, driver):
                print(f"[!] XSS Found! Request ID: {req.request_id} Point: {point} Parameter: {key} Payload: {payload}")
                if not settings.continue_on_success:
                    break
            
              
               
        
            
            #if self.analyze_response(response, driver):
            #    print("This is breaking time")
            #    break

    def analyze_response(self, response, driver):
        try:
            # Search html element with specified ID
            driver.get("data:text/html;charset=utf-8," + response.body)
            element = driver.find_element(By.ID, self.generator.unique_string)
            if element:
                #print("ELEMENT: ",element.get_attribute("outerHTML"))
                return True
            
            # Check body appended unique string
            body = driver.find_element(By.TAG_NAME, "body")
            if body.get_attribute(self.generator.unique_string) == "true":
                #print("Body: ",body)
                return True
            
            # Check the available log entries
            logs = driver.get_log("browser")  # Böngésző konzol logjainak lekérése
            for entry in logs:
                if self.generator.unique_string in entry["message"]:
                    #print("LOG: ", entry["message"])
                    return True
            
            return False    
        except Exception as e:
            return False



class XssTester3(ActiveModule):
    def __init__(self,request):
        super().__init__(request)
        self.name = "XSS Tester Module"
        self.generator = XssGen2()

        self.generator.waf_bypass = True
        self.generator.reverse_payload = True

        # Headless böngésző beállítása
        self.webdriver_options = Options()
        self.webdriver_options.add_argument("--headless")
        #self.webdriver_options.add_argument("--disable-gpu")  # GPU kikapcsolása
        self.webdriver_options.add_argument("--window-size=1920,1080")  # Ablak méretének beállítása
        self.webdriver_options.add_argument("--no-sandbox")  # Sandbox kikapcsolása bizonyos környezetekben

        self.driver = webdriver.Chrome(options=self.webdriver_options)
    
    def analyze_response(self, response, request, payload, point, param):
        
        issue_found = False
        """
        if "Content-Type" in response.headers:
            ct = response.headers["Content-Type"]
        else:
            ct = "text/html"
        """     

        try:
            # Search html element with specified ID
            self.driver.get(f"data:text/html;charset=utf-8," + response.body)
            element = self.driver.find_element(By.ID, self.unique_string)
            if element:
                settings.finding_library.add_finding(name="XSS",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
                issue_found = True
               
            
            # Check body appended unique string
            body = self.driver.find_element(By.TAG_NAME, "body")
            if body.get_attribute(self.unique_string) == "true":
                settings.finding_library.add_finding(name="XSS",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
                issue_found = True
               
            
            # Check the available log entries
            logs = self.driver.get_log("browser")  # Böngésző konzol logjainak lekérése
            for entry in logs:
                if self.unique_string in entry["message"]:
                    settings.finding_library.add_finding(name="XSS",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
                    issue_found = True
                    
            
               
        except Exception as e:
            print(e)
        

        if issue_found and not self.continue_on_success:
            self.stop_test()      