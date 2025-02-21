from pluck.core import BaseModule, PayloadInjector, Finding
from pluck.generators.xss_generator import XSSPayloadGenerator
import pluck.settings as settings
from httplib import HTTPRequest, HTTPResponse,  HTTPRequestSender
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import issuelib as issuelib
from threading import Thread
from queue import Queue


class XssTester(BaseModule):
    def __init__(self, request):
        # initialize the Base module
        super().__init__(request)
        self.name = "XSSTester"
        self.default_injection_points = ["query","body"]
        self.xss_popup_timeout = 1
        self.sender = None


        self.driver = None
        # Headless böngésző beállítása
        self.webdriver_options = Options()
        self.webdriver_options.add_argument("--headless")
        self.webdriver_options.add_argument("--disable-gpu")
        self.webdriver_options.add_argument("--no-sandbox")
        self.webdriver_options.add_argument("--window-size=1920,1080")  # Ablak méretének beállítása
        
        # Automatikus ellenőrzések kikapcsolása
        #self.webdriver_options.add_experimental_option("useAutomationExtension", False)
        #self.webdriver_options.add_experimental_option("excludeSwitches", ["enable-automation"])

    # Generate payloads for the execution
    def generate_payloads(self):
        generator = XSSPayloadGenerator()
        return generator.generate_payloads()

    def run(self):
        """Payload injektálása és küldése."""

    


        if not self.sender:
            return False

        print(f"[*] Executing the {self.name} module")
        payloads = self.generate_payloads()

        keep_testing = True
        if settings.xss_popup_timeout: self.xss_popup_timeout = settings.xss_popup_timeout 

        print(f"[+] Generated {str(len(payloads))} payloads.")

        new_request = HTTPRequest(self.original_request.rebuild_request())
        injector = PayloadInjector(new_request)
        
        # determine injection points
        injection_points = injector.find_injection_points()
        
        #import json
        #print(json.dumps(injection_points, indent=5))
        # Check the defined injection points in the settings
        if len(settings.injection_points) > 0:
            self.default_injection_points = settings.injection_points 
        if "all" in self.default_injection_points:
            self.default_injection_points = ["path", "query", "body", "headers", "cookies"]

        for point in injection_points:
            if len(point) and point in self.default_injection_points:
                if keep_testing:
                    for k in injection_points[point]:
                        if keep_testing:
                            for p in payloads:
                                if keep_testing:
                                    #print("Point: ", point, "Key: ", k, "Payload: ", p)
                                    injector.inject_payload(point,k ,p )
                                    #if point == "body":
                                    #    new_request.reparse_body()
                                    
                                    #print(new_request.rebuild_request())
                                    #input(">> ENTER to SEND")

                                    response = self.sender.send_request(new_request)
                                   
                                    print("Miafasz")
                                    if self.analyze_response(response):
                                        f = Finding()
                                        f.name = "Refelcted XSS Vulnerability"
                                        f.payload = p
                                        f.injection_point = point
                                        f.parameter = k
                                        f.finding_type = "xss"
                                        f.module_name = self.name
                                        f.request = new_request
                                        f.response = response
                                        f.request_id = f.request.request_id
                                        issuelib.findings.append(f)
                                        keep_testing = False




    def analyze_response(self, response):
        print("Anyád")
        #self.driver = webdriver.Chrome(options=options)        
        driver = webdriver.Firefox(options=self.webdriver_options) 
        driver.get("data:text/html;charset=utf-8," + response.body)

        try:
            WebDriverWait(driver, 5).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert_text = alert.text
            print(f"Alert detektálva! Üzenet: {alert_text}")
            driver.save_screenshot("/tmp/screenshot.png")
            input()
            return True
        except:
            print("Anyád")
            return False
    