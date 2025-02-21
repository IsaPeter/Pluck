import pluck.settings as settings
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from pluck.module import ActiveModule
from pluck.generators.xgen import  XssGen

class XssTester(ActiveModule):
    def __init__(self,request):
        super().__init__(request)
        self.name = "XSS Tester Module"
        self.generator = XssGen()

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