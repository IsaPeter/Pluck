from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from queue import Queue
from threading import Thread

class XssDetector():
    def __init__(self):
        self.thread_num = 5

        # Headless böngésző beállítása
        self.webdriver_options = Options()
        self.webdriver_options.add_argument("--headless")
        #self.webdriver_options.add_argument("--disable-gpu")  # GPU kikapcsolása
        self.webdriver_options.add_argument("--window-size=1920,1080")  # Ablak méretének beállítása
        self.webdriver_options.add_argument("--no-sandbox")  # Sandbox kikapcsolása bizonyos környezetekben

        self.request_queue = Queue()

        self.threads = []

    def analyse_requests(self, request_list):
        for req in request_list:
            self.request_queue.put(req)

        for _ in range(self.thread_num):
            t = Thread(target=self.analyze_worker)
            t.start()
            self.threads.append(t)

        # Várakozás az összes feladat befejezésére vagy találatra
        #self.request_queue.join()
        print("vége")
        #self.request_queue = Queue()
        for t in self.threads:
            t.join()
        #self.threads = []
        return None


    def analyze_worker(self):
        driver = webdriver.Edge(options=self.webdriver_options)

        while not self.request_queue.empty() and self.request_queue.qsize() > 0:
            try:
                resp = self.request_queue.get()
                driver.get("data:text/html;charset=utf-8," + resp.body)
                WebDriverWait(driver, 5).until(EC.alert_is_present())
                #fname = resp.response_id+".png"
                #driver.save_screenshot("/tmp/"+fname)
                alert = driver.switch_to.alert
                alert_text = alert.text
                print(f"Alert detektálva! Üzenet: {alert_text}", resp.response_id)
            except:
                pass
        print("worker end")
        #driver.quit()