import base64
from urllib.parse import parse_qs, urlencode
from datetime import datetime


class PayloadInjector:
    def __init__(self, http_request):
        self.http_request = http_request

    # Injekciós pontok keresése
    def find_injection_points(self):
        points = {'path': [], 'query': [], 'body': [], 'headers': [], 'cookies': []}

        # Path paraméterek
        if '?' in self.http_request.path:
            path, query_string = self.http_request.path.split('?', 1)
            points['path'].append(path)
            if '/' in path: points['path'].extend(list(set([p.strip() for p in path.split('/') if p != ''])))
            points['query'] = list(parse_qs(query_string).keys())
        else:
            points['path'].append(self.http_request.path)
            if '/' in self.http_request.path: points['path'].extend(list(set([p.strip() for p in self.http_request.path.split('/') if p != ''])))

        # Body paraméterek
        content_type = self.http_request.headers.get('Content-Type', '')
        if 'application/x-www-form-urlencoded' in content_type:
            points['body'] = list(parse_qs(self.http_request.body).keys())
        elif 'application/json' in content_type:
            import json
            try:
                body_json = json.loads(self.http_request.body)
                points['body'] = list(body_json.keys())
            except json.JSONDecodeError:
                pass
        elif 'multipart/form-data' in content_type:
            boundary = content_type.split("boundary=")[-1]
            parts = self.http_request.body.split(f'--{boundary}')
            for part in parts:
                if 'Content-Disposition' in part:
                    lines = part.strip().split('\r\n')
                    disposition_line = next((line for line in lines if 'Content-Disposition' in line), '')
                    if 'name="' in disposition_line:
                        name_part = disposition_line.split('name="')[1].split('"')[0]
                        points['body'].append(name_part)
                    if 'filename="' in disposition_line:
                        filename_part = disposition_line.split('filename="')[1].split('"')[0]
                        points['body'].append(f'filename')
    

        # Header és Cookie paraméterek
        points['headers'] = list(self.http_request.headers.keys())
        points['cookies'] = list(self.http_request.get_cookies().keys())

        return points

    # Payload injektálás
    def inject_payload(self, target, key, payload, append=False):
        if target == 'query':
            path, query_string = self.http_request.path.split('?', 1)
            query_params = parse_qs(query_string)
            if key in query_params:
                if append:
                    value = query_params[key][0] 
                    query_params[key] = [value+payload]
                    #print(query_params[key])
                else:
                    query_params[key] = [payload]
                self.http_request.path = f"{path}?{urlencode(query_params, doseq=True)}"

        elif target == 'body':
            content_type = self.http_request.headers.get('Content-Type', '')
            if 'application/x-www-form-urlencoded' in content_type:
                body_params = parse_qs(self.http_request.body)
                if key in body_params:
                    if append:
                        value = body_params[key][0]
                        body_params[key] = [key+payload]
                    else:
                        body_params[key] = [payload]
                    self.http_request.body = urlencode(body_params, doseq=True)
            elif 'application/json' in content_type:
                import json
                body_json = json.loads(self.http_request.body)
                if key in body_json:
                    if append:
                        value = body_json[key][0] 
                        body_json[key] = value+payload
                    else:
                        body_json[key] = payload
                    self.http_request.body = json.dumps(body_json)
            elif 'multipart/form-data' in content_type:
                boundary = content_type.split("boundary=")[-1]
                parts = self.http_request.body.split(f'--{boundary}')
                new_parts = []
                
                for part in parts:
                    if f'name="{key}"' in part:
                        if '\r\n' in part:
                            headers_body_split = part.split('\r\n\r\n', 1)
                            linesep = '\r\n'
                        else:
                            headers_body_split = part.split('\n\n', 1)
                            linesep = '\n'
                        
                        if len(headers_body_split) == 2:
                            headers, body = headers_body_split
                            if append:
                                body = body + payload
                            else:
                                body = payload
                            new_part = f"{headers}{linesep}{linesep}{body}{linesep}"
                            new_parts.append(new_part)
                        else:
                            new_parts.append(part)
                
                    elif key == "filename" and "filename" in part:
                        if "\r\n" in part:
                            lines = part.strip().split('\r\n')
                        else:
                            lines = part.strip().split('\n')

                        new_lines = []
                        for line in lines:
                            if 'filename="' in line:
                                # kivágom a filename változót és kinyerem belőle magát az értéket és azt helyettesítem bele a replaceba. 
                                # Benne hagyom a " és ' karaktereket hogy ezzel se legyen baj, eltérés és meg tudom tartani az eredeti struktúrát.
                                fname = [v for v in line.split(";") if "filename" in v]
                                if len(fname) > 0: fname = fname[0].split('=')[1]

                                if append:
                                    new_line = line.replace(f'filename={fname}', f'filename="{fname}{payload}"')
                                else:
                                    new_line = line.replace(f'filename={fname}', f'filename="{payload}"')
                                new_lines.append(new_line)
                                
                            else:
                                new_lines.append(line)
                        new_parts.append('\r\n'.join(new_lines) + '\r\n')
                    else:
                        new_parts.append(part)

                self.http_request.body = f'--{boundary}'.join(new_parts)

        elif target == 'headers':
            if key in self.http_request.headers:
                if append:
                    value = self.http_request.headers[key][0]
                    self.http_request.headers[key] = value + payload
                else:
                    self.http_request.headers[key] = payload

        elif target == 'cookies':
            if append:
                value = self.http_request.cookies[key][0]
                self.http_request.set_cookie(key, value + payload) 
            else:
                self.http_request.set_cookie(key, payload)

        elif target == 'path':
            if key in self.http_request.path:
                if append:
                    self.http_request.path = self.http_request.path.replace(key, key+payload)
                else:
                    self.http_request.path = self.http_request.path.replace(key, payload)

        # reparsing the body to apply the changes in the request body
        self.http_request.reparse_body()

    # HTTP metódus módosítása
    def set_method(self, method):
        self.http_request.method = method

    def get_injection_parameters(self, point):
        injection_points = self.find_injection_points()
        if point in injection_points:
            return injection_points[point]
        return []
    
    
    # return injection points which has available parameters
    def get_available_injection_points(self):
        available_injection_points = [k for k, v in self.find_injection_points().items() if len(v) > 0]
        return available_injection_points

class BaseModule:
    def __init__(self, request):
        self.original_request = request
        self.payloads = []
    
    def generate_payloads(self):
        """Egyedi payloadok generálása az adott teszthez."""
        raise NotImplementedError("Implementáld a payload generálást az alosztályban.")

    def run(self, injector, sender):
        """Payload injektálása és küldése."""
        raise NotImplementedError("Implementáld a futtatást")

    def analyze_response(self, response):
        """Válasz elemzése sérülékenység szempontjából."""
        raise NotImplementedError("Implementáld az elemzést az alosztályban.")
    


class FindingLibrary():
    def __init__(self):
        self.findings = []

    def add_finding(self, name="", payload="", point="", param="", module="", request=None, response=None):
        nf = Finding()
        nf.name = name
        nf.payload = payload
        nf.injection_point = point
        nf.parameter = param
        nf.module_name = module
        nf.request = request
        nf.response = response
        nf.request_id = request.request_id
        self.findings.append(nf)





class Finding():
    def __init__(self):
        self.name = ""
        self.payload = ""
        self.injection_point = ""
        self.parameter = ""
        self.finding_type = ""
        self.module_name = ""
        self.timestamp = datetime.now()
        self.request = None
        self.response = None
        self.request_id = None
