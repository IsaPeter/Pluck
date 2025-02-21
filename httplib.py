import json, base64
from urllib.parse import parse_qs, urljoin
import uuid
import requests


class HTTPRequest:
    def __init__(self, raw_request):
        self.raw_request = raw_request
        self.method = ''
        self.path = ''
        self.http_version = ''
        self.headers = {}
        self.body = ''
        self.parsed_body = None
        self.line_ending = self.detect_line_ending(raw_request)  # Automatikus sorvége felismerés
        
        
        
        self.parse_request()

    def reparse_body(self):
        # Body parszolása (a már meglévő logika alapján)
        content_type = self.headers.get('Content-Type', '')
        if 'application/json' in content_type:
            try:
                self.parsed_body = json.loads(self.body)
            except json.JSONDecodeError:
                self.parsed_body = self.body
        elif 'application/x-www-form-urlencoded' in content_type:
            raw_parsed = parse_qs(self.body)
            # Lista eltávolítása, ha csak egy elem van
            self.parsed_body = {k: v[0] if len(v) == 1 else v for k, v in raw_parsed.items()}
        elif 'multipart/form-data' in content_type:
            self.parse_multipart(content_type)
        else:
            self.parsed_body = self.body

    def parse_request(self):
        # A megfelelő sorvége karakter használata
        parts = self.raw_request.split(f'{self.line_ending}{self.line_ending}', 1)
        header_section = parts[0]
        self.body = parts[1] if len(parts) > 1 else ''
        
        # Feldolgozzuk a request line-t
        lines = header_section.split(self.line_ending)
        request_line = lines[0]
        self.method, self.path, self.http_version = request_line.split()
        
        # Header-ek feldolgozása
        for header in lines[1:]:
            if ': ' in header:
                key, value = header.split(': ', 1)
                self.headers[key] = value

        # Body parszolása (a már meglévő logika alapján)
        content_type = self.headers.get('Content-Type', '')
        if 'application/json' in content_type:
            try:
                self.parsed_body = json.loads(self.body)
            except json.JSONDecodeError:
                self.parsed_body = self.body
        elif 'application/x-www-form-urlencoded' in content_type:
            raw_parsed = parse_qs(self.body)
            # Lista eltávolítása, ha csak egy elem van
            self.parsed_body = {k: v[0] if len(v) == 1 else v for k, v in raw_parsed.items()}
        elif 'multipart/form-data' in content_type:
            self.parse_multipart(content_type)
        else:
            self.parsed_body = self.body

    def parse_multipart(self, content_type):
        boundary = content_type.split('boundary=')[1]
        delimiter = f'--{boundary}'
        parts = self.body.split(delimiter)
        parsed_data = {}

        for part in parts:
            if not part or part.strip() in ('', '--'):
                continue

            # Elválasztjuk a fejléceket és a tartalmat
            headers_part, _, body_part = part.lstrip().partition('\r\n\r\n')
            if not body_part:
                headers_part, _, body_part = part.lstrip().partition('\n\n')  # Alternatív separator, ha \r\n\r\n nincs

            headers_lines = headers_part.strip().splitlines()
            headers = {}

            for line in headers_lines:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key.strip()] = value.strip()

            content_disp = headers.get('Content-Disposition', '')
            content_type = headers.get('Content-Type', 'text/plain')  # Ha nincs, alapértelmezett érték

            # Kinyerjük a név és fájlnév információkat
            if 'name="' in content_disp:
                name = content_disp.split('name="')[1].split('"')[0]

                if 'filename="' in content_disp:
                    filename = content_disp.split('filename="')[1].split('"')[0]
                    parsed_data[name] = {
                        'filename': filename,
                        'content_type': content_type,
                        'content': body_part.rstrip(f'\r\n--').strip()
                    }
                else:
                    parsed_data[name] = body_part.strip()

        self.parsed_body = parsed_data

   
    def inject_payload(self, field, payload):
        # Payload beillesztése adott mezőbe
        if isinstance(self.parsed_body, dict):
            self.parsed_body[field] = payload
        elif isinstance(self.parsed_body, str):
            self.parsed_body += payload

    def rebuild_request(self):
        request_line = f"{self.method} {self.path} {self.http_version}\r\n"
        headers = ''.join(f"{k}: {v}\r\n" for k, v in self.headers.items())

        if isinstance(self.parsed_body, dict):
            content_type = self.headers.get('Content-Type', '')

            if 'application/json' in content_type:
                body = json.dumps(self.parsed_body)

            elif 'application/x-www-form-urlencoded' in content_type:
                body = '&'.join(f"{k}={v}" for k, v in self.parsed_body.items())

            elif 'multipart/form-data' in content_type:
                boundary = content_type.split('boundary=')[1]
                delimiter = f'--{boundary}'
                body_parts = []

                for name, value in self.parsed_body.items():
                    if isinstance(value, dict) and 'filename' in value:
                        # Dinamikus Content-Type visszaírás
                        file_part = (
                            f'{delimiter}\r\n'
                            f'Content-Disposition: form-data; name="{name}"; filename="{value["filename"]}"\r\n'
                            f'Content-Type: {value["content_type"]}\r\n\r\n'
                            f'{value["content"]}\r\n'
                        )
                        body_parts.append(file_part)
                    else:
                        text_part = (
                            f'{delimiter}\r\n'
                            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                            f'{value}\r\n'
                        )
                        body_parts.append(text_part)

                body_parts.append(f'{delimiter}--\r\n')
                body = ''.join(body_parts)

            else:
                body = self.body

        else:
            body = self.parsed_body

        return f"{request_line}{headers}\r\n{body}"

    def detect_line_ending(self, raw_request):
        if '\r\n' in raw_request:
            return '\r\n'
        elif '\n' in raw_request:
            return '\n'
        elif '\r' in raw_request:
            return '\r'
        else:
            raise ValueError("Ismeretlen sorvége karakter a requestben.")

    # Cookie-k feldolgozása dictionary-be
    def get_cookies(self):
        cookies = {}
        if 'Cookie' in self.headers:
            cookie_header = self.headers['Cookie']
            for cookie in cookie_header.split(';'):
                if '=' in cookie:
                    key, value = cookie.strip().split('=', 1)
                    cookies[key] = value
        return cookies
    # Cookie hozzáadása/módosítása
    def set_cookie(self, key, value):
        cookies = self.get_cookies()
        cookies[key] = value
        cookie_string = '; '.join([f"{k}={v}" for k, v in cookies.items()])
        self.headers['Cookie'] = cookie_string

    # Bearer token beállítása
    def set_bearer_token(self, token):
        self.headers['Authorization'] = f'Bearer {token}'

    # HTTP Basic Auth beállítása
    def set_basic_auth(self, username, password):
        auth_string = f'{username}:{password}'
        encoded_auth = base64.b64encode(auth_string.encode()).decode()
        self.headers['Authorization'] = f'Basic {encoded_auth}'

    # Tetszőleges header hozzáadása/módosítása
    def set_custom_header(self, key, value):
        self.headers[key] = value

    def get_request_url(self, default_scheme='http'):
        
        host = self.headers.get('Host', 'localhost')
        scheme = 'https' if self.headers.get('X-Forwarded-Proto', default_scheme) == 'https' else default_scheme
        base_url = f"{scheme}://{host}/"

        return urljoin(base_url, self.path)


class HTTPResponse:
    def __init__(self, response=None, raw_response=None):
        self.status_code = None
        self.http_version = "HTTP/1.0" # This is the default
        self.status_string = ""
        self.headers = {}
        self.body = ''
        self.elapsed_time = None
        self.response_id = ""
        self.is_redirect = False

        if raw_response is not None:
            self.parse_raw_response(raw_response)
        if response is not None:
            self.parse_requests_response(response)

    def parse_raw_response(self, raw_response):
        line_ending = self.detect_line_ending(raw_response)
        response_parts = raw_response.split(line_ending, 1)
        header_lines = response_parts[0].splitlines()

        status_line = header_lines[0]
        self.http_version, self.status_code, *status_string = status_line.split(' '); self.status_string = ' '.join(status_string)

        

        for line in header_lines[1:]:
            if ': ' in line:
                key, value = line.split(': ', 1)
                self.headers[key.strip()] = value.strip()

        self.body = response_parts[1] if len(response_parts) > 1 else ''

    def parse_requests_response(self, response):
        self.status_code = response.status_code
        self.headers = dict(response.headers)
        self.body = response.text
        self.elapsed_time = response.elapsed.total_seconds()

    def get_header(self, key):
        return self.headers.get(key, None)
    
    def get_headers(self):
        return self.headers
    
    def get_cookies(self):
            return self.headers.get("Set-Cookie",{})

    def __str__(self):
        return f"Status Code: {self.status_code}\nHeaders: {json.dumps(self.headers, indent=4)}\nBody: {self.body[:200]}...\nElapsed Time: {self.elapsed_time} seconds"

    def rebuild_response(self):
        status_line = f"{self.http_version} {self.status_code} {self.status_string}\r\n"
        headers = ''.join([f'{k}: {v}\r\n' for k, v in self.headers.items()])
        return f"{status_line}{headers}\r\n{self.body}"
    
    def detect_line_ending(self, raw_request):
        if '\r\n\r\n' in raw_request:
            return '\r\n\r\n'
        elif '\n\n' in raw_request:
            return '\n\n'
        if '\r\n' in raw_request:
            return '\r\n'
        elif '\n' in raw_request:
            return '\n'
        elif '\r' in raw_request:
            return '\r'
        else:
            raise ValueError("Ismeretlen sorvége karakter a requestben.")


class HTTPRequestSender:
    def __init__(self, request_timeout=20, proxies=None):
        
        self.request_timeout = request_timeout
        self.proxies = proxies  # Proxy beállítások
        self.address = None # IP or Domain Name
        self.port_number = None # trivial
        self.protocol = "https" # http/https
        self.verify = True
        self.allow_redirects = False


    def send_request(self, request_obj, timeout=None):
        
        if self.address:
            base_url = f"{self.protocol}://{self.address}"
            if self.port_number:
                base_url += ":"+str(self.port_number)
            base_url += "/"
            url = urljoin(base_url,request_obj.path)
        else:
            url = request_obj.get_request_url()
        
        headers = request_obj.headers
        data = None


        request_obj.request_id = str(uuid.uuid4())
        request_obj.set_custom_header("Request-ID",request_obj.request_id)


        # Body kezelése a Content-Type alapján
        if request_obj.method in ['POST', 'PUT', 'PATCH']:
            content_type = headers.get('Content-Type', '')
            
            if 'application/json' in content_type:
                data = json.dumps(request_obj.parsed_body)
            elif 'application/x-www-form-urlencoded' in content_type:
                data = '&'.join(f"{k}={v}" for k, v in request_obj.parsed_body.items())
            elif 'multipart/form-data' in content_type:
                files = {}
                for key, value in request_obj.parsed_body.items():
                    if isinstance(value, dict) and 'filename' in value:
                        files[key] = (value['filename'], value['content'], value['content_type'])
                    else:
                        if data is None:
                            data = {}
                        data[key] = value
                if len(data) >0:
                    request_obj.headers['Content-Length'] = str(len(data.encode('utf-8')))
                else:
                    request_obj.headers['Content-Length'] = "0"
                response = requests.request(
                    method=request_obj.method,
                    url=url,
                    headers=headers,
                    data=data,
                    files=files,
                    timeout=timeout or self.request_timeout,
                    proxies=self.proxies,  # Proxy alkalmazása
                    verify=self.verify,
                    allow_redirects=self.allow_redirects
                )

                result_response = HTTPResponse(response=response) 
                result_response.response_id = request_obj.request_id
                return result_response
            else:
                data = request_obj.body

        if data and len(data) >0:
            request_obj.headers['Content-Length'] = str(len(data.encode('utf-8')))
        else:
            request_obj.headers['Content-Length'] = "0"
        # Egyedi kérés küldése (session nélkül)
        response = requests.request(
            method=request_obj.method,
            url=url,
            headers=headers,
            data=data,
            timeout=timeout or self.request_timeout,
            proxies=self.proxies,  # Proxy alkalmazása
            verify=self.verify,
            allow_redirects=self.allow_redirects
        )

        result_response = HTTPResponse(response=response)
        result_response.response_id = request_obj.request_id
        return result_response
