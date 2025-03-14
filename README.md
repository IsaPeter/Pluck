# Pluck

Pluck is a web application vulnerability scanner with custom payload generation function. It injects all the generated payloads into all the possible injection points and check the response of the server for multiple scenarios, depending on the generated payload type.

### Modules

```
+----------------+-----------------------------+
| Module Name    | Summary                     |
+----------------+-----------------------------+
| xss            | XSS Tester Module           |
| http_methods   | HTTP Method Tester          |
| html_injection | HTML Injection Tester       |
| command_inject | OS Command Injection Tester |
| ored           | Open Redirection Tester     |
| reflection     | Parameter Reflection Tester |
| php            | PHP Code Injection Tester   |
| ssi            | SSI Injection Tester        |
| sqli           | SQL Injection Tester        |
| traversal      | Directory Traversal Tester  |
| template       | Template Injection Tester   |
| crlf           | CRLF Injection Tester       |
| shellshock     | Shell Shock Tester          |
+----------------+-----------------------------+
```


### HTML Injection GET Request

**Obtain a request and save to a file**

```http
GET /htmli_get.php?firstname=test&lastname=test&form=submit HTTP/1.1
Host: 127.0.0.1:8888
sec-ch-ua: "Chromium";v="121", "Not A(Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://127.0.0.1:8888/htmli_get.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: security_level=0; PHPSESSID=ek9npeot2sop3ubofjaeul06l2
Connection: close

```

**Execute the script**

Set the module to `html_injection` and the parameters to `firstname` and `lastname`. The application found the correct payload and print out the unique ID.


```bash
python3 pluck.py -r /tmp/req -m "html_injection" -I "query" -P "firstname,lastname"
### Testing Parameters ###
URL:  http://127.0.0.1:8888/htmli_get.php?firstname=test&lastname=test&form=submit
PATH:  /htmli_get.php?firstname=test&lastname=test&form=submit
METHOD:  GET
Proxy: 127.0.0.1:8080
Parameters To Test:  ['firstname', 'lastname']
Modules to run:  ['html_injection']
Injection POints:  ['query']
[*] Executing the HTML Injection Tester module
Library Items:  1
[!] HTML Injection found in query firstname parameter with <div><img src='http://127.0.01/?r=q4OUnZcwKrcgAaBD&d= payload! Request ID: cde8bf77-b4d2-4509-8891-67b45770a8ab
```

**Found the request in burp**

Copy the request id and filter the HTTP history in burp to obtain the proper payload.




