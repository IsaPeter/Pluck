# Pluck

Pluck is a web application vulnerability scanner with custom payload generation function. It injects all the generated payloads into all the possible injection points and check the response of the server for multiple scenarios, depending on the generated payload type.

### Help

```bash
usage: pluck.py [-h] [-r] [-x] [-b] [-s] [-p] [-k] [--list-modules] [-li] [--test] [-I] [--payload-timeout] [-m] [-P] [--oast] [--exclude-parameter] [--continue-on-success]

Pluck Web Application Vulnerability Tester

options:
  -h, --help            show this help message and exit

Pluck Request Handling:
  -r , --request        Set the initial request
  -x , --proxy          Set the Proxy
  -b , --base-address   Set the base address for URL creation
  -s , --protocol       Set the protocol http/https
  -p , --port           Set the web application port number
  -k, --ignore-cert     Ignore the SSL Warnings

Pluck General Options:
  --list-modules        List the available modules
  -li, --list-injection-points
                        List the available injection points
  --test

Pluck Execution Options:
  -I , --injection-points 
                        Set injection points ',' coma separated
  --payload-timeout     Set the payload timeout.
  -m , --modules        Set the using modules
  -P , --parameters     Set the testing parameters
  --oast                Set Collaborator address for OAST
  --exclude-parameter   Exclude parameter from testing
  --continue-on-success
                        Continue Testing if found a vulnerability
```

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

### Example Injection Point Identification

This is the example HTTP request which I parsed and below the found injection points by the PayloadInjector module in JSON format.

```http
POST /commandi_blind.php HTTP/1.1
Host: 127.0.0.1:8888
Content-Length: 28
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="121", "Not A(Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
Origin: http://127.0.0.1:8888
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://127.0.0.1:8888/commandi_blind.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: security_level=0; PHPSESSID=9dcv4k8ope03vgcrbub4p9f012
Connection: close

target=127.0.0.1&form=submit
```

Injection points:

```js
{
     "path": [
          "/commandi_blind.php",
          "commandi_blind.php"
     ],
     "query": [],
     "body": [
          "target",
          "form"
     ],
     "headers": [
          "Host",
          "Content-Length",
          "Cache-Control",
          "sec-ch-ua",
          "sec-ch-ua-mobile",
          "sec-ch-ua-platform",
          "Upgrade-Insecure-Requests",
          "Origin",
          "Content-Type",
          "User-Agent",
          "Accept",
          "Sec-Fetch-Site",
          "Sec-Fetch-Mode",
          "Sec-Fetch-User",
          "Sec-Fetch-Dest",
          "Referer",
          "Accept-Encoding",
          "Accept-Language",
          "Cookie",
          "Connection"
     ],
     "cookies": [
          "security_level",
          "PHPSESSID"
     ]
}
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




