---
description: File Transfer protocol (port 21)
---

# FTP

## Resources that might help

* What is FTP?

{% embed url="https://www.techtarget.com/searchnetworking/definition/File-Transfer-Protocol-FTP" %}

* some vuln desc and exploits/payloads

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp" %}

## FTP Help menu

```bash
ftp> help
Commands may be abbreviated.  Commands are:

!               dir             mdelete         qc              site
$               disconnect      mdir            sendport        size
account         exit            mget            put             status
append          form            mkdir           pwd             struct
ascii           get             mls             quit            system
bell            glob            mode            quote           sunique
binary          hash            modtime         recv            tenex
bye             help            mput            reget           tick
case            idle            newer           rstatus         trace
cd              image           nmap            rhelp           type
cdup            ipany           nlist           rename          user
chmod           ipv4            ntrans          reset           umask
close           ipv6            open            restart         verbose
cr              lcd             prompt          rmdir           ?
delete          ls              passive         runique
debug           macdef          proxy           send
```

## Bruteforce with hydra

* Multiple users&#x20;

```bash
hydra -L /path/to/username/wordlist.txt -P /path/to/password/wordlist.txt $IP ftp

#for ejpt exams the wordlist generally is in /usr
#easy cp paste : 
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt \
-P /usr/share/metasploit-framework/data/wordlists/common_users.txt $IP ftp
```



## nmap

* Bruteforce&#x20;

```bash
nmap --script ftp-brute --script-args userdb=/path/to/user_list.txt $IP -p21

#e.g. of userdb : 
# echo 'test' > ~/ejpt/users
# userdb=~/ejpt/users
```

* check if anonymous login is allowed

```bash
nmap -p21 $IP --script ftp-anon
# -sC does this for us already
```
