---
description: cheatsheet
---

# 🎑 Overview (fundamentals/cheatsheet)

## Port scanning

* rustscan

```bash
rustscan -a $IP --ulimit 5000 -- -sC -sV | tee ports.scan
```



## Directory bruteforcing

* ffuf

```bash
ffuf -u http://$IP/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt 
```

* gobuster&#x20;

```bash
 gobuster dir -u http://$1/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt 
```



## Subdomain bruteforcing

* ffuf (vhost)

```bash
ffuf -u http://$subdomain/ -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.${subdomain}" 
```





