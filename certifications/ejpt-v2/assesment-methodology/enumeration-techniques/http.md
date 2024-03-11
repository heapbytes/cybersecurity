---
description: Hypertext transfer protocol (port 80)
---

# HTTP

* cmds to enum info

```bash
whatweb $IP

http $IP

dirb http://$IP/

browsh --startup-url $URL #outputs on terminal all that you'll see on browser
```



## nmap&#x20;

```bash
nmap -sC -sV $IP -p80 --script http-enum
```

* for http headers

```bash
nmap -sC -sV $IP -p80 --script http-headers
```

* http methods enum

```bash
nmap -sC -sV $IP -p80 --script http-methods \
--script-args http-methods.url-path=/directory/
```

* http webdav scan

```bash
nmap -sC -sV $IP -p80 --script http-webdav-scan \
--script-args http-methods.url-path=/directory/
```

\----------- everything that the course provide for http (nmap) can be done with -sC scan ^^



## dir bruteforcing

* for directory bruteforcing using we can use gobuster or ffuf or any other tool

### ffuf&#x20;

```bash
ffuf -w /path/to/wordlists/ -u http://$IP/FUZZ -ac #ac just to filter out repeated stuff 
```

### gobuster

```bash
gobuster dir -w /path/to/wordlists/ -u http://$IP/FUZZ -ac
```

## check robots.txt

```bash
curl http://$IP/robots.txt 
```
