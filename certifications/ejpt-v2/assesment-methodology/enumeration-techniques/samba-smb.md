# Samba (SMB)

* smb -> server message block
* net use \* /delete -> deletes all the folders and files in SMB
* net use z: \\\\\<IP>\dir$ \<password> \<username> -> will create a samba share

## nmap scans



* To scan udp ports&#x20;

```bash
nmap -sU $IP 
# for the sake of speed, you can also scan top ports
# e.g. (scanning top 100)
# -> nmap -sU --top-ports 100 $IP
```

* session enumeration&#x20;

```bash
nmap $IP -p445 --script smb-enum-sessions \
--script-args smbusername=$username,smbpassword=$password
```

* share enumerations

```bash
nmap $IP -p445 --script smb-enum-shares \
--script-args smbusername=$username,smbpassword=$password
```

* enumerate users -> to find how many users exists

```bash
nmap $IP -p445 --script smb-enum-users \
--script-args smbusername=$username,smbpassword=$password
```

* enumerate server staticstics -> prints out how many logged in, failed attempt count, etc.

```bash
nmap $IP -p445 --script smb-enum-stats \
--script-args smbusername=$username,smbpassword=$password
```

* enumerate domain (scan) -> find out how many domains are there

```bash
nmap $IP -p445 --script smb-enum-domains \
--script-args smbusername=$username,smbpassword=$password
```

* enumerate groups -> shows all users belongs to what groups

```bash
nmap $IP -p445 --script smb-enum-groups \
--script-args smbusername=$username,smbpassword=$password
```

* enumerate services -> to see what services are running

```bash
nmap $IP -p445 --script smb-enum-services \
--script-args smbusername=$username,smbpassword=$password
```

```bash
nmap $IP -p445 --script smb-enum-services,smb-ls \
--script-args smbusername=$username,smbpassword=$password

# above command just with `smb-ls` which will list all the files
# smb-ls -> linux machine
# smb-dir -> windows machine
```

* smb protocols or Dialects
* What is dialect?
  * `The SMB protocol has gone through various versions, and each version is referred to as a "dialect."`

```bash
nmap $IP -p445 --script smb-protocols
```

* smb security level information

```bash
nmap $IP -p445 --script smb-security-mode
```

* To find exact os & version smb is using

```bash
nmap --script smb-os-discovery.nse -p445 $IP #note the port (-p) can be changed
```



## smb map

* to list , see what permission we have

```bash
smbmap -u guest -p "" -d . -H $IP
```

```bash
smbmap -u $username -p $password -d . -H $IP
```

* To run commands on the target machine (-x flag)

```bash
smbmap -u $username -p $password -H $IP -x $command
```

* To list shares

```bash
smbmap -u $username -p $password -H $IP -L
```

* to see contents of the shares

```bash
smbmap -u $username -p $password -H $IP -r <dir> #e.g. C$ 
```

* to upload to the smb share

```bash
smbmap -u $username -p $password --upload '/local/machine/file' '$C/remote/machine'
# if windows : C$\file\path
```

* to download the smb share

```bash
smbpmap -u $username -p $password --download '$C\path\file'
```

* Login

```bash
smbmap -H $IP -u $username -p $password 
```

## msfconsole

* msfconsole module to scan samba version

```bash
msfconsole
use auxiliary/scanner/smb/smb_version 

#run : 'show options' & fill up needed fields.
```

* to enum shares

```bash
use auxiliary/scanner/smb/smb_enumshares
```

* To bruteforce password

```bash
use auxiliary/scanner/smb/smb_login 
#options : 
set RHOSTS $IP
set pass_file /path/to/wordlists
set smbuser $username

#execute show options and see if all options with required 'yes' are filled.
```

* to scan pipes&#x20;

```bash
use auxiliary/scanner/smb/pipe_auditor

#options
set RHOSTS $IP
set smbuser $username
set smbpass $password
```

##

## nmblookup - a tool for recon smb

* To scan an IP

```bash
nmblookup -A $IP
```



## smbclient

* To list by host

```bash
smbclient -L $IP
```

* To try connecting samba share without password

```bash
smbclient -L $IP -N
```



## rpcclient

* To connect to the smb share (username and password is NULL here)

```bash
rpcclient -U "" -N $IP
```

* To get username after login

```bash
rpcclient$> getusername
```

* to get server info&#x20;

```bash
rpcclient$> srvinfo
```

* to get usernames&#x20;

```bash
rpcclient$> enumdomusers
```

* to get groups

```
rpcclient$> enumdomgroups
```

* to get SID of a user

```bash
rpcclient$> lookupnames <username>
```

## enum4linux&#x20;

* to scan os&#x20;

```bash
enum4linux -o $IP
```

* to scan shares

```bash
enum4linux -S $IP
```

* to list connected printers

```bash
enum4linux -i $IP
```

* RID cycling using enum4Linux

```bash
enum4linux -r -u admin $IP
```

## hydra

* to bruteforce password

```bash
hydra -l $username -P /path/to/wordlist $IP smb
```





\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_done with smb cheatsheet.
