---
description: will organise as time passes.......
---

# 🖥️ Active Directory

* to change password of any user

```bash
Set-ADAccountPassword <username> -Reset \
-NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose
```

* to force reset password on next login

```bash
Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose
```
