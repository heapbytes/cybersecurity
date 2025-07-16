# Infrastructure

## ctfuser&#x20;

password was given

## smbuser

There was note.txt in /home/ftpuser

```
Congratulations on accessing the FTP server!

Here are some important notes:

1. The next step involves network file sharing
2. Credentials are encoded for security: NDIwMm96Zl9xZWJqZmZuYzplcmZob3pm
3. Remember to try different decoding methods if the first does not work
4. The share name is backup_share

Hint: The encoding uses multiple transformations "reverse" is the key
```

base64 -> reverse -> rot13 gives the password

Password ⇒ `smbuser:password_smb2024`

