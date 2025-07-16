---
description: File upload bypass - Magic bytes
---

# Secure Upload

##

## me page

<figure><img src="../../../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

As the challenge is written all over, it's a file upload bypass with changing magic bytes of the file.

The challenge was simple, yet a bit guessy, \
Instead of bypassing all the png checks and validation, we can upload a simple PNG and append PHP code within it.

<figure><img src="../../../../.gitbook/assets/image (5).png" alt=""><figcaption><p>PAYATU{png_php_pwnd}</p></figcaption></figure>

\_\_\_\_\_\_\_\_\_\_heapbytes still pwning



## Resources

{% embed url="https://en.wikipedia.org/wiki/List_of_file_signatures" %}

{% embed url="https://medium.com/@wakedxy/bypassing-file-upload-restriction-using-magic-bytes-ae59fb5bb383" %}

{% embed url="https://sagarsajeev.medium.com/file-upload-bypass-to-rce-76991b47ad8f" %}
