---
description: HTTP header - CSP
---

# Content Security Policy

<figure><img src="../../.gitbook/assets/image (165).png" alt="" width="563"><figcaption><p>image credit: imperva.com (added link in references)</p></figcaption></figure>

**CSP** or **Content Security Policy** Header is a security protection that nullifies XSS attacks if correctly used. It is responsible for allowing browser to load content/execute scripts, etc only from the source present in the CSP header.

When we request webserver a webpage, It will send the http headers and the page content.\
E.g:

```html
heap@dragon:~/stuff$ curl -I https://www.google.com

HTTP/2 200 
content-type: text/html; charset=ISO-8859-1
content-security-policy-report-only: object-src 'none';base-uri 'self';script-src 'nonce-8HmRuxMakKIdxmmQOcUJ2w' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
accept-ch: Sec-CH-Prefers-Color-Scheme
p3p: CP="This is not a P3P policy! See g.co/p3phelp for more info."

<SNIP>
```

In the above request we see that google has sent many http headers, lets talk about CSP.\
If take example of `script-src 'nonce-8HmRuxMakKIdxmmQOcUJ2w'`from the header, it tells browser that executes javascript code `<script> code </script>`only when it has the nonce.

For e.g.

<pre class="language-javascript"><code class="lang-javascript"><strong>// 1
</strong><strong>&#x3C;script nonce=nonce-8HmRuxMakKIdxmmQOcUJ2w> &#x3C;script>alert('yay :)')&#x3C;/script>
</strong>
// 2
&#x3C;script> &#x3C;script>alert('nope :(')&#x3C;/script>
</code></pre>

From the above snippets, google will `alert yay`since the nonce is present in the script tag, but 2nd snippet won't be executed by the browser since the nonce value isn't present.

## References

{% embed url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP" %}

{% embed url="https://www.imperva.com/learn/application-security/content-security-policy-csp-header/" %}

For labs you can try Portswigger:&#x20;

{% embed url="https://portswigger.net/web-security/cross-site-scripting/content-security-policy" %}
