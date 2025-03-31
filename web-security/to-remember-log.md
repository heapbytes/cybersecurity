---
description: Writing few intresting things I liked. Maybe too basic sometimes :)
---

# To remember LoG

## 1. LFI vs File disclosure.

So, you can report the vuln as LFI if it executes the file else it's file disclosure.\
&#x20;\
For e.g. if the page looks like: `<?php phpinfo(); ?` and once you called the page (page?param=file.php), \
If the output is `<?php phpinfo(); ?>`  then it's a file disclosure vuln. \
\
Whereas if u get details of php that's running on server (i.e phpinfo() is executed) then you can report it as LFI.

## 2. innerText vs innerHTML

#### Considering input as : \<script>alert(1)\</script>

```javascript
//1. innerText
<script>
    const script = document.createElement('script');
    script.innerText = debug;
    document.body.appendChild(script);
</script>

/*
In innerText, the input or data is not parsed, 
i.e if we enter <script>alert(1)</script> 
the output will be :
<script>
    <script>alert(1)</script>
</script>
*/
```

```javascript
//2. innerHTML
<script>
    const script = document.createElement('script');
    script.innerHTML = debug;
    document.body.appendChild(script);
</script>

/*
In innerHTML, the input or data is parsed, 
i.e if we enter <script>alert(1)</script> 
the output will be :
<script>
    alert(1)
</script>
*/
```



