---
description: Writing few intresting things I learned. Maybe too basic sometimes :)
---

# Did you know?

## 1. LFI vs File disclosure.

So, you can report the vuln as LFI if it executes the file else it's file disclosure.\
&#x20;\
For e.g. if the page looks like: `<?php phpinfo(); ?` and once you called the page (page?param=file.php), \
If the output is `<?php phpinfo(); ?>`  then it's a file disclosure vuln. \
\
Whereas if u get details of php that's running on server (i.e phpinfo() is executed) then you can report it as LFI.
