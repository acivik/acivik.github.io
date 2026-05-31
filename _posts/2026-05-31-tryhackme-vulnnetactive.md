---

title: THM - VulnNet:Active
author: Acivik
date: 2026-05-31 08:00:00 +0300 
categories: [CTF, TryHackMe]
tags: [tryhackme, ad, active directory, writeup, ctf, walkthrough, windows]

---

# <span style="color:#AA0E1C"><b># Summary</b></span>
Bu yazıda TryHackMe platformundaki VulnNet: Active makinesinin çözümünü ele alacağız.
Makine, Active Directory ortamında gerçekçi bir saldırı zinciri sunuyor. Başlangıçta şifresiz erişime açık bir Redis servisi üzerinden hem kullanıcı adını hem de NTLM hash'ini elde ediyoruz. Yakalanan hash'i `hashcat` ile kırarak geçerli bir credential elde ettikten sonra SMB üzerinden sistemi daha ayrıntılı inceliyoruz. Yazma yetkimizin bulunduğu bir PowerShell scripti aracılığıyla reverse shell alıyoruz. Yetki yükseltme aşamasında ise iki farklı yol izliyoruz: `SeImpersonatePrivilege` üzerinden `GodPotato` ile SYSTEM token'ı ele geçirme ve BloodHound analizi sonucunda tespit ettiğimiz `GPO` üzerindeki `GenericWrite` yetkisini `SharpGPOAbuse` ile kötüye kullanarak domain administrator yetkisi elde etme olaylarını göreceğiz.

---
# <span style="color:#AA0E1C"><b># Enumeration</b></span>

## <span style="color:#0096FF">Nmap</span>

![https://i.ibb.co/vxcJy9hg/Ekran-g-r-nt-s-2026-05-30-180756.png](https://i.ibb.co/vxcJy9hg/Ekran-g-r-nt-s-2026-05-30-180756.png)

`Nmap` TCP taramasına göre belli başlı portların açık olduğunu görebiliyoruz. Ek olarak UDP taraması gerçekleştireceğim.

![https://i.ibb.co/Vc2PcmZq/Ekran-g-r-nt-s-2026-05-30-180948.png](https://i.ibb.co/Vc2PcmZq/Ekran-g-r-nt-s-2026-05-30-180948.png)

Burada da bazı portları filtred olarak gösteriyor `netcat` kullanarak açık olup olmadıklarını doğrulamak istiyorum.

![https://i.ibb.co/8LD0RnG0/Ekran-g-r-nt-s-2026-05-30-181059.png](https://i.ibb.co/8LD0RnG0/Ekran-g-r-nt-s-2026-05-30-181059.png)

Şu ana kadar elimizde enumerate etmek için `dns,smb,rpc,redis,ldap` gibi servisler bulunuyor.
Sırasıyla dikkatli bir şekilde saldırı yüzeyini geliştirmek için bilgi toplamaya çalışacağım.
## <span style="color:#0096FF">SMB</span>

![https://i.ibb.co/bjSRHy9c/Ekran-g-r-nt-s-2026-05-30-182824.png](https://i.ibb.co/bjSRHy9c/Ekran-g-r-nt-s-2026-05-30-182824.png)

`nxc` toolu ile smb üzerindeki paylaşımları görmek adına denemeler yaptım.
Null Auth izin verilmiş fakat yetkisi yok.
Guest session ise devre dışı.
Bu aşamada smb üzerindeki paylaşılan dosyaları görüntüleme şansımız yok.
Edindiğimiz bilgilere göre karşımızda Windows Server 2019 bir makine var ve adı:VULNNET-BC3TCK1 domain: vulnnet.local
## <span style="color:#0096FF">RPC</span>

![https://i.ibb.co/7xGHYbKW/Ekran-g-r-nt-s-2026-05-30-184134.png](https://i.ibb.co/7xGHYbKW/Ekran-g-r-nt-s-2026-05-30-184134.png)

Yekimiz olmadığı için enum yapamadık.
## <span style="color:#0096FF">LDAP</span>
sadece udp üzerinde açık olduğu için enum etmek mümkün değil.
## <span style="color:#0096FF">REDIS</span>

![https://i.ibb.co/KpjwXMCJ/Ekran-g-r-nt-s-2026-05-30-190454.png](https://i.ibb.co/KpjwXMCJ/Ekran-g-r-nt-s-2026-05-30-190454.png)

Güzel!
Burada hem redis servisinin versiyon bilgisini hem de kullanıcı adı ve dosya yolunu öğreniyoruz.
redis_version: `2.8.2402`
username: `enterprise-security`

# <span style="color:#AA0E1C"><b># Foothold</b></span>

![https://i.ibb.co/N202dmYy/Ekran-g-r-nt-s-2026-05-30-191919.png](https://i.ibb.co/N202dmYy/Ekran-g-r-nt-s-2026-05-30-191919.png)

Redis üzerinden ntlm hash yakalama tekniği işe yaradı. Bu sayede enterprise-security kullanıcısının hash değerini elde ettik. Şimdi bunu `hashcat` yardımıyla kıralım.
```
➜  active hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt --force
[...]
ENTERPRISE-SECURITY::VULNNET:388343945c6acba6:1e21183c73d0971b234477185b422198:010100000000000000437e4b2ef0dc013dfce1af2e77ba350000000002000800420033004e00560001001e00570049004e002d00550054005a0057003200480037004d0044005900310004003400570049004e002d00550054005a0057003200480037004d004400590031002e00420033004e0056002e004c004f00430041004c0003001400420033004e0056002e004c004f00430041004c0005001400420033004e0056002e004c004f00430041004c000700080000437e4b2ef0dc0106000400020000000800300030000000000000000000000000300000b9bdb222af742fb5ad5222de093e9f97d60612cb54b670efcd97b8ff0f5b9f150a001000000000000000000000000000000000000900280063006900660073002f003100390032002e003100360038002e003200310031002e003200310035000000000000000000:sand_0873959498
```
Şu an elimizde kullanıcı adı ve parola var. `enterprise-security:sand_0873959498`
Bu aşamada kerberoasting deneyebiliriz, smb üzerinden bilgi toplamaya devam edebiliriz, direkt oturum açmayı deneyebiliriz. 

![https://i.ibb.co/fYn6NN3t/Ekran-g-r-nt-s-2026-05-30-193159.png](https://i.ibb.co/fYn6NN3t/Ekran-g-r-nt-s-2026-05-30-193159.png)

Elimizdeki credential ile tekrardan smb servisine döndük. Bu sefer paylaşımları ve sistemdeki kullanıcıları görebiliyoruz.
Paylaşımlar arasında default olmayan göze çarpan `Enterprise-Share` bulunuyor. Üstelik hem okuma hem yazma yetkimiz bulunuyor.

![https://i.ibb.co/fzxf2vYN/Ekran-g-r-nt-s-2026-05-30-193725.png](https://i.ibb.co/fzxf2vYN/Ekran-g-r-nt-s-2026-05-30-193725.png)

Paylaşımı incelediğimizde bir powershell scripti bizi karşılıyor. İçerisine baktığımızda ise scriptin `C:\Users\Public\Documents\` dizinindeki tüm dosyaları sildiğini görüyoruz. 
Bu dosya sanki belirli aralıklarla çalışıyor gibi görünüyor. Bu dosya içerisine reverse shell payloadını yerleştireceğim

![https://i.ibb.co/Xr6nDx10/Ekran-g-r-nt-s-2026-05-30-194556.png](https://i.ibb.co/Xr6nDx10/Ekran-g-r-nt-s-2026-05-30-194556.png)

Düşündüğüm gibi de gerçekleşti ve shell kazandık.
# <span style="color:#AA0E1C"><b># Privilege Escalation</b></span>
## <span style="color:#0096FF">SeImpersonatePrivilege</span>
Çok basit bir inceleme yapıyorum.

![https://i.ibb.co/dwfbG9jr/Ekran-g-r-nt-s-2026-05-30-194812.png](https://i.ibb.co/dwfbG9jr/Ekran-g-r-nt-s-2026-05-30-194812.png)

Sistemdeki kullanıcıları ve bağlandığımız kullanıcının yetkilerini inceliyorum.
Kritik bir yetkiye sahibiz.

- **SeImpersonatePrivilege** : Bu ayrıcalık başka bir kullanıcının güvenlik bağlamını taklit etmesine olanak tanır. "Potato" saldırısı, bu ayrıcalığın kötüye kullanılması etrafında döner.

- GodPotato: https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe
- nc.exe: https://github.com/int0x33/nc.exe/raw/refs/heads/master/nc.exe

Dosyalarımızı hedef sisteme taşıdıktan sonra system kullanıcısından shell alıyorum.

![https://i.ibb.co/QvLWCpph/Ekran-g-r-nt-s-2026-05-31-060811.png](https://i.ibb.co/QvLWCpph/Ekran-g-r-nt-s-2026-05-31-060811.png)

## <span style="color:#0096FF">GPO Abuse</span>
Hedef sistem üzerinde sharphound çalıştırdım ve topladığı bilgileri bloodhound'a aktararak inceledim.

![https://i.ibb.co/BVbdykmD/Ekran-g-r-nt-s-2026-05-25-005933.png](https://i.ibb.co/BVbdykmD/Ekran-g-r-nt-s-2026-05-25-005933.png)

GPO nesnesi üzerinde GenericWrite yetkisine sahibiz yani özelliklerini değiştirebiliriz.
GPLink ise GPO'nun bağlı olduğu yeri gösteriyor. Bu ortamda direkt domaine bağlı olduğu için her şeyi etkileyebilir. Eğer OU'ya bağlı olsaydı sadece o OU'daki bilgisayarları etkilerdi.

```
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Backdoor" --Author "NT AUTHORITY\SYSTEM" --Command "cmd.exe" --Arguments "/c net localgroup administrators enterprise-security /add" --GPOName "SECURITY-POL-VN"
```
Bu kodda GPO uygulandığında bizi administrators grubuna eklemesini söyledim.

![https://i.ibb.co/67mLdDVt/Ekran-g-r-nt-s-2026-05-31-073423.png](https://i.ibb.co/67mLdDVt/Ekran-g-r-nt-s-2026-05-31-073423.png)

Sonrasında biraz bekleyebilir ve `gpupdate /force` komutu kullanabiliriz.
![https://i.ibb.co/Q3YjC5PH/Ekran-g-r-nt-s-2026-05-31-073523.png](https://i.ibb.co/Q3YjC5PH/Ekran-g-r-nt-s-2026-05-31-073523.png)

Görüldüğü gibi sahip olduğumuz kullanıcı artık administrators grubu içerisinde yer alıyor.
psexec ile shell almaya çalışacağım.

![https://i.ibb.co/rKQkJd4n/Ekran-g-r-nt-s-2026-05-31-073938.png](https://i.ibb.co/rKQkJd4n/Ekran-g-r-nt-s-2026-05-31-073938.png)

ve evet bu şekilde de system alabiliyoruz.
