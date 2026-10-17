# GoodbyeDPI-Turkey (TurkDPI v2.0 — Sıfırdan Yazılmış Yeni Nesil DPI ve Discord Motoru)

[ 🇬🇧 English ](README.md) | [ 🇹🇷 Türkçe ](README.tr.md)

**TurkDPI v2.0**, Türkiye'deki internet servis sağlayıcılarının (Türk Telekom, Superonline, Vodafone, TurkNet, Kablonet) güncel DPI cihazlarını aşmak ve **Discord (Web, Uygulama ve Sesli Sohbet / WebRTC UDP)** dahil tüm engelli servisleri sıfır hız kaybıyla çalıştırmak için [SS2Genji](https://github.com/SS2Genji) tarafından **sıfırdan (clean-sheet)** C99 ve donanımsal `SSE2`/`SSE4.2` SIMD komutlarıyla yazılmış yeni nesil DPI atlatma motorudur.

Sektörde kullanılan en güçlü DPI motorlarından (**Zapret `nfqws`/`winws`**, **ByeDPI `ciadpi`**, **SpoofDPI** ve **GoodbyeDPI**) ilham alınarak geliştirilmiş; eski sürümdeki kırılgan `.cmd` döngüleri ve `curl.exe` bağımlılıkları tamamen kaldırılıp tüm otomatik algılama, DNS koruması, UAC yetki yükseltme ve Windows Hizmet yönetimi doğrudan derlenmiş `goodbyedpi.exe` C çekirdeğinin içine gömülmüştür.

> [!IMPORTANT]
> **Yönetici Yetkisi ve Antivirüs Uyarısı:**
> - TurkDPI (`goodbyedpi.exe`), ağ paketlerini çekirdek düzeyinde işlemek için açık kaynaklı ve imzalı [WinDivert 2.2](https://github.com/basil00/WinDivert) sürücüsünü (`WinDivert.dll` ve `WinDivert64.sys`) kullanır. Çift tıkladığınızda otomatik olarak Yönetici (UAC) izni ister.
> - **Kaspersky Antivirüs**, devre dışı bırakılsa bile WinDivert sürücüsünü engellemektedir. Sisteminizde Kaspersky yüklüyse kaldırıp Windows Defender kullanmanız önerilir.

---

## TurkDPI v2.0 Neleri Değiştirdi? (Teknik Yenilikler)

1. **3-Parçalı SNI-Orta Nokta Bölme ve Ters Sıralama (ByeDPI + Zapret):** TLS 1.2/1.3 (ve 1200+ baytlık Post-Quantum `ClientHello`) paketlerindeki SNI alan adını **7.96 nanosaniyede** bulur; paketi `[0..2]`, `[2..SNI_ortası]`, `[SNI_ortası..son]` şeklinde tam alan adının ortasından (`"dis"` + `"cord.com"`) 3 parçaya böler ve ters sıra numarasıyla (`reverse disorder`) gönderir.
2. **Çoklu Aldatma (Multi-Fooling) Sahte Paket Enjeksiyonu (Zapret `md5sig,badseq,badsum`):** RFC 2385 TCP Seçenek 19 (`MD5 Signature`), pencere dışı sıra numarası (`-10000` seq / `-66000` ack), bozuk TCP sağlama toplamı (`BadSum`) ve gelen `SYN-ACK` paketinden santral mesafesini otomatik hesaplayan **Akıllı Auto-TTL** (`clamp(hop - 1, 3, 10)`) tekniklerini birleştirir.
3. **Discord Sesli Sohbet (Voice) & WebRTC UDP Desync:** Discord ses sunucularına giden UDP IP Discovery (`0x00 0x01 0x00 0x46`), RFC 5389 STUN (`0x2112A442`) ve DTLS (`0x16 0xFE`) el sıkışma paketlerini yakalayıp öncesinde `TTL=3` sahte UDP paketi göndererek ses kanallarındaki *"RTC Bağlanıyor"* takılmasını çözer.
4. **Çift Yığınlı DNS Kalkanı + IPv6 Modem Sızıntı Engelleyici:** IPv4 ve IPv6 UDP 53 DNS sorgularını standart dışı Yandex portuna (`77.88.8.8:1253`) yönlendirir; ev modemlerinin (`fe80::1`) yaptığı IPv6 DNS sızıntılarını otomatik engelleyerek Windows'un anında korumalı IPv4 tüneline geçmesini sağlar ve `dnsapi.dll!DnsFlushResolverCache()` ile DNS önbelleğini milisaniyeler içinde temizler.
5. **Çekirdek İçi Gerçek TLS 1.3 Otomatik İSS Algılayıcı (`--auto`):** Bozuk `.cmd` betikleri veya sistem DNS'ine bağımlı `curl.exe` yerine doğrudan C soketleriyle `77.88.8.8:1253` üzerinden `discord.com` IP'sini çözümler, çalışan WinDivert filtresi üzerinde profilleri bellekte anlık değiştirir ve gerçek TLS 1.3 `ClientHello` $\rightarrow$ `ServerHello` testiyle en hızlı profili bulur.

---

## Hızlı Kurulum ve Kullanım (Windows)

1. [Releases (Sürümler)](https://github.com/SS2Genji/GoodbyeDPI-Turkey/releases) sayfasından **`GoodbyeDPI-Turkey-Optimized.zip`** dosyasını indirin ve kalıcı bir klasöre (ör. `C:\GoodbyeDPI\`) çıkartın.
2. **`GoodbyeDPI-Turkey.cmd`** dosyasına (veya doğrudan `x86_64\goodbyedpi.exe` dosyasına) çift tıklayın.
3. Açılan Türkçe konsol menüsünde:
   - **`A`** tuşuna basarak İSS'niz için en hızlı çalışan profili otomatik bulup başlatabilir,
   - **`S`** tuşuna basarak en uygun profili otomatik tespit ettirip **Windows Hizmeti (Servis)** olarak kurabilirsiniz (bilgisayar her açıldığında arka planda otomatik çalışır),
   - **`R`** tuşuna basarak hizmeti ve WinDivert sürücüsünü tek tuşla tamamen kaldırabilirsiniz.

### Komut Satırı Parametreleri

```cmd
:: Etkileşimli Türkçe menüyü açar
GoodbyeDPI-Turkey.cmd

:: Otomatik İSS profili algılama (TLS 1.3 el sıkışma testi) ve çalıştırma
GoodbyeDPI-Turkey.cmd --auto

:: Belirli bir profili (0..6) doğrudan çalıştırma
GoodbyeDPI-Turkey.cmd --profile 0

:: En iyi profili otomatik bulup Windows Hizmeti olarak kurma
GoodbyeDPI-Turkey.cmd --install

:: Belirli bir profili (0..6) Windows Hizmeti olarak kurma
GoodbyeDPI-Turkey.cmd --install 1

:: Windows Hizmetini ve WinDivert sürücüsünü tamamen kaldırma
GoodbyeDPI-Turkey.cmd --remove

:: Hizmet durumunu ve canlı Discord TLS 1.3 erişimini test etme
GoodbyeDPI-Turkey.cmd --status
```

### Dahili Türkiye İSS Profilleri (`0..6`)

| No | Profil Adı | Hedef İSS | Kullanılan Desync Stratejisi |
| :---: | :--- | :--- | :--- |
| **`0`** | **Standart Türkiye** | Türk Telekom / TurkNet / Kablonet | 3-Parça SNI-MidSplit + Ters Sıralama + BadSum/BadSeq + Discord UDP Ses + Yandex `:1253` |
| **`1`** | **Superonline & Vodafone Modern** | Turkcell Superonline / Vodafone | Zapret TCP `MD5Sig` + Akıllı Auto-TTL (`1-3-10`) + BadSeq + SNI-MidSplit + Discord UDP Ses |
| **`2`** | **Superonline Alternatif 1** | Superonline Fiber / VDSL | Akıllı Auto-TTL (`1-3-10`) + BadSeq + 3-Parça SNI-MidSplit + Yandex `:1253` |
| **`3`** | **Superonline Alternatif 2** | Superonline (Uzak Santraller) | Sabit `TTL=4` + BadSeq + 3-Parça SNI-MidSplit + Yandex `:1253` |
| **`4`** | **Superonline Alternatif 3** | Superonline Klasik Mod | Sabit `TTL=3` + 3-Parça SNI-MidSplit + Yandex `:1253` |
| **`5`** | **ByeDPI Saf SNI-Disorder** | Düşük Gecikme / Oyun Modu | Saf 3-Parça SNI-MidSplit + Ters Sıralama (Sahte paketsiz, sıfır site bozma) |
| **`6`** | **Cloudflare DNS (`1.1.1.1`)** | Yurt / Kampüs / Kurumsal Ağlar | Cloudflare `1.1.1.1:53` + Hibrit `MD5Sig` / `BadSum` / `BadSeq` + SNI-MidSplit |

---

## Mikro-Benchmark Sonuçları (`gcc -O3 -flto -march=x86-64-v2`)

| Çekirdek Bileşeni | Gecikme (`ns/işlem`) | Mimari Detay |
| :--- | :---: | :--- |
| **RFC 1624 Diferansiyel Checksum** (`547 B`) | **`2.15 ns`** | Yalnızca değişen 16/32-bit başlık alanlarını O(1) sürede güncelleme |
| **TLS 1.3 + Post-Quantum SNI Ayrıştırıcı** (`1297 B`) | **`7.96 ns`** | Kayıt ve uzantı uzunlukları üzerinden doğrudan SNI ofset atlama |
| **Zero-Copy Kara Liste Arama** | **`10.54 ns`** | Donanımsal `_mm_crc32_u64` ile kopyalamasız alan adı soneki eşleştirme |
| **HTTP Başlık Arama (`fast_memmem`)** (`507 B`) | **`15.02 ns`** | `SSE2` 16-bayt/döngü vektör karşılaştırma |
| **TCP Auto-TTL Conntrack (`SYN-ACK + Sorgu`)** | **`54.94 ns`** | Sıfır-tahsisli (zero-alloc) 64-bayt hizalı 4096 yuvalı tablo |
| **UDP DNS Conntrack (`Giden + Gelen`)** | **`59.99 ns`** | Sıfır-tahsisli (zero-alloc) 64-bayt hizalı 2048 yuvalı tablo |

---

## Lisans

[Apache License 2.0](LICENSE) altında lisanslanmıştır.
