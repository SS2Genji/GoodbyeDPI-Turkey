[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-lightgrey.svg)](#)
[![Release](https://img.shields.io/github/v/release/SS2Genji/GoodbyeDPI-Turkey)](https://github.com/SS2Genji/GoodbyeDPI-Turkey/releases)
[![Downloads](https://img.shields.io/github/downloads/SS2Genji/GoodbyeDPI-Turkey/total.svg)](https://github.com/SS2Genji/GoodbyeDPI-Turkey/releases)

# Kaspersky Antivirüsü Hakkında Önemli Not
>
> [!CAUTION]
> Kaspersky isimli antivirüs yazılımı Rus hükümetiyle olan anlaşmasından dolayı GoodbyeDPI'ın çalışmasına engel olmaktadır. Kaspersky isimli yazılımı kullanıyorsanız, kullandıysanız veya devre dışı halde bile olsa bilgisayarınızda bulunuyorsa lütfen tamamen kaldırın. Bunu yapmadığınız takdirde GoodbyeDPI çok yüksek ihtimalle çalışmayacaktır. Kaspersky yerine alternatif antivirüs yazılımları tercih edebilir ya da Windows Defender kullanabilirsiniz.
> Kaspersky'i GoodbyeDPI ZIP dosyasının indirme işlemi sırasında devre dışı bırakmanız, indirdikten sonra dışlamalara eklemeniz veya devre dışı bırakmanız sorunu çözmeyecektir. GoodbyeDPI'ı doğru şekilde kullanabilmek için Kaspersky isimli antivirüs yazılımını sistemden tamamen kaldırmanız gerekir.

## Özet

Bu proje, Discord (Web, masaüstü uygulaması ve sesli sohbet / WebRTC UDP kanalları dahil) ve diğer engelli site ile uygulamalara VPN kullanmadan ve internet hızında yavaşlama olmadan erişmek için [GoodbyeDPI-Turkey](https://github.com/cagritaskn/GoodbyeDPI-Turkey) projesinin sıfırdan yeniden yazılmış ve optimize edilmiş versiyonudur.

Orijinal sürümden farklı olarak klasör içinde onlarca `.cmd` komut dosyası barındırmaz ve görev çubuğunda açık kalan siyah bir komut istemi (`cmd.exe`) penceresi tutmaz. Uygulama çalıştırıldığında doğrudan sağ alt köşedeki **Windows Sistem Tepsisine (System Tray / Bildirim Alanı)** yerleşir; tüm profil geçişleri, otomatik İSS algılama ve başlangıç ayarları sağ tık menüsü üzerinden yapılır.

## GoodbyeDPI — Derin Paket İnceleme (DPI) atlatma aracı (Türkiye versiyonu)

Bu uygulama, Türkiye'deki bazı internet servis sağlayıcılarının DNS değişikliğine izin vermemesi ve SNI tabanlı paket engellemesi uygulaması sebebiyle, asıl proje olan [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)'ın Türkiye'deki İSS profillerine göre yeniden yapılandırılmış bir versiyonudur.
Birçok İSS'de (İnternet Servis Sağlayıcısı) bulunan ve belirli web sitelerine erişimi engelleyen "Derin Paket İnceleme" (DPI) sistemlerini atlatmak için tasarlanmıştır.
Optik ayırıcı veya port yansıtma (Pasif DPI) kullanarak bağlanan ve herhangi bir veriyi engellemeyen, ancak istenen hedeften daha hızlı yanıt veren DPI sistemlerini ve sıralı olarak bağlanan Aktif DPI cihazlarını işler. Bu uygulama bir VPN değildir; trafiğinizi uzak bir sunucu üzerinden geçirmez ve oyunlarda veya genel internet kullanımında hız ya da ping değişikliğine sebep olmaz.

> [!NOTE]
> Windows 10 ve 11 işletim sistemlerinde uygulama kendi manifest dosyası sayesinde çalışırken otomatik olarak yönetici izni (UAC) ister.

## Virüs & Veri Sızıntısı & Bitcoin Mining

Program açık kaynak kodlu olduğundan tüm kaynak kodunu `src/` klasörü altından inceleyebilirsiniz. Bazı kullanıcılar VirusTotal'de false positive (hatalı olumlu) sonuçlarla karşılaşabilmektedir; bunun sebebi paket yakalama işlemini yapan `WinDivert.dll` ve `WinDivert64.sys` sürücü dosyalarının doğrudan Windows ağ yığınına müdahale etmesidir. Bu `.dll` ve `.sys` dosyaları da açık kaynak kodludur ve Microsoft tarafından dijital olarak imzalanmıştır.
Dilerseniz tüm klasörü ya da `.zip` dosyasını [VirusTotal](https://www.virustotal.com/gui/home/upload) üzerinde taratıp sonuçları inceleyebilirsiniz.

> [!IMPORTANT]
> WinDivert dosyalarının açıklamalarında ya da özelliklerinde karşılaşacağınız Bitcoin adresi sizi endişelendirmesin.
> WinDivert açık kaynaklı bir Windows Paket İnceleme ve Değiştirme kütüphanesidir. Kütüphanenin geliştiricisi olan [basil00](https://github.com/basil00), bu projeyi ücretsiz ve açık kaynak kodlu olarak [GitHub - WinDivert](https://github.com/basil00/WinDivert) deposunda paylaşmaktadır.
> Geliştirici, bağış yapmak isteyenler için Bitcoin cüzdan adresini `.dll` ve `.sys` dosyalarının dosya açıklamasına eklemiştir. Dosya özelliklerinde görünen karmaşık harf ve rakam dizisi, WinDivert geliştiricisi basil00'a ait [resmi bağış sayfasındaki](https://reqrypt.org/donate.html) Bitcoin cüzdan adresidir.

## GoodbyeDPI'ı Kullanmak

Bu sürümde karmaşık `.cmd` betikleri kaldırılmıştır. İndirdiğiniz arşivde yalnızca 3 dosya yer alır: `goodbyedpi.exe`, `WinDivert.dll` ve `WinDivert64.sys`.

1. [Releases](https://github.com/SS2Genji/GoodbyeDPI-Turkey/releases) sayfasından **`GoodbyeDPI-Turkey-Optimized.zip`** dosyasını bilgisayarınıza indirin.
2. ZIP dosyasını kalıcı bir klasöre çıkarın (örneğin `C:\GoodbyeDPI\`).
3. Klasör içindeki **`goodbyedpi.exe`** dosyasına çift tıklayın.
4. Uygulama konsol penceresi açmadan sağ alt köşedeki **Sistem Tepsisine (System Tray)** yerleşir. İlk çalıştırmada internet servis sağlayıcınız için en hızlı çalışan profili otomatik olarak test edip seçer ve `turkdpi.cfg` dosyasına kaydeder.

> [!NOTE]
> İndirdiğiniz ZIP dosyasını çıkarttığınız konumdan taşımayın. Windows açılışında otomatik başlatma özelliğini aktif ettiğinizde sistem bu dosya yolunu kullanır. Dosyaları silmeyecek veya taşımayacağınız bir klasörde (`C:\GoodbyeDPI\` gibi) tutmanız önerilir.

### Sistem Tepsisi (Sağ Tık Menüsü) Kullanımı

Sağ alt köşedeki uygulama simgesine sağ tıkladığınızda (veya sol tıkladığınızda) açılan menüden tüm işlemleri yönetebilirsiniz:

- **Otomatik İSS Algıla (En Hızlı Profili Bul):** 7 farklı Türkiye İSS profilini gerçek TLS 1.3 bağlantısıyla arka planda test eder ve en düşük gecikmeli çalışan profili otomatik seçer.
- **Discord & TLS 1.3 Bağlantısını Test Et:** `discord.com` ile canlı TLS 1.3 el sıkışması yaparak bağlantı süresini milisaniye (`ms`) cinsinden ölçer ve bildirim olarak gösterir.
- **Profil Seçimi (`[0]` – `[6]`):** Uygulamayı kapatıp açmaya gerek kalmadan Türk Telekom, TurkNet, Kablonet ve Superonline alternatif profilleri arasında anında geçiş yapar ve DNS önbelleğini temizler.
- **DPI Filtresini Duraklat / Başlat:** Uygulamadan çıkmadan paket filtrelemeyi geçici olarak duraklatır veya yeniden başlatır.
- **Windows Açılışında Otomatik Başlat:** Eski `service_install.cmd` dosyalarına gerek kalmadan, bilgisayar her açıldığında uygulamanın sağ alt tepside otomatik olarak başlamasını sağlar.
- **Sürücü ve Ayarları Sıfırla (Tamamen Kaldır):** Çalışan filtreyi durdurur, `WinDivert` çekirdek sürücüsünü kaldırır, otomatik başlatma görevini ve `turkdpi.cfg` ayar dosyasını silip DNS önbelleğini temizler.

## GoodbyeDPI'ı Kaldırmak ve Ayarları Eski Haline Getirmek

Uygulamayı, `WinDivert` sürücüsünü ve başlangıç görevini bilgisayarınızdan tamamen kaldırmak için herhangi bir `.cmd` dosyası çalıştırmanıza gerek yoktur:

1. Sağ alt köşedeki (System Tray) uygulama simgesine sağ tıklayın.
2. **Sürücü ve Ayarları Sıfırla (Tamamen Kaldır)** seçeneğine tıklayın ve onay verin.
3. Uygulama tüm sürücü kayıtlarını ve başlangıç ayarlarını temizleyip kapanacaktır. Ardından klasörü silebilirsiniz.

Komut satırından kaldırmak isterseniz aynı işlemi `goodbyedpi.exe --uninstall` komutuyla da yapabilirsiniz.

## Superonline ve Alternatif Yöntemler

Superonline Fiber veya katı DPI uygulayan diğer servis sağlayıcılarda standart profil çalışmadığında, sağ tık menüsündeki **Otomatik İSS Algıla** seçeneği alternatif profilleri sırayla deneyerek çalışan yöntemi bulur. Dilerseniz sağ tık menüsünden manuel olarak da seçebilirsiniz:

- **Profil [0] Standart Türkiye:** Türk Telekom, TurkNet, Kablonet (Mod `-5` + Yandex DNS `77.88.8.8:1253`)
- **Profil [1] Alternatif 1:** Superonline (Sadece `TTL 3`)
- **Profil [2] Alternatif 2:** Superonline (Mod `-5` Auto-TTL)
- **Profil [3] Alternatif 3:** Superonline (`TTL 3` + Yandex DNS)
- **Profil [4] Alternatif 4:** Superonline (Mod `-5` + Yandex DNS)
- **Profil [5] Alternatif 5:** Modern Mod `-9` + Yandex DNS (3 parçalı SNI ortası bölme, ters sıralama ve Discord UDP ses atlatma, siteleri en az bozan profil)
- **Profil [6] Alternatif 6:** Modern Mod `-9` (DNS yönlendirmesiz)

> [!NOTE]
> DNS yönlendirmesi içermeyen **Profil 1, 2 veya 6**'yı manuel olarak seçerseniz, Windows ağ ayarlarınızdan DNS adresinizi **Yandex DNS (`77.88.8.8` / `77.88.8.1`)** veya **Cloudflare DNS (`1.1.1.1` / `1.0.0.1`)** olarak ayarlamanız gerekir. **Profil 0, 3, 4 ve 5** ise DNS trafiğini otomatik olarak port `1253` üzerinden Yandex DNS'e yönlendirir.

## Sık Karşılaşılan Sorunlar

- **WinDivert dosyaları bulunamadı hatası (Yalancı virüs algılaması):**
  Bu hatayı alıyorsanız antivirüs programınız `WinDivert64.sys` veya `WinDivert.dll` dosyasını karantinaya almış olabilir. Kullandığınız antivirüs yazılımında uygulamayı çıkardığınız klasörü dışlamalara (istisnalara) ekleyin. Kaspersky kullanıyorsanız dışlamalara eklemek yeterli olmayacağından Kaspersky'i sistemden kaldırmanız gerekir.

- **Bazı sitelerin yavaş açılması veya açılmaması sorunu:**
  Sabit düşük TTL değeri (`TTL 3`) kullanan **Profil 1** veya **Profil 3** seçiliyse bazı uzak sunuculara giden paketler hedefe ulaşmadan düşebilir. Sağ alt tepsideki simgeye sağ tıklayıp **Profil [5]** (Modern Mod `-9`), **Profil [4]** veya **Profil [2]** seçeneğine geçiş yaparak sorunu anında çözebilirsiniz.

- **Discord'a web üzerinden girilebilmesine rağmen masaüstü uygulamasının açılmaması ("Update failed") sorunu:**
  Sisteminizde daha önceden kalma başka bir GoodbyeDPI veya WinDivert kullanan uygulama çakışma yaratıyor olabilir. Önce sağ tık menüsünden **Sürücü ve Ayarları Sıfırla (Tamamen Kaldır)** seçeneğini çalıştırıp bilgisayarınızı yeniden başlatın ve yalnızca tek bir klasörden `goodbyedpi.exe` uygulamasını başlatın.

- **Ethernet bağlantısı sorunu:**
  İnternet bağlantınızı ethernet adaptörü ile sağlıyorsanız ve tüm profilleri denemenize rağmen sonuç alamıyorsanız **harmanprecious** isimli kullanıcının hazırladığı ethernet kartı ayar rehberine [Technopat Sosyal konusundan](https://www.technopat.net/sosyal/konu/goodbyedpi-ethernet-kartiyla-calismiyorsa-ne-yapilmali.3619948/) ulaşabilirsiniz.

## Performans ve Mimari Karşılaştırma (Benchmark)

Bu depodaki motor (`TurkDPI v2.1`), orijinal `GoodbyeDPI-Turkey` kod tabanındaki darboğazları ortadan kaldırmak üzere sıfırdan C ile yeniden yazılmıştır:

- **Sıfır Bellek Tahsisi (Zero-Allocation Conntrack):** Orijinal kodda her DNS sorgusunda ve her TCP `SYN-ACK` paketinde çalışan `uthash` (`malloc` / `free`) yapısı kaldırılmış; yerine 64-bayt işlemci önbelleği (cache-line) hizalı statik tablolar ve donanımsal `SSE4.2 CRC32C` (`_mm_crc32_u64`) özetleme fonksiyonu getirilmiştir.
- **Doğrudan TLS 1.3 ve Post-Quantum (`X25519MLKEM768`) SNI Ayrıştırma:** Orijinal kodun 1200+ baytlık TLS `ClientHello` paketini bayt bayt taraması yerine, TLS kayıt ve uzantı uzunlukları üzerinden doğrudan `0x0000` (SNI) uzantısının ofsetine atlayan $O(\text{uzantı})$ ayrıştırıcı yazılmıştır.
- **RFC 1624 Diferansiyel Checksum:** TCP pencere boyutu, sıra numarası, TTL veya DNS IP/port değiştirildiğinde tüm paketi baştan taramak yerine yalnızca değişen 16/32-bitlik başlık alanları $O(1)$ sürede güncellenir.
- **Toplu Paket İşleme (`WinDivertRecvEx` / `WinDivertSendEx`):** Çekirdek ve kullanıcı alanı (Ring-0 / Ring-3) arasındaki geçiş maliyetini düşürmek için paketler 64'lü diziler halinde okunur ve 3 parçalı SNI bölme paketleri tek bir sistem çağrısıyla gönderilir.

### A/B Çekirdek Benchmark Sonuçları (`gcc -O3 -flto -march=x86-64-v2`)

`tests/bench_hotpath.c` içerisindeki test paketi, orijinal `GoodbyeDPI-Turkey` algoritmaları ile `TurkDPI v2.1` fonksiyonlarını aynı paket yükleri üzerinde 500.000 – 2.000.000 iterasyon boyunca çalıştırarak karşılaştırır:

| Çekirdek / Paket Hattı Aşaması | Orijinal GoodbyeDPI-Turkey | TurkDPI v2.1 | Hızlanma | Teknik Fark |
| :--- | :---: | :---: | :---: | :--- |
| **TLS 1.3 PQ-ClientHello SNI Ayrıştırma** (`1297 B`) | `605.85 ns` | **`7.96 ns`** | **76.1x** | Bayt tarama yerine uzantı uzunluklarından doğrudan SNI ofsetine atlama |
| **Paket Başlığı Checksum Hesabı** (`547 B`) | `44.50 ns` | **`2.14 ns`** | **20.8x** | Tam paket taraması yerine $O(1)$ RFC 1624 diferansiyel güncelleme |
| **HTTP Başlık Arama (`fast_memmem`)** (`507 B`) | `118.60 ns` | **`23.62 ns`** | **5.0x** | Bayt döngüsü yerine `SSE2` 16-bayt/döngü vektör karşılaştırma |
| **DNS Conntrack (`Giden + Gelen`)** | `77.53 ns` (`malloc`/`free`) | **`20.10 ns`** (`0 tahsis`) | **3.9x** | `UTHASH` + bağlı liste temizliği yerine 64B hizalı statik tablo |
| **Uçtan Uca TLS Desync Hattı (End-to-End)** | `856.59 ns` | **`186.93 ns`** | **4.6x** | `9016B` kopya + 2 ayrı syscall yerine 3-parça SNI-MidSplit tek `WinDivertSendEx` |
| **Tek Çekirdek Maksimum TLS Desync Hızı** | `1.17 Mpps` | **`5.35 Mpps`** | **4.6x** | Saniyede işlenebilen milyon TLS `ClientHello` paketi |

```text
====================================================================================
  HEAD-TO-HEAD A/B BENCHMARK: Original GoodbyeDPI-Turkey vs. TurkDPI v2.1
====================================================================================
  Kernel / Pipeline Stage              |     Original | TurkDPI v2.1 |    Speedup
  -------------------------------------+--------------+--------------+-----------
  TLS 1.3 PQ-ClientHello SNI (1297B)   |    605.85 ns |      7.96 ns |     76.1x
  Packet Header Checksum (547B)        |     44.50 ns |      2.14 ns |     20.8x
  HTTP Header Search (507B)            |    118.60 ns |     23.62 ns |      5.0x
  DNS Conntrack (Out+In + 0-Alloc)     |     77.53 ns |     20.10 ns |      3.9x
  Full TLS Desync Pipeline (End2End)   |    856.59 ns |    186.93 ns |      4.6x
  -------------------------------------+--------------+--------------+-----------
  Max Single-Core TLS Desync Rate      |    1.17 Mpps |    5.35 Mpps |      4.6x
====================================================================================
```

### Testleri Kendiniz Çalıştırma

**1. A/B Çekirdek Benchmark'ı (Linux / WSL / MinGW):**
```bash
make -C src test OPTIMIZE=1
```

**2. Canlı Windows Ölçümü (PowerShell):**
`goodbyedpi.exe` sistem tepsisinde çalışırken PowerShell üzerinden anlık bellek/CPU kullanımını ve gerçek `discord.com:443` TLS 1.3 el sıkışma süresini ölçmek için:

```powershell
# Anlık RAM (MB) ve CPU süresini göster
Get-Process goodbyedpi | Select-Object Name, Id, @{N="RAM (MB)";E={[math]::Round($_.WorkingSet64 / 1MB, 2)}}, @{N="CPU (sn)";E={[math]::Round($_.CPU, 3)}}

# Discord.com:443 üzerinde 5 gerçek TLS 1.3 el sıkışmasını milisaniye olarak ölç
$ip = (Resolve-DnsName discord.com -Server 77.88.8.8 -Type A | Select-Object -First 1).IPAddress
1..5 | ForEach-Object {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $tcp = New-Object System.Net.Sockets.TcpClient($ip, 443)
    $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false)
    $ssl.AuthenticateAsClient("discord.com")
    $sw.Stop()
    Write-Host ("Test #{0}: Protokol={1} | El Sikisma Suresi={2} ms" -f $_, $ssl.SslProtocol, $sw.ElapsedMilliseconds)
    $ssl.Dispose(); $tcp.Dispose()
}
```

## Yasal Uyarı
>
> [!IMPORTANT]
> Bu uygulamanın kullanımından doğan her türlü yasal sorumluluk kullanan kişiye aittir. Uygulama yalnızca eğitim ve araştırma amaçları ile yazılmış ve düzenlenmiş olup; bu uygulamayı bu şartlar altında kullanmak ya da kullanmamak kullanıcının kendi seçimidir. Açık kaynak kodlarının paylaşıldığı bu platformdaki düzenlenmiş bu proje, bilgi paylaşımı ve kodlama eğitimi amaçları ile yazılmış ve düzenlenmiştir.
