# GoodbyeDPI-Turkey (TurkDPI v2.1 — System Tray & Yeni Nesil DPI Motoru)

[ 🇬🇧 English ](README.md) | [ 🇹🇷 Türkçe ](README.tr.md)

**TurkDPI v2.1**, Türkiye'deki internet servis sağlayıcılarının (Türk Telekom, Superonline, Vodafone, TurkNet, Kablonet) güncel DPI cihazlarını aşmak ve **Discord (Web, Uygulama ve Sesli Sohbet / WebRTC UDP)** dahil tüm engelli servisleri sıfır hız kaybıyla çalıştırmak için [SS2Genji](https://github.com/SS2Genji) tarafından **sıfırdan (clean-sheet)** yazılmış yeni nesil DPI atlatma motorudur.

Görev çubuğunda siyah `cmd.exe` penceresi tutmaz ve `.cmd` betik kalabalığına ihtiyaç duymaz; doğrudan **sağ alt köşeye (System Tray / Bildirim Alanı)** yerleşir ve sağ tık menüsüyle tüm ayarları anlık olarak yönetmenizi sağlar.

---

## Hızlı Kullanım (Sıfır CMD Penceresi — System Tray)

1. [Releases (Sürümler)](https://github.com/SS2Genji/GoodbyeDPI-Turkey/releases) sayfasından **`GoodbyeDPI-Turkey-Optimized.zip`** dosyasını indirin ve kalıcı bir klasöre (ör. `C:\TurkDPI\`) çıkartın.
2. Klasörün içinde karmaşık `.cmd` dosyaları yoktur; yalnızca **3 dosya** bulunur:
   - `goodbyedpi.exe` (System Tray Arayüzü + TurkDPI Çekirdeği)
   - `WinDivert.dll`
   - `WinDivert64.sys`
3. **`goodbyedpi.exe`** dosyasına çift tıklayın. Program hiçbir siyah konsol penceresi açmadan doğrudan **sağ alt köşedeki System Tray (Sistem Tepsisi)** alanına yerleşir.
4. İlk çalıştırmada İSS'niz için en hızlı çalışan profili arka planda otomatik olarak algılar, aktif eder ve seçiminizi `turkdpi.cfg` dosyasına kaydeder.
5. Sağ alttaki **TurkDPI simgesine sağ tıklayarak** (veya sol tıklayarak) açılan menüden:
   - **`⚡ Otomatik İSS Algıla (En Hızlı Profili Bul)`**: 7 farklı Türkiye İSS profilini gerçek TLS 1.3 el sıkışmasıyla test edip en hızlısını seçer.
   - **`🔍 Discord & TLS 1.3 Bağlantısını Test Et`**: Anlık Discord TLS 1.3 erişimini milisaniye (`ms`) cinsinden ölçüp bildirim olarak gösterir.
   - **Profiller (`[0]..[6]`)**: Tek tıkla programı kapatmadan profiller arasında geçiş yapar ve DNS önbelleğini temizler.
   - **`⏸ DPI Filtresini Duraklat / ▶ Başlat`**: İstediğiniz an filtreyi tek tıkla duraklatıp devam ettirir.
   - **`🚀 Windows Açılışında Otomatik Başlat`**: Bilgisayar her açıldığında sağ alt tepside otomatik başlamasını açar/kapatır.
   - **`🧹 Sürücü ve Ayarları Sıfırla (Tamamen Kaldır)`**: WinDivert sürücüsünü, başlangıç görevini ve ayarları tamamen temizleyip çıkar.

---

## Sadeleştirilmiş Dosya Mimarisi

```text
GoodbyeDPI-Turkey/
├── src/
│   ├── turkdpi.h                # SIMD (SSE2/SSE4.2), RFC 1624 Checksum & PQ-TLS SNI Ofset Ayrıştırıcı
│   ├── conntrack.c              # 64B önbellek hizalı sıfır-tahsisli DNS & SYN-ACK Auto-TTL takipçisi
│   ├── desync.c                 # 3-Parça SNI-MidSplit, Ters Sıralama, MD5Sig/BadSeq & Discord UDP Ses
│   ├── probe.c                  # Doğrudan 77.88.8.8:1253 DNS çözücü & TLS 1.3 ServerHello doğrulayıcı
│   ├── main.c                   # 64-paket toplu WinDivert iş parçacığı & Win32 System Tray arayüzü
│   ├── goodbyedpi-rc.rc         # Gömülü Tepsi Simgesi (Icon) & UAC Manifest kaynağı
│   ├── goodbyedpi.exe.manifest  # Otomatik Yönetici Yetkisi (UAC) bildirimi
│   └── Makefile                 # Derleme ve Sanitizer/Benchmark test betiği
├── tests/
│   └── bench_hotpath.c          # Birim testleri ve A/B karşılaştırmalı mikro-benchmark paketi
└── windows/
    ├── goodbyedpi.exe           # Derlenmiş 64-bit System Tray uygulaması
    ├── WinDivert.dll            # İmzalı WinDivert 2.2 kütüphanesi
    └── WinDivert64.sys          # İmzalı WinDivert 2.2 çekirdek sürücüsü
```

---

## A/B Performans Karşılaştırması (Orijinal Repo vs. TurkDPI v2.1)

Aynı paket yükleri üzerinde 500.000 – 2.000.000 iterasyonla deterministik olarak ölçülmüştür (`gcc -O3 -flto -march=x86-64-v2 -fno-plt`, `tests/bench_hotpath.c`):

| Çekirdek / Paket Hattı Aşaması | Orijinal GoodbyeDPI-Turkey | TurkDPI v2.1 | Hızlanma | Mimari Fark |
| :--- | :---: | :---: | :---: | :--- |
| **TLS 1.3 + Post-Quantum SNI Ayrıştırıcı** (`1297 B`) | `605.85 ns` | **`7.96 ns`** | **76.1x** | $O(N)$ bayt tarama yerine doğrudan uzantı uzunluğu üzerinden SNI ofset atlama |
| **Paket Başlığı Checksum Hesabı** (`547 B`) | `44.50 ns` | **`2.14 ns`** | **20.8x** | Tüm paketi baştan taramak yerine $O(1)$ RFC 1624 diferansiyel güncelleme |
| **HTTP Başlık Arama (`fast_memmem`)** (`507 B`) | `118.60 ns` | **`23.62 ns`** | **5.0x** | Bayt-bayt döngü yerine `SSE2` 16-bayt/döngü vektör karşılaştırma |
| **DNS Conntrack (`Giden + Gelen`)** | `77.53 ns` (`malloc`/`free`) | **`20.10 ns`** (`0 tahsis`) | **3.9x** | `UTHASH` heap düğümü + $O(N)$ temizlik yerine 64B hizalı statik tablo |
| **Uçtan Uca TLS Desync Hattı (End-to-End)** | `856.59 ns` | **`186.93 ns`** | **4.6x** | `9016B` yedek kopya + 2 ayrı syscall yerine 3-parça SNI-MidSplit tek `WinDivertSendEx` |
| **Tek Çekirdek Maksimum TLS Desync Hızı** | `1.17 Mpps` | **`5.35 Mpps`** | **4.6x** | Saniyede işlenebilen milyon TLS `ClientHello` paketi (tek CPU çekirdeği) |

---

## Performans Farkını Kendiniz Nasıl Ölçebilirsiniz?

### 1. Deterministik A/B Çekirdek Benchmark'ı (Linux / WSL / MinGW)
`tests/bench_hotpath.c` içindeki test paketi, orijinal algoritmaları ve TurkDPI v2.1 motorunu birebir aynı paketler üzerinde yarıştırıp nanosaniye (`ns`) ve `Mpps` (saniyede milyon paket) cinsinden tabloyu ekrana basar:

```bash
make -C src test OPTIMIZE=1
```

### 2. Canlı Windows Ölçümü (RAM, CPU ve Discord TLS 1.3 El Sıkışma Süresi)
`goodbyedpi.exe` sağ altta (System Tray) çalışırken **PowerShell** penceresinde şu komutları çalıştırarak canlı tüketimi ve TLS 1.3 bağlantı süresini ölçebilirsiniz:

```powershell
# 1. Anlık RAM (MB) ve Toplam CPU Süresini Ölç
Get-Process goodbyedpi | Select-Object Name, Id, @{N="RAM (MB)";E={[math]::Round($_.WorkingSet64 / 1MB, 2)}}, @{N="CPU (sn)";E={[math]::Round($_.CPU, 3)}}

# 2. Discord.com:443 Üzerinde 5 Gerçek TLS 1.3 El Sıkışmasını Milisaniye Olarak Ölç
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

---

## Lisans

[Apache License 2.0](LICENSE) altında lisanslanmıştır.
