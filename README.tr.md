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
│   └── bench_hotpath.c          # Birim testleri ve nanosaniye mikro-benchmark paketi
└── windows/
    ├── goodbyedpi.exe           # Derlenmiş 64-bit System Tray uygulaması
    ├── WinDivert.dll            # İmzalı WinDivert 2.2 kütüphanesi
    └── WinDivert64.sys          # İmzalı WinDivert 2.2 çekirdek sürücüsü
```

---

## Performans Karşılaştırması (Orijinal Repo vs. TurkDPI v2.1)

| Çekirdek Bileşeni | Orijinal Repo | TurkDPI v2.1 | Hızlanma | Mimari Detay |
| :--- | :---: | :---: | :---: | :--- |
| **TLS 1.3 + Post-Quantum SNI Ayrıştırıcı** (`1297 B`) | `718.66 ns` | **`7.78 ns`** | **92.3x** | Kayıt ve uzantı uzunlukları üzerinden doğrudan SNI ofset atlama |
| **RFC 1624 Diferansiyel Checksum** (`547 B`) | `44.76 ns` | **`2.19 ns`** | **20.4x** | Yalnızca değişen 16/32-bit başlık alanlarını O(1) sürede güncelleme |
| **HTTP Başlık Arama (`fast_memmem`)** (`507 B`) | `139.74 ns` | **`15.62 ns`** | **8.9x** | `SSE2` 16-bayt/döngü vektör karşılaştırma |
| **Zero-Copy Kara Liste Arama** | `uthash` + `malloc` | **`10.52 ns`** | **Sıfır Kopya** | Donanımsal `_mm_crc32_u64` ile kopyalamasız alan adı soneki eşleştirme |
| **UDP DNS Conntrack (`Giden + Gelen`)** | `66.30 ns` + `malloc` | **`53.38 ns`** | **Sıfır Tahsis** | 64-bayt hizalı 2048 yuvalı statik tablo |
| **TCP Auto-TTL Conntrack (`SYN-ACK + Sorgu`)** | `73.94 ns` + `malloc` | **`55.51 ns`** | **Sıfır Tahsis** | 64-bayt hizalı 4096 yuvalı statik tablo |

---

## Lisans

[Apache License 2.0](LICENSE) altında lisanslanmıştır.
