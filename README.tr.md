# GoodbyeDPI-Turkey (Yüksek Performanslı Sürüm)

[ 🇬🇧 English ](README.md) | [ 🇹🇷 Türkçe ](README.tr.md)

[GoodbyeDPI-Turkey](https://github.com/cagritaskn/GoodbyeDPI-Turkey) ve [ValdikSS/GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) projelerinin [SS2Genji](https://github.com/SS2Genji) tarafından donanım ivmeli ve sıfır dinamik bellek tahsisli (zero-allocation) mimariyle optimize edilmiş sürümü. C99 ve x86_64 SIMD komut setleri (`SSE2` / `SSE4.2`), RFC 1624 diferansiyel sağlama toplamı (checksum), 64-byte önbellek satırı hizalı bağlantı takip tabloları, WinDivert toplu paket G/Ç (Batch I/O) ve Türkiye'deki İSS profillerini otomatik test eden tekil akıllı başlatıcı üzerine inşa edilmiştir.

> [!IMPORTANT]
> **Yönetici yetkisi ve antivirüs uyarısı:**
> - GoodbyeDPI, TCP/UDP paket başlıklarını çekirdek düzeyinde yakalayıp düzenlemek için açık kaynaklı ve imzalı [WinDivert 2.2](https://github.com/basil00/WinDivert) sürücüsünü (`WinDivert.dll` ve `WinDivert64.sys`) kullanır. Windows 7, 8, 10 ve 11 üzerinde yönetici yetkisi gerektirir.
> - Kaspersky Antivirüs, devre dışı bırakılsa veya dışlamalara eklense dahi WinDivert sürücüsünü engellemektedir. Sisteminizde Kaspersky kuruluysa GoodbyeDPI'ı çalıştırmadan önce tamamen kaldırıp Windows Defender kullanmanız gerekir.

---

## Mimari genel bakış

Paket işleme hattı, eşleşen TCP/UDP akışlarını WinDivert çekirdek sürücüsü üzerinden yakalar, kullanıcı alanında `malloc`/`free` çağrısı yapmadan DPI atlatma ve DNS yönlendirme işlemlerini uygular ve paketleri toplu olarak ağ yığınına geri gönderir.

```
┌────────────────────────────────────────────────────────────┐
│             Windows Ağ Yığını (NDIS / WFP)                 │
└─────────────────────────────┬──────────────────────────────┘
                              │ WinDivert 2.2 Çekirdek Filtresi
                              │ (QUEUE_LEN=8192, QUEUE_SIZE=4MB)
┌─────────────────────────────▼──────────────────────────────┐
│        Toplu Paket G/Ç (WinDivertRecvEx / SendEx)          │
│  - Tek çekirdek geçişinde 64 pakete kadar toplu okuma/yazma│
│  - 64-byte önbellek satırı (cache-line) hizalı tamponlar   │
└─────────────┬───────────────────────────────┬──────────────┘
              │ TCP (80 / 443)                │ UDP (53 / DNS)
┌─────────────▼──────────────┐  ┌─────────────▼──────────────┐
│  SIMD Arama & SNI Ayrıştır │  │  Zero-Alloc DNS Conntrack  │
│  - SSE2 16B/döngü memmem   │  │  - 4096 yuvalı statik tablo│
│  - O(ext) TLS/PQ-SNI okuma │  │  - SSE4.2 _mm_crc32_u64    │
│  - Kopyasız sonek eşleme   │  │  - Yandex DNS :1253 yönl.  │
└─────────────┬──────────────┘  └─────────────┬──────────────┘
              │                               │
┌─────────────▼───────────────────────────────▼──────────────┐
│      Tek Seferlik Paket Üretimi & RFC 1624 Checksum        │
│  - Yedek kopyasız TCP parçalama (--reverse-frag)           │
│  - Tek ayrıştırmalı sahte paket üretimi (TTL / SEQ / Csum) │
│  - O(1) diferansiyel başlık checksum güncellemesi          │
└────────────────────────────────────────────────────────────┘
```

---

## Hot-path performans ölçümleri

Linux x86_64 (`gcc -O3 -flto -march=x86-64-v2`) üzerinde [`tests/bench_hotpath.c`](tests/bench_hotpath.c) ile ölçülen birim işlem süreleri:

| Çekirdek Bileşen | Önceki (`ns/işlem`) | Optimize (`ns/işlem`) | Hızlanma | Teknik Detay |
| :--- | :---: | :---: | :---: | :--- |
| **TLS 1.3 + Post-Quantum SNI Okuma** (`1297 B`) | `718.66 ns` | **`17.81 ns`** | **40.4x** | $O(N)$ byte taraması yerine yapısal TLS uzantı (extension) atlayıcı |
| **Paket Checksum Güncelleme** (`547 B`) | `44.76 ns` | **`2.36 ns`** | **19.0x** | RFC 1624 diferansiyel 16/32-bit tümleyen aritmetiği |
| **HTTP Başlık Desen Arama** (`507 B`) | `139.74 ns` | **`15.05 ns`** | **9.3x** | `SSE2` ilk/son byte vektör yayılımı (`_mm_cmpeq_epi8` + `__builtin_ctz`) |
| **UDP DNS Conntrack (`Giden+Gelen`)** | `66.30 ns` + `malloc` | **`48.99 ns`** | **1.35x** | 4096 yuvalı statik tablo + `_mm_crc32_u64` + `GetTickCount64` |
| **TCP Auto-TTL Conntrack (`Gelen+Giden`)** | `73.94 ns` + `malloc` | **`51.24 ns`** | **1.44x** | 8192 yuvalı statik tablo + tam sayı Auto-TTL hesaplaması |
| **Blacklist Alan Adı Kontrolü** | `uthash` + `strchr` | **`32.25 ns`** | **Zero-Copy** | Tampon kopyalamadan `_mm_crc32_u64` ile büyük/küçük harf duyarsız sonek tarama |

---

## Hızlı başlangıç (Windows)

### Seçenek 1: Hazır ZIP paketi ile kurulum

1. [Releases](https://github.com/SS2Genji/GoodbyeDPI-Turkey/releases) sayfasından **`GoodbyeDPI-Turkey-Optimized.zip`** arşivini indirin.
2. Arşivi `C:\GoodbyeDPI\` gibi kalıcı bir klasöre çıkartın (Windows hizmeti kurduktan sonra klasörün yerini değiştirmeyin).
3. **`GoodbyeDPI-Turkey.cmd`** dosyasına çift tıklayın (Yönetici iznini otomatik olarak ister).
4. Açılan menüde **`A`** tuşuna basarak **Otomatik İSS Algılama** modunu başlatın veya istediğiniz profili seçin.

### Seçenek 2: Depoyu klonlayarak çalıştırma

`windows/x86_64` ve `windows/x86` klasörleri GitHub Actions tarafından derlenmiş hazır `.exe` ve `.sys` dosyalarını barındırır:

```cmd
git clone https://github.com/SS2Genji/GoodbyeDPI-Turkey.git
cd GoodbyeDPI-Turkey\windows
GoodbyeDPI-Turkey.cmd
```

---

## Birleştirilmiş akıllı başlatıcı (`GoodbyeDPI-Turkey.cmd`)

`windows/GoodbyeDPI-Turkey.cmd`, 14 ayrı `.cmd` dosyasını tek bir etkileşimli menü ve komut satırı arayüzünde birleştirir. Mevcut kısayolların bozulmaması için eski `.cmd` dosyaları otomatik olarak bu başlatıcıya yönlendirilmiştir.

### Komut satırı parametreleri

```cmd
:: 7 Türkiye İSS profilini sırayla test edip çalışan en hızlı profili bulur
GoodbyeDPI-Turkey.cmd --auto

:: Belirtilen profili (0..6) geçici pencerede çalıştırır
GoodbyeDPI-Turkey.cmd --run 0

:: Belirtilen profili (0..6) her açılışta başlayan Windows Hizmeti olarak kurar
GoodbyeDPI-Turkey.cmd --install 0

:: GoodbyeDPI ve WinDivert hizmetlerini tamamen durdurur ve kaldırır
GoodbyeDPI-Turkey.cmd --remove

:: Hizmet durumunu ve discord.com HTTPS erişimini kontrol eder
GoodbyeDPI-Turkey.cmd --status
```

### Türkiye İSS profil tablosu

Otomatik algılama (`--auto`), web sitelerinde yavaşlamaya yol açabilecek düşük sabit TTL profillerinden önce modern ve en az müdahaleci profilleri test eder:

| Profil No | Hedef İSS / Senaryo | Parametreler | DNS Yönlendirme |
| :---: | :--- | :--- | :--- |
| **`5`** | Modern Mod `-9` + Yandex DNS (İlk test edilen) | `-9 --dns-addr 77.88.8.8 --dns-port 1253 ...` | Yandex (`:1253`) |
| **`6`** | Sadece Modern Mod `-9` | `-9` | Sistem DNS |
| **`4`** | Superonline Alternatif 4 (Sabit TTL yok) | `-5 --dns-addr 77.88.8.8 --dns-port 1253 ...` | Yandex (`:1253`) |
| **`2`** | Superonline Alternatif 2 (Auto-TTL) | `-5` | Sistem DNS |
| **`0`** | Standart Türkiye (Türk Telekom / TurkNet / Kablonet) | `-5 --set-ttl 5 --dns-addr 77.88.8.8 --dns-port 1253 ...` | Yandex (`:1253`) |
| **`3`** | Superonline Alternatif 3 (`TTL 3` + Yandex DNS) | `--set-ttl 3 --dns-addr 77.88.8.8 --dns-port 1253 ...` | Yandex (`:1253`) |
| **`1`** | Superonline Alternatif 1 (Sadece `TTL 3`) | `--set-ttl 3` | Sistem DNS |

---

## macOS kullanımı

macOS tarafında depo, `byedpi` (`ciadpi`) aracını yerel bir SOCKS5 vekil sunucusu ve Türkiye'ye özel PAC (split-tunnel) betikleriyle sarmalar. Detaylı kurulum için [`macos/README.md`](macos/README.md) dosyasına bakabilirsiniz:

```bash
./macos/build.sh
sudo ./macos/scripts/turkey_dnsredir.sh
```

---

## Kaynak koddan derleme ve test

Linux üzerinde birim testlerini ve mikro-benchmark paketini çalıştırmak için:

```bash
# AddressSanitizer + UndefinedBehaviorSanitizer ile bellek güvenliği testi
make -C src test SANITIZE=1

# -O3 -flto -march=x86-64-v2 ile mikro-benchmark ölçümü
make -C src test OPTIMIZE=1
```

MinGW-w64 ile 64-bit Windows ikili dosyasını derlemek için:

```bash
make -C src CPREFIX=x86_64-w64-mingw32- BIT64=1 OPTIMIZE=1 \
  WINDIVERTHEADERS=/path/to/WinDivert/include \
  WINDIVERTLIBS=/path/to/WinDivert/x64
```

---

## Katkıda bulunanlar ve lisans

- Orijinal GoodbyeDPI motoru: [ValdikSS/GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)
- Türkiye DNS/İSS uyarlaması: [cagritaskn/GoodbyeDPI-Turkey](https://github.com/cagritaskn/GoodbyeDPI-Turkey)
- SIMD, RFC 1624, sıfır tahsisli conntrack, toplu G/Ç ve akıllı başlatıcı optimizasyonları: [Ahmet Emir Şimşek (SS2Genji)](https://github.com/SS2Genji)

[Apache License 2.0](LICENSE) altında lisanslanmıştır.
