# GoodbyeDPI-Turkey (TurkDPI v2.1 — System Tray & Clean-Sheet DPI Engine)

[ 🇬🇧 English ](README.md) | [ 🇹🇷 Türkçe ](README.tr.md)

**TurkDPI v2.1** is a clean-sheet, zero-allocation DPI circumvention engine for Turkey engineered from the ground up by [SS2Genji](https://github.com/SS2Genji). Inspired by **Zapret (`nfqws`/`winws`)**, **ByeDPI (`ciadpi`)**, **SpoofDPI**, and **GoodbyeDPI**, it runs silently in the **Windows System Tray (Notification Area)** with zero console window and zero `.cmd` script clutter, unblocking **Discord (Web, Gateway, and Voice/WebRTC UDP)** and all restricted services across every Turkish ISP.

---

## Quickstart (Windows — System Tray)

1. Download **`GoodbyeDPI-Turkey-Optimized.zip`** from [Releases](https://github.com/SS2Genji/GoodbyeDPI-Turkey/releases) and extract it to a permanent folder (e.g., `C:\TurkDPI\`).
2. The folder contains **only 3 files**:
   - `goodbyedpi.exe` (Native System Tray + DPI Desync Engine)
   - `WinDivert.dll`
   - `WinDivert64.sys`
3. Double-click **`goodbyedpi.exe`**. No `cmd.exe` window stays open — the app immediately settles into the **bottom-right System Tray (Notification Area)**.
4. On first launch, it automatically probes all 7 Turkish ISP profiles via real TLS 1.3 `ClientHello` $\rightarrow$ `ServerHello` handshakes, selects the fastest profile for your ISP, and saves your preference in `turkdpi.cfg`.
5. **Right-click the System Tray icon** at any time to:
   - **`⚡ Otomatik İSS Algıla (En Hızlı Profili Bul)`** — Re-probe all profiles in the background.
   - **`🔍 Discord & TLS 1.3 Bağlantısını Test Et`** — Measure live TLS 1.3 handshake latency to `discord.com`.
   - **Switch ISP Profiles (`[0]..[6]`)** — Instantaneous in-memory hot-swap + DNS cache flush.
   - **`⏸ DPI Filtresini Duraklat / ▶ Başlat`** — Pause or resume packet filtering on the fly.
   - **`🚀 Windows Açılışında Otomatik Başlat`** — Toggle automatic background Tray launch on Windows login.
   - **`🧹 Sürücü ve Ayarları Sıfırla (Tamamen Kaldır)`** — Remove all drivers, services, startup tasks, and config files cleanly.

---

## Clean Repository Structure

```text
GoodbyeDPI-Turkey/
├── src/
│   ├── turkdpi.h                # SIMD (SSE2/SSE4.2), RFC 1624 checksums & PQ-TLS SNI offset parser
│   ├── conntrack.c              # 64B cache-aligned zero-alloc DNS & SYN-ACK Auto-TTL conntrack
│   ├── desync.c                 # 3-Way SNI-MidSplit, Reverse Disorder, MD5Sig/BadSeq & Discord UDP Ses
│   ├── probe.c                  # Raw 77.88.8.8:1253 DNS resolver & TLS 1.3 ServerHello verifier
│   ├── main.c                   # Batched WinDivert worker thread & Native Win32 System Tray UI
│   ├── goodbyedpi-rc.rc         # Embedded Tray Icon & UAC Manifest resource
│   ├── goodbyedpi.exe.manifest  # Native Administrator UAC manifest
│   └── Makefile                 # Build & Sanitizer/Benchmark runner
├── tests/
│   └── bench_hotpath.c          # Unit assertions & nanosecond micro-benchmark suite
└── windows/
    ├── goodbyedpi.exe           # Pre-compiled 64-bit System Tray executable
    ├── WinDivert.dll            # Signed WinDivert 2.2 user-mode library
    └── WinDivert64.sys          # Signed WinDivert 2.2 kernel driver
```

---

## Hot-Path Micro-Benchmarks (`gcc -O3 -flto -march=x86-64-v2`)

| Kernel Component | Original Repo | TurkDPI v2.1 | Speedup | Implementation Detail |
| :--- | :---: | :---: | :---: | :--- |
| **TLS 1.3 + Post-Quantum SNI Parser** (`1297 B`) | `718.66 ns` | **`7.78 ns`** | **92.3x** | Direct record & extension length jumper (`extract_sni_info`) |
| **Header Checksum Update** (`547 B`) | `44.76 ns` | **`2.19 ns`** | **20.4x** | RFC 1624 incremental 16/32-bit one's complement arithmetic |
| **HTTP Header Pattern Search** (`507 B`) | `139.74 ns` | **`15.62 ns`** | **8.9x** | `SSE2` 16B/cycle first/last byte vector broadcast (`fast_memmem`) |
| **Zero-Copy Blacklist Suffix Lookup** | `uthash` + `malloc` | **`10.52 ns`** | **Zero-Copy** | Case-insensitive `_mm_crc32_u64` suffix hashing |
| **UDP DNS Conntrack (`Out + In`)** | `66.30 ns` + `malloc` | **`53.38 ns`** | **Zero-Alloc** | 64B-aligned 2048-slot static open-addressed table |
| **TCP Auto-TTL Conntrack (`In + Out`)** | `73.94 ns` + `malloc` | **`55.51 ns`** | **Zero-Alloc** | 64B-aligned 4096-slot static open-addressed table |

---

## License

Licensed under the [Apache License 2.0](LICENSE).
