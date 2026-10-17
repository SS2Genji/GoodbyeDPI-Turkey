# GoodbyeDPI-Turkey (TurkDPI v2.0 — Next-Gen Clean-Sheet DPI Engine)

[ 🇬🇧 English ](README.md) | [ 🇹🇷 Türkçe ](README.tr.md)

**TurkDPI v2.0** is a clean-sheet, zero-allocation DPI circumvention engine for Turkey engineered from the ground up by [SS2Genji](https://github.com/SS2Genji). Inspired by industry-proven DPI bypass architectures (**Zapret `nfqws`/`winws`**, **ByeDPI `ciadpi`**, **SpoofDPI**, and **GoodbyeDPI**), it replaces the legacy 2017 codebase with a 5-file hardware-accelerated C99/SIMD engine that unblocks **Discord (Web, Gateway, and Voice/WebRTC UDP)** and all restricted services across every Turkish ISP out of the box.

> [!IMPORTANT]
> **Administrator privileges and antivirus notice:**
> - TurkDPI (`goodbyedpi.exe`) uses the signed open-source [WinDivert 2.2](https://github.com/basil00/WinDivert) kernel driver (`WinDivert.dll` and `WinDivert64.sys`) to inspect and desynchronize TCP/UDP headers in flight. Running the binary automatically requests Administrator privileges via Windows UAC.
> - Kaspersky Antivirus blocks the WinDivert driver even when paused or added to exclusions. If Kaspersky is installed, uninstall it and use Windows Defender.

---

## Why a Clean-Sheet Rewrite?

Turkish ISPs (**Türk Telekom, Superonline, Vodafone, TurkNet, Kablonet**) deploy heterogeneous DPI middleboxes that inspect TLS 1.3 SNI extensions, hijack port 53 DNS, leak IPv6 DNS via router advertisements (`fe80::1`), and throttle or drop Discord Voice/WebRTC UDP handshakes.

TurkDPI v2.0 solves all of these inside a single compiled C binary (`goodbyedpi.exe`) with zero batch scripting loops:

1. **3-Way SNI-Midpoint Split & Reverse Disorder (ByeDPI + Zapret):** Parses TLS 1.2/1.3 (including 1200B+ Post-Quantum X25519MLKEM768 `ClientHello`s) in **7.96 ns** and splits the TCP payload into 3 segments (`[0..2]`, `[2..SNI_mid]`, `[SNI_mid..end]`) transmitted in reverse sequence order so passive/inline DPI reassemblers never see the contiguous hostname (e.g., `"dis"` + `"cord.com"`).
2. **Multi-Fooling Decoy Injection (Zapret `dpi-desync-fooling=md5sig,badseq,badsum`):** Forges decoy TLS `ClientHello` packets carrying RFC 2385 TCP Option 19 (`MD5 Signature`, 20 bytes), out-of-window sequence/acknowledgment offsets (`-10000` / `-66000`), deliberate bad TCP checksums, and SYN-ACK Auto-TTL calculation (`clamp(hops - delta, 3, 10)`).
3. **Discord Voice & WebRTC UDP Desync:** Detects outbound Discord Voice IP Discovery (`70/74B` starting with `0x00 0x01 0x00 0x46`), RFC 5389 STUN (`0x2112A442`), and DTLS (`0x16 0xFE`) handshakes on high UDP ports (`19294..65535`) and injects a low-TTL (`TTL=3`) zero-payload UDP decoy beforehand.
4. **Dual-Stack DNS Hijack Shield + IPv6 Router Leak Blocker:** Redirects IPv4/IPv6 UDP 53 queries to Yandex Safe Non-Standard Port (`77.88.8.8:1253` / `2a02:6b8::feed:0ff:1253`), drops outbound IPv6 link-local router DNS queries (`fe80::/10` UDP 53) so Windows immediately falls back to the protected IPv4 tunnel, and flushes the Windows DNS cache in-process via `dnsapi.dll!DnsFlushResolverCache()`.
5. **In-Process TLS 1.3 ISP Auto-Probe (`--auto`):** Eliminates broken `cmd.exe` `FOR` loops and `curl.exe` calls. Queries `77.88.8.8:1253` directly via raw UDP sockets, hot-swaps the active profile in memory while the WinDivert worker thread runs, and verifies real TLS 1.3 `ClientHello` $\rightarrow$ `ServerHello` (`0x16 0x03 .. 0x02`) handshakes against `discord.com`, `gateway.discord.gg`, and `www.google.com`.

---

## Architecture Overview

The entire engine is organized into 5 clean C files under `src/`:

| Source File | Responsibility |
| :--- | :--- |
| [`src/turkdpi.h`](src/turkdpi.h) | SIMD (`SSE2` / `SSE4.2 CRC32C`) intrinsics, O(1) RFC 1624 differential checksums, structural TLS SNI offset parser (`extract_sni_info`), and profile definitions. |
| [`src/conntrack.c`](src/conntrack.c) | 64-byte cache-line-aligned zero-allocation DNS UDP tracker, TCP SYN-ACK Auto-TTL hop tracker, zero-copy domain suffix matcher, and `DnsFlushResolverCache()`. |
| [`src/desync.c`](src/desync.c) | 7 Turkish ISP profiles, 3-way SNI-midpoint TCP splitter, RFC 2385 TCP MD5Sig + BadSeq + BadSum + Auto-TTL decoy injector, and Discord Voice/WebRTC UDP desync. |
| [`src/probe.c`](src/probe.c) | Raw UDP DNS resolver (`77.88.8.8:1253` + anycast fallbacks + BTK sinkhole filter) and non-blocking TLS 1.3 `ServerHello` verifier. |
| [`src/main.c`](src/main.c) | 64-packet batched WinDivert worker thread, IPv6 router DNS leak blocker, UAC auto-elevation, native Windows Service manager (`--install`/`--remove`/`--status`), and interactive Turkish console UI. |

---

## Hot-Path Micro-Benchmarks

Measured on Linux x86_64 (`gcc -O3 -flto -march=x86-64-v2 -fno-plt`) using [`tests/bench_hotpath.c`](tests/bench_hotpath.c):

| Kernel Component | Latency (`ns/op`) | Implementation Detail |
| :--- | :---: | :--- |
| **RFC 1624 Differential Checksum** (`547 B`) | **`2.15 ns`** | Incremental 16/32-bit one's complement header update |
| **TLS 1.3 + Post-Quantum SNI & Offset Parser** (`1297 B`) | **`7.96 ns`** | Direct record & extension length jumper (`extract_sni_info`) |
| **Zero-Copy Blacklist Suffix Lookup** | **`10.54 ns`** | Case-insensitive `_mm_crc32_u64` suffix hashing without buffer copies |
| **HTTP Header Pattern Search** (`507 B`) | **`15.02 ns`** | `SSE2` 16B/cycle first/last byte vector broadcast (`fast_memmem`) |
| **TCP Auto-TTL Conntrack (`SYN-ACK + Lookup`)** | **`54.94 ns`** | Zero-allocation 4096-slot 64B-aligned open-addressed table |
| **UDP DNS Conntrack (`Out + In Pair`)** | **`59.99 ns`** | Zero-allocation 2048-slot 64B-aligned open-addressed table |

---

## Quickstart (Windows)

1. Download **`GoodbyeDPI-Turkey-Optimized.zip`** from [Releases](https://github.com/SS2Genji/GoodbyeDPI-Turkey/releases) and extract it to a permanent folder (e.g., `C:\GoodbyeDPI\`).
2. Double-click **`GoodbyeDPI-Turkey.cmd`** (or run `x86_64\goodbyedpi.exe` directly). It automatically elevates via UAC and opens the native Turkish console menu.
3. Press **`A`** for **Automatic ISP Detection & Live Run**, or **`S`** to automatically detect the fastest profile for your ISP and install it as a permanent Windows Service.

### Command-Line Interface (`goodbyedpi.exe` / `GoodbyeDPI-Turkey.cmd`)

```cmd
:: Interactive Turkish menu (default when launched without arguments)
GoodbyeDPI-Turkey.cmd

:: In-process TLS 1.3 ISP auto-probe and live run
GoodbyeDPI-Turkey.cmd --auto

:: Run a specific Turkish ISP profile (0..6)
GoodbyeDPI-Turkey.cmd --profile 0

:: Auto-probe the best profile and install as an auto-starting Windows service
GoodbyeDPI-Turkey.cmd --install

:: Install a specific profile (0..6) as a Windows service
GoodbyeDPI-Turkey.cmd --install 1

:: Stop and remove GoodbyeDPI and WinDivert services cleanly
GoodbyeDPI-Turkey.cmd --remove

:: Check Windows service status and live Discord TLS 1.3 reachability
GoodbyeDPI-Turkey.cmd --status
```

### Built-in Turkish ISP Profiles (`0..6`)

| ID | Profile Name | Target ISP | Desync Strategy |
| :---: | :--- | :--- | :--- |
| **`0`** | **Standart Türkiye** | Türk Telekom / TurkNet / Kablonet | 3-Way SNI-MidSplit + Reverse Disorder + BadSum/BadSeq + Discord UDP Ses + Yandex `:1253` |
| **`1`** | **Superonline & Vodafone Modern** | Turkcell Superonline / Vodafone | Zapret TCP `MD5Sig` + Smart Auto-TTL (`1-3-10`) + BadSeq + SNI-MidSplit + Discord UDP Ses |
| **`2`** | **Superonline Alternatif 1** | Superonline Fiber / VDSL | Smart Auto-TTL (`1-3-10`) + BadSeq + 3-Way SNI-MidSplit + Yandex `:1253` |
| **`3`** | **Superonline Alternatif 2** | Superonline (4+ Hop Central Offices) | Fixed `TTL=4` + BadSeq + 3-Way SNI-MidSplit + Yandex `:1253` |
| **`4`** | **Superonline Alternatif 3** | Superonline Classic | Fixed `TTL=3` + 3-Way SNI-MidSplit + Yandex `:1253` |
| **`5`** | **ByeDPI Saf SNI-Disorder** | Low-Latency / Gaming Mode | Pure 3-Way SNI-MidSplit + Reverse Disorder (Zero fake packets, zero site breakage) |
| **`6`** | **Cloudflare DNS (`1.1.1.1`)** | Campus / Corporate / Port 1253 Blocked | Cloudflare `1.1.1.1:53` + Hybrid `MD5Sig` / `BadSum` / `BadSeq` + SNI-MidSplit |

---

## Building and Testing from Source

```bash
# Run unit tests + ASan/UBSan sanitizer suite (10 test suites + benchmarks)
make -C src test SANITIZE=1

# Run optimized hot-path micro-benchmarks (-O3 -flto -march=x86-64-v2)
make -C src test OPTIMIZE=1

# Cross-compile 64-bit Windows binary using MinGW-w64
make -C src CPREFIX=x86_64-w64-mingw32- BIT64=1 OPTIMIZE=1 \
  WINDIVERTHEADERS=/path/to/WinDivert/include \
  WINDIVERTLIBS=/path/to/WinDivert/x64
```

---

## Credits & License

- Clean-Sheet TurkDPI v2.0 Engine & SIMD Architecture: [Ahmet Emir Şimşek (SS2Genji)](https://github.com/SS2Genji)
- DPI Research & Inspiration: [bol-van/zapret](https://github.com/bol-van/zapret), [hufrea/byedpi](https://github.com/hufrea/byedpi), [ValdikSS/GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI), [cagritaskn/GoodbyeDPI-Turkey](https://github.com/cagritaskn/GoodbyeDPI-Turkey)

Licensed under the [Apache License 2.0](LICENSE).
