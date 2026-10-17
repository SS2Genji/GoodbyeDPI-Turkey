# GoodbyeDPI-Turkey (High-Performance Edition)

[ 🇬🇧 English ](README.md) | [ 🇹🇷 Türkçe ](README.tr.md)

Hardware-accelerated, zero-allocation fork of [GoodbyeDPI-Turkey](https://github.com/cagritaskn/GoodbyeDPI-Turkey) and [ValdikSS/GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) by [SS2Genji](https://github.com/SS2Genji). Built in C99 with x86_64 SIMD intrinsics (`SSE2` / `SSE4.2`), RFC 1624 differential checksums, static cache-line-aligned connection tracking tables, WinDivert batch packet I/O, and a single smart launcher that automatically probes Turkish ISP DPI profiles.

> [!IMPORTANT]
> **Administrator privileges and antivirus notice:**
> - GoodbyeDPI uses the signed open-source [WinDivert 2.2](https://github.com/basil00/WinDivert) kernel driver (`WinDivert.dll` and `WinDivert64.sys`) to inspect and modify TCP/UDP headers in flight. Windows 7, 8, 10, and 11 require Administrator privileges to load this driver.
> - Kaspersky Antivirus blocks the WinDivert driver even when paused or added to exclusions. If Kaspersky is installed on the system, uninstall it and use Windows Defender before running GoodbyeDPI.

---

## Architecture overview

The packet pipeline intercepts matching TCP/UDP flows through the WinDivert kernel driver, applies DPI circumvention and DNS redirection in user space without dynamic heap allocations, and reinjects packets in batches.

```
┌────────────────────────────────────────────────────────────┐
│            Windows Network Stack (NDIS / WFP)              │
└─────────────────────────────┬──────────────────────────────┘
                              │ WinDivert 2.2 Kernel Filter
                              │ (QUEUE_LEN=8192, QUEUE_SIZE=4MB)
┌─────────────────────────────▼──────────────────────────────┐
│          Batched Packet I/O (WinDivertRecvEx / SendEx)     │
│  - Up to 64 packets per user/kernel transition             │
│  - 64-byte cache-line-aligned staging buffers              │
└─────────────┬───────────────────────────────┬──────────────┘
              │ TCP (80 / 443)                │ UDP (53 / DNS)
┌─────────────▼──────────────┐  ┌─────────────▼──────────────┐
│  SIMD Inspection & Parser  │  │  Zero-Alloc DNS Conntrack  │
│  - SSE2 16B/cycle memmem   │  │  - 4096-slot static table  │
│  - O(ext) TLS/PQ-SNI parse │  │  - SSE4.2 _mm_crc32_u64    │
│  - Zero-copy suffix lookup │  │  - Yandex DNS :1253 redir  │
└─────────────┬──────────────┘  └─────────────┬──────────────┘
              │                               │
┌─────────────▼───────────────────────────────▼──────────────┐
│        Zero-Reparse Injection & RFC 1624 Checksums         │
│  - Single-pass TCP fragmentation (--reverse-frag)          │
│  - Single-parse fake packet forging (TTL / SEQ / Checksum) │
│  - O(1) differential header checksum updates (RFC 1624)    │
└────────────────────────────────────────────────────────────┘
```

---

## Hot-path benchmarks

Measured on Linux x86_64 (`gcc -O3 -flto -march=x86-64-v2`) using [`tests/bench_hotpath.c`](tests/bench_hotpath.c):

| Kernel Component | Baseline (`ns/op`) | Optimized (`ns/op`) | Speedup | Implementation Detail |
| :--- | :---: | :---: | :---: | :--- |
| **TLS 1.3 + Post-Quantum SNI Parser** (`1297 B`) | `718.66 ns` | **`17.81 ns`** | **40.4x** | Structural record/extension jumper (`extract_sni`) replacing $O(N)$ byte scan |
| **Header Checksum Update** (`547 B`) | `44.76 ns` | **`2.36 ns`** | **19.0x** | RFC 1624 incremental 16/32-bit one's complement arithmetic |
| **HTTP Header Pattern Search** (`507 B`) | `139.74 ns` | **`15.05 ns`** | **9.3x** | `SSE2` first/last byte vector broadcast (`_mm_cmpeq_epi8` + `__builtin_ctz`) |
| **UDP DNS Conntrack (`Out+In`)** | `66.30 ns` + `malloc` | **`48.99 ns`** | **1.35x** | Zero-allocation 4096-slot open-addressed table + `_mm_crc32_u64` + `GetTickCount64` |
| **TCP Auto-TTL Conntrack (`In+Out`)** | `73.94 ns` + `malloc` | **`51.24 ns`** | **1.44x** | Zero-allocation 8192-slot open-addressed table + integer Auto-TTL scaling |
| **Blacklist Hostname Lookup** | `uthash` + `strchr` | **`32.25 ns`** | **Zero-Copy** | Case-insensitive `_mm_crc32_u64` suffix hashing without buffer copies |

---

## Quickstart (Windows)

### Option 1: Ready-to-run release package

1. Download **`GoodbyeDPI-Turkey-Optimized.zip`** from the [Releases](https://github.com/SS2Genji/GoodbyeDPI-Turkey/releases) page.
2. Extract the archive to a permanent folder such as `C:\GoodbyeDPI\`. Do not move the folder after installing the Windows service.
3. Run **`GoodbyeDPI-Turkey.cmd`** (it automatically requests Administrator privileges).
4. Press **`A`** to run the **Automatic ISP Probe**, or select a profile manually.

### Option 2: Clone repository

The `windows/x86_64` and `windows/x86` directories include pre-built executables compiled via GitHub Actions:

```cmd
git clone https://github.com/SS2Genji/GoodbyeDPI-Turkey.git
cd GoodbyeDPI-Turkey\windows
GoodbyeDPI-Turkey.cmd
```

---

## Unified smart launcher (`GoodbyeDPI-Turkey.cmd`)

`windows/GoodbyeDPI-Turkey.cmd` replaces the 14 separate `.cmd` scripts with one menu and CLI interface while keeping backwards-compatible wrapper scripts for existing shortcuts.

### CLI flags

```cmd
:: Automatically probe all 7 Turkish ISP profiles and select the fastest working mode
GoodbyeDPI-Turkey.cmd --auto

:: Run a specific profile (0..6) in a temporary window
GoodbyeDPI-Turkey.cmd --run 0

:: Install and start a profile (0..6) as an auto-starting Windows service
GoodbyeDPI-Turkey.cmd --install 0

:: Stop and remove GoodbyeDPI and WinDivert services cleanly
GoodbyeDPI-Turkey.cmd --remove

:: Check service state and test HTTPS reachability to discord.com
GoodbyeDPI-Turkey.cmd --status
```

### Turkish ISP profile matrix

The automatic probe (`--auto`) tests profiles from least intrusive (no fixed low TTL, avoiding broken websites) to most aggressive:

| Profile ID | Target ISP / Scenario | Flags | DNS Redirection |
| :---: | :--- | :--- | :--- |
| **`5`** | Modern Mode `-9` + Yandex DNS (Probed 1st) | `-9 --dns-addr 77.88.8.8 --dns-port 1253 ...` | Yandex (`:1253`) |
| **`6`** | Modern Mode `-9` Only | `-9` | System DNS |
| **`4`** | Superonline Alternative 4 (No fixed TTL) | `-5 --dns-addr 77.88.8.8 --dns-port 1253 ...` | Yandex (`:1253`) |
| **`2`** | Superonline Alternative 2 (Auto-TTL) | `-5` | System DNS |
| **`0`** | Standard Turkey (Türk Telekom / TurkNet / Kablonet) | `-5 --set-ttl 5 --dns-addr 77.88.8.8 --dns-port 1253 ...` | Yandex (`:1253`) |
| **`3`** | Superonline Alternative 3 (`TTL 3` + Yandex DNS) | `--set-ttl 3 --dns-addr 77.88.8.8 --dns-port 1253 ...` | Yandex (`:1253`) |
| **`1`** | Superonline Alternative 1 (`TTL 3` Only) | `--set-ttl 3` | System DNS |

---

## macOS usage

On macOS, the repository wraps `byedpi` (`ciadpi`) as a local SOCKS5 proxy with Turkish ISP split-tunnel PAC scripts. See [`macos/README.md`](macos/README.md) for details:

```bash
./macos/build.sh
sudo ./macos/scripts/turkey_dnsredir.sh
```

---

## Building and testing from source

Run the native sanitizer and micro-benchmark test suite on Linux:

```bash
# Run unit tests under AddressSanitizer + UndefinedBehaviorSanitizer
make -C src test SANITIZE=1

# Run hot-path micro-benchmarks with -O3 -flto -march=x86-64-v2
make -C src test OPTIMIZE=1
```

Cross-compile the 64-bit Windows binary using MinGW-w64:

```bash
make -C src CPREFIX=x86_64-w64-mingw32- BIT64=1 OPTIMIZE=1 \
  WINDIVERTHEADERS=/path/to/WinDivert/include \
  WINDIVERTLIBS=/path/to/WinDivert/x64
```

---

## Credits & license

- Original GoodbyeDPI engine: [ValdikSS/GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)
- Turkey DNS/ISP configuration fork: [cagritaskn/GoodbyeDPI-Turkey](https://github.com/cagritaskn/GoodbyeDPI-Turkey)
- SIMD, RFC 1624, zero-allocation conntrack, batch I/O, and smart launcher optimizations: [Ahmet Emir Şimşek (SS2Genji)](https://github.com/SS2Genji)

Licensed under the [Apache License 2.0](LICENSE).
