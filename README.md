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
│   └── bench_hotpath.c          # Unit assertions & Head-to-Head A/B benchmark suite
└── windows/
    ├── goodbyedpi.exe           # Pre-compiled 64-bit System Tray executable
    ├── WinDivert.dll            # Signed WinDivert 2.2 user-mode library
    └── WinDivert64.sys          # Signed WinDivert 2.2 kernel driver
```

---

## Head-to-Head A/B Benchmarks (Original Repo vs. TurkDPI v2.1)

Measured deterministically over 500,000–2,000,000 iterations per kernel (`gcc -O3 -flto -march=x86-64-v2 -fno-plt`) via `tests/bench_hotpath.c`:

| Kernel / Pipeline Stage | Original GoodbyeDPI-Turkey | TurkDPI v2.1 | Speedup | Architectural Difference |
| :--- | :---: | :---: | :---: | :--- |
| **TLS 1.3 + Post-Quantum SNI Parser** (`1297 B`) | `605.85 ns` | **`7.96 ns`** | **76.1x** | $O(N)$ byte scan vs. direct extension length jump (`extract_sni_info`) |
| **Packet Header Checksum** (`547 B`) | `44.50 ns` | **`2.14 ns`** | **20.8x** | Full payload scan vs. $O(1)$ RFC 1624 incremental update |
| **HTTP Header Pattern Search** (`507 B`) | `118.60 ns` | **`23.62 ns`** | **5.0x** | Byte-by-byte loop vs. `SSE2` 16B/cycle vector broadcast (`fast_memmem`) |
| **DNS Conntrack (`Out + In`)** | `77.53 ns` (`malloc`/`free`) | **`20.10 ns`** (`0 alloc`) | **3.9x** | `UTHASH` heap node + $O(N)$ cleanup vs. 64B cache-aligned static table |
| **Full End-to-End TLS Desync Pipeline** | `856.59 ns` | **`186.93 ns`** | **4.6x** | `9016B` copy + 2x `WinDivertSend` vs. 3-way SNI-MidSplit single `WinDivertSendEx` batch |
| **Max Single-Core TLS Desync Throughput** | `1.17 Mpps` | **`5.35 Mpps`** | **4.6x** | Million TLS `ClientHello` desync operations per second per CPU core |

---

## How to Reproduce the Benchmarks Yourself

### 1. Deterministic A/B Hot-Path & Pipeline Benchmark (Linux / WSL / MinGW)
Runs both the legacy algorithms and the TurkDPI v2.1 engine side-by-side over identical packet payloads (`tests/bench_hotpath.c`):

```bash
make -C src test OPTIMIZE=1
```

### 2. Live Windows Runtime Benchmark (RAM, CPU & Discord TLS 1.3 Handshake Latency)
While `goodbyedpi.exe` is running in the System Tray, open **PowerShell** and run:

```powershell
# 1. Measure Process Memory (Private Working Set) & CPU Time
Get-Process goodbyedpi | Select-Object Name, Id, @{N="Memory (MB)";E={[math]::Round($_.WorkingSet64 / 1MB, 2)}}, @{N="CPU (s)";E={[math]::Round($_.CPU, 3)}}

# 2. Measure 5 Live TLS 1.3 Handshakes to discord.com:443 (via Yandex DNS 77.88.8.8)
$ip = (Resolve-DnsName discord.com -Server 77.88.8.8 -Type A | Select-Object -First 1).IPAddress
1..5 | ForEach-Object {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $tcp = New-Object System.Net.Sockets.TcpClient($ip, 443)
    $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false)
    $ssl.AuthenticateAsClient("discord.com")
    $sw.Stop()
    Write-Host ("Run #{0}: TLS={1} | Handshake={2} ms" -f $_, $ssl.SslProtocol, $sw.ElapsedMilliseconds)
    $ssl.Dispose(); $tcp.Dispose()
}
```

---

## License

Licensed under the [Apache License 2.0](LICENSE).
