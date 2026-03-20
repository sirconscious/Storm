```
 ░▒▓███████▓▒░▒▓████████▓▒░▒▓██████▓▒░░▒▓███████▓▒░░▒▓██████████████▓▒░  
░▒▓█▓▒░         ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░         ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░   ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░  ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░  ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░   ░▒▓█▓▒░   ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
```

<p align="center">
  <img src="https://img.shields.io/badge/version-0.4-cyan?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/language-Java-orange?style=for-the-badge&logo=java"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge"/>
</p>

<p align="center">
  A fast, multithreaded web security toolkit written in Java — featuring directory fuzzing, subdomain enumeration, and port scanning with banner grabbing.
</p>

---

## ⚡ Features

- 🔀 **Multithreaded** — configurable thread count for maximum speed
- 🌐 **HTTP/2 support** — faster connections with automatic HTTP/1.1 fallback
- 📂 **Directory fuzzing** — brute-force hidden paths and endpoints
- 🔎 **Subdomain enumeration** — discover subdomains via DNS resolution
- 🔌 **Port scanning** — TCP connect scan across any port range with split-thread architecture
- 🏷️ **Banner grabbing** — identify software and versions running on open ports
- 📊 **Live progress bar** — real-time scan progress across all threads
- 🎨 **Color-coded output** — instantly spot hits by status code
- 📝 **Async logging** — non-blocking `BlockingQueue` writer keeps threads from stalling on disk I/O
- 📊 **Scan summary** — hit/miss stats printed at the end of every scan

---

## 🚀 Getting Started

### Prerequisites

- Java 16+ (uses `record` types)

### Build & Run

```bash
# Clone the repo
git clone https://github.com/sirconscious/storm.git
cd storm

# Compile
cd src
javac *.java

# Run fuzzer from project root (so wordlists are found)
cd ..
java -cp src Main

# Run port scanner directly
java -cp src PortScanner <host> <startPort> <endPort> [threads] [timeoutMs]
```

---

## ⚙️ Configuration

### Fuzzer — edit constants in `Main.java`:

```java
static String target             = "https://example.com";  // target URL
static String wordlist           = "common.txt";            // wordlist for dir fuzzing
static String subdomainsWordlist = "subdomains.txt";        // wordlist for subdomain enum
static int    threads            = 50;                      // number of threads

static boolean runDirFuzz    = true;   // toggle directory fuzzing
static boolean runSubDomains = true;   // toggle subdomain enumeration
```

To enable/disable failed request logging, edit `Logger.java`:

```java
private static final boolean LOG_FAILED = false; // set true to log all failed requests
```

> ⚠️ Enabling failed logging on large wordlists will noticeably slow the scan.

### Port Scanner — CLI arguments:

```bash
java PortScanner <host> <startPort> <endPort> [threads] [timeoutMs]
```

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `host` | ✅ | — | Target hostname or IP |
| `startPort` | ✅ | — | First port to scan |
| `endPort` | ✅ | — | Last port to scan |
| `threads` | ❌ | `100` | Number of parallel threads |
| `timeoutMs` | ❌ | `200` | Connection timeout in milliseconds |

**Examples:**
```bash
# Scan common ports on localhost
java PortScanner 127.0.0.1 1 1024

# Full scan with custom threads and timeout
java PortScanner 192.168.1.1 1 65535 200 300

# Single port check
java PortScanner scanme.nmap.org 22 22 1 2000
```

---

## 🎨 Output

### Fuzzer
Hits are color-coded in the terminal:

| Color | Status Code | Meaning |
|-------|-------------|---------|
| 🟢 Green | `200` | OK |
| 🔵 Cyan | `301` / `302` | Redirect |
| 🟡 Yellow | `403` | Forbidden |

Results are saved to:
- `success.log` — all hits (200, 301, 302, 403)
- `failed.log` — everything else *(if enabled)*

### Port Scanner
Open ports and banners are displayed in a formatted table:

```
  [████████████████████████████████████████]  100.0%  (1024 / 1024 ports)

╔══════════════════════════════════════════════════════════╗
║  Scan results for scanme.nmap.org                        ║
╠══════╦══════════════════════════════════════════════════╣
║ Port ║ Banner                                           ║
╠══════╬══════════════════════════════════════════════════╣
║ 22   ║ SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13      ║
║ 80   ║ (no banner)                                      ║
╠══════╩══════════════════════════════════════════════════╣
║  Open: 2   Time: 3.19s                                  ║
╚══════════════════════════════════════════════════════════╝
```

---

## 📁 Project Structure

```
storm/
├── src/
│   ├── Main.java              # Entry point & configuration
│   ├── FuzzerThread.java      # Directory fuzzing thread
│   ├── SubDomainFuzzer.java   # Subdomain enumeration thread
│   ├── RequestSender.java     # HTTP client (shared, HTTP/2)
│   ├── WorldListReader.java   # Wordlist loader & chunk splitter
│   ├── Logger.java            # Async non-blocking logger
│   └── PortScanner.java       # Multithreaded port scanner & banner grabber
├── common.txt                 # Directory wordlist
├── subdomains.txt             # Subdomain wordlist
├── success.log                # Generated at runtime
└── failed.log                 # Generated at runtime (if enabled)
```

---

## 🏗️ Architecture

```
Main
 ├── WorldListReader    →  splits wordlist into N chunks
 ├── FuzzerThread × N  →  each thread hammers its chunk via RequestSender
 ├── SubDomainFuzzer × N → same but prepends word to domain
 └── Logger             →  single background writer drains BlockingQueue

PortScanner
 ├── buildThreads()     →  splits port range into N equal slices
 ├── ScannerThread × N  →  each thread extends Thread, scans its slice
 │    ├── isPortOpen()  →  TCP connect with configurable timeout
 │    └── grabBanner()  →  reads first response line from open port
 ├── AtomicInteger      →  thread-safe progress counter
 └── TreeMap (sync)     →  collects results sorted by port number
```

The shared `HttpClient` in `RequestSender` is intentional — one client handles connection pooling across all threads, which is far more efficient than spinning up a new client per thread.

The `PortScanner` divides the port range into contiguous slices — e.g. with 100 threads scanning ports 1–1024, each thread owns ~10 ports. This avoids thread contention and maximises throughput.

---

## 📜 Disclaimer

> This tool is intended for **authorized security testing and educational purposes only**.  
> Do not use STORM against systems you do not own or have explicit permission to test.  
> The author is not responsible for any misuse or damage caused by this tool.

---

## 👤 Author

Made with ☕ by **sirconscious**

---

<p align="center">⭐ Star the repo if you found it useful!</p>