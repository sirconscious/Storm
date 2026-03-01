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
  <img src="https://img.shields.io/badge/version-0.3-cyan?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/language-Java-orange?style=for-the-badge&logo=java"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge"/>
</p>

<p align="center">
  A fast, multithreaded web directory fuzzer and subdomain enumerator written in Java.
</p>

---

## ⚡ Features

- 🔀 **Multithreaded** — configurable thread count for maximum speed
- 🌐 **HTTP/2 support** — faster connections with automatic HTTP/1.1 fallback
- 📂 **Directory fuzzing** — brute-force hidden paths and endpoints
- 🔎 **Subdomain enumeration** — discover subdomains via DNS resolution
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

# Run from project root (so wordlists are found)
cd ..
java -cp src Main
```

---

## ⚙️ Configuration

Edit the constants at the top of `Main.java`:

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

---

## 🎨 Output

Hits are color-coded in the terminal:

| Color  | Status Code     | Meaning               |
|--------|-----------------|-----------------------|
| 🟢 Green  | `200`           | OK                    |
| 🔵 Cyan   | `301` / `302`   | Redirect              |
| 🟡 Yellow | `403`           | Forbidden             |

Results are saved to:
- `success.log` — all hits (200, 301, 302, 403)
- `failed.log` — everything else *(if enabled)*

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
│   └── Logger.java            # Async non-blocking logger
├── common.txt                 # Directory wordlist
├── subdomains.txt             # Subdomain wordlist
├── success.log                # Generated at runtime
└── failed.log                 # Generated at runtime (if enabled)
```

---

## 🏗️ Architecture

```
Main
 ├── WorldListReader  →  splits wordlist into N chunks
 ├── FuzzerThread × N →  each thread hammers its chunk via RequestSender
 ├── SubDomainFuzzer × N → same but prepends word to domain
 └── Logger           →  single background writer drains BlockingQueue
```

The shared `HttpClient` in `RequestSender` is intentional — one client handles connection pooling across all threads, which is far more efficient than spinning up a new client per thread.

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