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
  <img src="https://img.shields.io/badge/version-0.5-cyan?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/language-Java-orange?style=for-the-badge&logo=java"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge"/>
</p>

<p align="center">
  A fast, multithreaded network security toolkit written in Java — featuring directory fuzzing, subdomain enumeration, port scanning, host discovery, and service fingerprinting with CVE risk flagging.
</p>

---

## ⚡ Features

- 🔀 **Multithreaded** — configurable thread count for maximum speed
- 🌐 **HTTP/2 support** — faster connections with automatic HTTP/1.1 fallback
- 📂 **Directory fuzzing** — brute-force hidden paths and endpoints
- 🔎 **Subdomain enumeration** — discover subdomains via DNS resolution
- 🔌 **Port scanning** — TCP connect scan across any port range with split-thread architecture
- 🏷️ **Banner grabbing** — identify software and versions running on open ports
- 🖥️ **Host discovery** — ICMP ping + TCP fallback across CIDR ranges and IP ranges
- 🔬 **Service fingerprinting** — protocol-specific probes to identify software, versions, and OS hints
- ⚠️ **Risk flagging** — cross-references findings against known CVEs and bad configurations
- 📊 **Live progress bar** — real-time scan progress across all threads
- 🎨 **Color-coded output** — instantly spot hits by status code and risk level
- 📝 **Async logging** — non-blocking `BlockingQueue` writer keeps threads from stalling on disk I/O
- 🖥️ **Unified interactive CLI** — single menu to launch any module

---

## 🚀 Getting Started

### Prerequisites

- Java 16+ (uses `record` types and switch expressions)

### Build & Run

```bash
# Clone the repo
git clone https://github.com/sirconscious/storm.git
cd storm

# Compile everything at once
cd src
javac *.java

# Launch the interactive menu (run from project root so wordlists are found)
cd ..
java -cp src Main
```

---

## ⚙️ Configuration

### Interactive Menu
Storm's unified CLI prompts you for all inputs at runtime. Every prompt shows a default value in `[brackets]` — just press Enter to accept it.

```
╔══════════════════════════════════════════╗
║              SELECT A MODULE             ║
╠══════════════════════════════════════════╣
║  [1]  Directory Fuzzer                   ║
║  [2]  Subdomain Enumerator               ║
║  [3]  Port Scanner                       ║
║  [4]  Host Discovery                     ║
║  [5]  Full Recon  (all modules)          ║
║  [0]  Exit                               ║
╚══════════════════════════════════════════╝
```

### Standalone Module Usage

Each module can also be run directly:

```bash
# Port scanner
java -cp src PortScanner <host> <startPort> <endPort> [threads] [timeoutMs]

# Host discovery
java -cp src HostDiscovery <target> [threads] [timeoutMs]

# Service fingerprinter
java -cp src ServiceFingerprinter <host> <port1,port2,...> [timeoutMs]
```

### Port Scanner — arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `host` | ✅ | — | Target hostname or IP |
| `startPort` | ✅ | — | First port to scan |
| `endPort` | ✅ | — | Last port to scan |
| `threads` | ❌ | `100` | Number of parallel threads |
| `timeoutMs` | ❌ | `200` | Connection timeout in ms |

### Host Discovery — target formats

| Format | Example |
|--------|---------|
| CIDR | `192.168.1.0/24` |
| IP Range | `192.168.1.1-192.168.1.254` |
| Single IP | `192.168.1.1` |

### Service Fingerprinter — arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `host` | ✅ | — | Target hostname or IP |
| `ports` | ✅ | — | Comma-separated list of ports |
| `timeoutMs` | ❌ | `500` | Connection timeout in ms |

```bash
# Examples
java -cp src ServiceFingerprinter 192.168.1.1 22,80,443,3306
java -cp src ServiceFingerprinter 192.168.100.50 3306 1000
java -cp src ServiceFingerprinter scanme.nmap.org 22,80
```

---

## 🔬 Service Fingerprinter — Supported Protocols

| Port(s) | Protocol | Probe Method | What It Detects |
|---------|----------|-------------|-----------------|
| 21 | FTP | Read greeting | ProFTPD, vsFTPD, FileZilla + version |
| 22 | SSH | Read banner | OpenSSH, Dropbear + version + OS hint |
| 23 | Telnet | Connect | Always flagged CRITICAL |
| 25, 587 | SMTP | Read greeting | Postfix, Exim, Sendmail, Exchange |
| 53 | DNS | Connect | Flags open recursion risk |
| 80, 8080 | HTTP | GET request | nginx, Apache, IIS + version |
| 110 | POP3 | Read greeting | Dovecot, Courier, Exchange |
| 143 | IMAP | Read greeting | Dovecot, Courier, Exchange |
| 443, 8443 | HTTPS | HTTPS request | Server header via TLS |
| 445 | SMB | Connect | Flags EternalBlue risk |
| 3306 | MySQL | Binary handshake | MySQL/MariaDB version + auth check |
| 3389 | RDP | Connect | Flags BlueKeep risk |
| 5900 | VNC | Read RFB banner | VNC version |

---

## ⚠️ Risk Levels

| Level | Meaning |
|-------|---------|
| 🔴 CRITICAL | Immediate action required — backdoor, no auth, RCE |
| 🟠 HIGH | Serious vulnerability or severely outdated software |
| ⚠️ MEDIUM | Outdated version or insecure configuration |
| 🔵 LOW | Minor concern, verify configuration |
| ✅ OK | No known issues with this version |
| ❓ UNKNOWN | Could not fingerprint |

---

## 🎨 Output Examples

### Service Fingerprinter
```
╠════════╬══════════════╬═══════════════════╬════════════╬══════════════════════════════╣
║ Port   ║ Service      ║ Software          ║ Version    ║ Risk                         ║
╠════════╬══════════════╬═══════════════════╬════════════╬══════════════════════════════╣
║ 22     ║ SSH          ║ OpenSSH           ║ 4.3p2      ║ 🟠 HIGH     ssh-rsa deprecated  ║
║ 80     ║ HTTP         ║ Apache            ║ 2.4.41     ║ ✅ OK       Version looks current║
║ 3306   ║ MySQL        ║ MySQL             ║ 5.5.62     ║ 🔴 CRITICAL EOL, many CVEs      ║
╠════════╩══════════════╩═══════════════════╩════════════╩══════════════════════════════╣
║  Ports: 3   🔴 Critical: 1   🟠 High: 1   ⚠️  Medium: 0   Time: 1.24s              ║
```

### Port Scanner
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

### Host Discovery
```
╠══════════════════╬═══════════════════════════════════════════╣
║ Host             ║ Open Ports                                ║
╠══════════════════╬═══════════════════════════════════════════╣
║ 192.168.1.1      ║ 53(DNS) 80(HTTP)                         ║
║ 192.168.1.50     ║ 3306(MySQL)                              ║
║ 192.168.1.119    ║ 22(SSH)                                  ║
╠══════════════════╩═══════════════════════════════════════════╣
║  Alive: 3   Scanned: 254   Time: 10.83s                     ║
```

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

---

## 📁 Project Structure

```
storm/
├── src/
│   ├── Main.java                  # Unified interactive CLI & entry point
│   ├── FuzzerThread.java          # Directory fuzzing thread
│   ├── SubDomainFuzzer.java       # Subdomain enumeration thread
│   ├── RequestSender.java         # HTTP client (shared, HTTP/2)
│   ├── WorldListReader.java       # Wordlist loader & chunk splitter
│   ├── Logger.java                # Async non-blocking logger
│   ├── PortScanner.java           # Multithreaded port scanner & banner grabber
│   ├── HostDiscovery.java         # ICMP + TCP host discovery across subnets
│   └── ServiceFingerprinter.java  # Protocol-aware fingerprinter with CVE risk flags
├── common.txt                     # Directory wordlist
├── subdomains.txt                 # Subdomain wordlist
├── success.log                    # Generated at runtime
└── failed.log                     # Generated at runtime (if enabled)
```

---

## 🏗️ Architecture

```
Main (Interactive CLI)
 ├── WorldListReader      →  splits wordlist into N chunks
 ├── FuzzerThread × N     →  each thread hammers its chunk via RequestSender
 ├── SubDomainFuzzer × N  →  same but prepends word to domain
 └── Logger               →  single background writer drains BlockingQueue

PortScanner
 ├── buildThreads()       →  splits port range into N equal slices
 ├── ScannerThread × N    →  each extends Thread, scans its slice
 │    ├── isPortOpen()    →  TCP connect with configurable timeout
 │    └── grabBanner()    →  reads first response line from open port
 ├── AtomicInteger        →  thread-safe progress counter
 └── TreeMap (sync)       →  collects results sorted by port number

HostDiscovery
 ├── resolveTargets()          →  parses CIDR / IP range / single IP
 ├── buildThreads()            →  splits IP list into N slices
 └── DiscoveryThread × N      →  each extends Thread
      ├── icmpProbe()          →  InetAddress.isReachable()
      ├── tcpProbe()           →  TCP fallback on 80,443,22,21,8080
      └── miniPortScan()       →  checks 18 common ports on live hosts

ServiceFingerprinter
 ├── buildThreads()            →  splits port list across threads
 └── FingerprintThread × N    →  each extends Thread
      ├── probeSSH()           →  parses SSH banner, checks OpenSSH version
      ├── probeFTP()           →  reads 220 greeting, detects vsFTPD backdoor
      ├── probeHTTP/HTTPS()    →  full GET request, parses Server: header
      ├── probeMySQL()         →  reads raw binary handshake packet
      ├── probeSMB/RDP/VNC()   →  connect + known risk flags
      └── assessX()            →  cross-references version against risk table
```

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