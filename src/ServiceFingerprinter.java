import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.atomic.*;

/**
 * ServiceFingerprinter — Identifies software and versions on open ports.
 *
 * How it works:
 *   1. Takes a list of open ports (from PortScanner or HostDiscovery)
 *   2. Sends a protocol-specific probe to each port
 *   3. Parses the response to extract software name + version
 *   4. Cross-references against a built-in risk table
 *   5. Prints an enriched results table with risk flags
 *
 * Usage (standalone):
 *   java ServiceFingerprinter <host> <port1,port2,...> [timeoutMs]
 *
 * Examples:
 *   java ServiceFingerprinter 192.168.100.119 22,80,443
 *   java ServiceFingerprinter 192.168.100.50 3306 1000
 *   java ServiceFingerprinter scanme.nmap.org 22,80
 */
public class ServiceFingerprinter {

    // ─── Risk levels ───────────────────────────────────────────────────────────
    static final String RISK_CRITICAL = "🔴 CRITICAL";
    static final String RISK_HIGH     = "🟠 HIGH    ";
    static final String RISK_MEDIUM   = "⚠️  MEDIUM  ";
    static final String RISK_LOW      = "🔵 LOW     ";
    static final String RISK_OK       = "✅ OK      ";
    static final String RISK_UNKNOWN  = "❓ UNKNOWN ";

    // ─── Shared state ──────────────────────────────────────────────────────────
    static final List<FingerprintResult> results =
            Collections.synchronizedList(new ArrayList<>());

    static final AtomicInteger scannedCount = new AtomicInteger(0);
    static int totalPorts = 0;

    // ─── Result record ─────────────────────────────────────────────────────────
    static class FingerprintResult {
        int    port;
        String serviceName;
        String software;
        String version;
        String osHint;
        String rawBanner;
        String risk;
        String riskDetail;

        FingerprintResult(int port) {
            this.port        = port;
            this.serviceName = "Unknown";
            this.software    = "?";
            this.version     = "?";
            this.osHint      = "";
            this.rawBanner   = "";
            this.risk        = RISK_UNKNOWN;
            this.riskDetail  = "Could not fingerprint";
        }
    }

    // ─── FingerprintThread ─────────────────────────────────────────────────────

    static class FingerprintThread extends Thread {

        private final String host;
        private final List<Integer> ports;
        private final int timeoutMs;

        FingerprintThread(String host, List<Integer> ports, int timeoutMs) {
            this.host      = host;
            this.ports     = ports;
            this.timeoutMs = timeoutMs;
        }

        @Override
        public void run() {
            for (int port : ports) {
                FingerprintResult result = fingerprint(host, port);
                results.add(result);
                int done = scannedCount.incrementAndGet();
                printProgress(done, totalPorts);
            }
        }

        // ── Main fingerprint dispatcher ────────────────────────────────────────

        private FingerprintResult fingerprint(String host, int port) {
            FingerprintResult result = new FingerprintResult(port);

            // Route to the right probe based on port number
            switch (port) {
                case 21          -> probeFTP(host, port, result);
                case 22          -> probeSSH(host, port, result);
                case 23          -> probeTelnet(host, port, result);
                case 25, 587     -> probeSMTP(host, port, result);
                case 53          -> probeDNS(host, port, result);
                case 80, 8080,
                     8888        -> probeHTTP(host, port, result);
                case 110         -> probePOP3(host, port, result);
                case 143         -> probeIMAP(host, port, result);
                case 443, 8443   -> probeHTTPS(host, port, result);
                case 445         -> probeSMB(host, port, result);
                case 3306        -> probeMySQL(host, port, result);
                case 3389        -> probeRDP(host, port, result);
                case 5900        -> probeVNC(host, port, result);
                default          -> probeGeneric(host, port, result);
            }

            return result;
        }

        // ══════════════════════════════════════════════════════════════════════
        //   PROTOCOL PROBES
        // ══════════════════════════════════════════════════════════════════════

        // ── SSH ────────────────────────────────────────────────────────────────
        // SSH servers speak first — they send their version string immediately
        // Format: SSH-<protocol>-<software>_<version> <optional comment>
        private void probeSSH(String host, int port, FingerprintResult r) {
            r.serviceName = "SSH";
            String banner = readBanner(host, port, null);
            if (banner == null) return;

            r.rawBanner = banner;
            // e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
            if (banner.startsWith("SSH-")) {
                String[] parts = banner.split("-", 3);
                if (parts.length >= 3) {
                    String[] softParts = parts[2].split("_", 2);
                    r.software = softParts[0];                              // "OpenSSH"
                    r.version  = softParts.length > 1
                            ? softParts[1].split(" ")[0] : "?";            // "8.9p1"

                    // OS hint from the comment part
                    if (banner.contains(" ")) {
                        r.osHint = banner.substring(banner.indexOf(" ") + 1); // "Ubuntu-3ubuntu0.6"
                    }
                }
            }
            assessSSH(r);
        }

        private void assessSSH(FingerprintResult r) {
            if (r.software.equalsIgnoreCase("OpenSSH")) {
                double v = parseVersion(r.version);
                if (v > 0 && v < 4.4) {
                    r.risk       = RISK_CRITICAL;
                    r.riskDetail = "OpenSSH < 4.4 — remote code execution vulnerabilities";
                } else if (v < 7.0) {
                    r.risk       = RISK_HIGH;
                    r.riskDetail = "OpenSSH < 7.0 — CVE-2016-6515 (DoS), weak algorithms";
                } else if (v < 8.0) {
                    r.risk       = RISK_MEDIUM;
                    r.riskDetail = "OpenSSH < 8.0 — CVE-2018-15473 (user enumeration)";
                } else {
                    r.risk       = RISK_OK;
                    r.riskDetail = "Version looks current";
                }
            } else if (r.software.equalsIgnoreCase("dropbear")) {
                r.risk       = RISK_MEDIUM;
                r.riskDetail = "Dropbear SSH — common on embedded/IoT devices";
            } else {
                r.risk       = RISK_UNKNOWN;
                r.riskDetail = "Unknown SSH implementation";
            }

            // DSS flag — always bad
            if (r.rawBanner.toLowerCase().contains("dss")) {
                r.risk       = RISK_HIGH;
                r.riskDetail = "ssh-dss enabled — algorithm deprecated since 2015";
            }
        }

        // ── FTP ────────────────────────────────────────────────────────────────
        // FTP servers speak first with a 220 greeting
        // Format: "220 ProFTPD 1.3.5 Server (hostname) [ip]"
            private void probeFTP(String host, int port, FingerprintResult r) {
            r.serviceName = "FTP";
            String banner = readBanner(host, port, null);
            if (banner == null) return;

            r.rawBanner = banner;
            // e.g. "220 ProFTPD 1.3.5 Server"
            //      "220 vsFTPd 3.0.3"
            //      "220 FileZilla Server 0.9.60"
            String[] tokens = banner.replaceFirst("^220[-\\s]", "").trim().split("\\s+");
            if (tokens.length >= 2) {
                r.software = tokens[0];
                r.version  = tokens[1];
            }
            assessFTP(r);
        }

        private void assessFTP(FingerprintResult r) {
            String sw = r.software.toLowerCase();
            double v  = parseVersion(r.version);

            if (sw.contains("proftpd")) {
                if (v > 0 && v < 1.3) {
                    r.risk = RISK_CRITICAL; r.riskDetail = "ProFTPD < 1.3 — remote root exploit";
                } else if (v < 1.35) {
                    r.risk = RISK_HIGH; r.riskDetail = "ProFTPD 1.3.x — CVE-2010-4221 buffer overflow";
                } else {
                    r.risk = RISK_LOW; r.riskDetail = "ProFTPD — check config for anonymous access";
                }
            } else if (sw.contains("vsftpd")) {
                if (r.version.equals("2.3.4")) {
                    r.risk = RISK_CRITICAL; r.riskDetail = "vsFTPD 2.3.4 — backdoor (CVE-2011-2523) !!!";
                } else {
                    r.risk = RISK_LOW; r.riskDetail = "vsFTPD — generally secure, verify anonymous login";
                }
            } else {
                r.risk = RISK_MEDIUM; r.riskDetail = "FTP transmits credentials in plaintext";
            }
        }

        // ── SMTP ───────────────────────────────────────────────────────────────
        private void probeSMTP(String host, int port, FingerprintResult r) {
            r.serviceName = "SMTP";
            String banner = readBanner(host, port, null);
            if (banner == null) return;

            r.rawBanner = banner;
            // e.g. "220 mail.example.com ESMTP Postfix (Ubuntu)"
            String lower = banner.toLowerCase();
            if (lower.contains("postfix"))  { r.software = "Postfix";  extractVersionAfter(r, "postfix"); }
            else if (lower.contains("exim")) { r.software = "Exim";     extractVersionAfter(r, "exim"); }
            else if (lower.contains("sendmail")) { r.software = "Sendmail"; }
            else if (lower.contains("exchange")) { r.software = "Exchange"; }
            else { r.software = "Unknown SMTP"; }

            r.risk       = RISK_LOW;
            r.riskDetail = "SMTP — verify relay config and TLS enforcement";
        }

        // ── HTTP ───────────────────────────────────────────────────────────────
        // We send a full HTTP request and parse the Server: header
        private void probeHTTP(String host, int port, FingerprintResult r) {
            r.serviceName = "HTTP";
            String probe  = "GET / HTTP/1.0\r\nHost: " + host + "\r\n\r\n";
            String banner = readBanner(host, port, probe);
            if (banner == null) return;

            r.rawBanner = banner;

            // Try to read Server: header by making a full request
            String serverHeader = fetchHeader(host, port, false);
            if (serverHeader != null) {
                r.rawBanner = serverHeader;
                parseServerHeader(serverHeader, r);
            } else {
                // Fallback: parse status line
                if (banner.startsWith("HTTP/")) {
                    r.software = "HTTP Server";
                    r.version  = banner.split(" ")[0]; // "HTTP/1.1"
                }
            }
            assessHTTP(r);
        }

        // ── HTTPS ──────────────────────────────────────────────────────────────
        private void probeHTTPS(String host, int port, FingerprintResult r) {
            r.serviceName = "HTTPS";
            String serverHeader = fetchHeader(host, port, true);
            if (serverHeader != null) {
                r.rawBanner = serverHeader;
                parseServerHeader(serverHeader, r);
            } else {
                r.software   = "HTTPS Server";
                r.risk       = RISK_LOW;
                r.riskDetail = "HTTPS — TLS in use, check certificate validity";
                return;
            }
            assessHTTP(r);
        }

        private void parseServerHeader(String header, FingerprintResult r) {
            // e.g. "nginx/1.18.0", "Apache/2.4.41 (Ubuntu)", "Microsoft-IIS/10.0"
            String lower = header.toLowerCase();
            if (lower.startsWith("nginx")) {
                r.software = "nginx";
                r.version  = header.contains("/") ? header.split("/")[1].split(" ")[0] : "?";
            } else if (lower.startsWith("apache")) {
                r.software = "Apache";
                r.version  = header.contains("/") ? header.split("/")[1].split(" ")[0] : "?";
                if (header.contains("(")) {
                    r.osHint = header.replaceAll(".*\\((.*)\\).*", "$1");
                }
            } else if (lower.contains("iis")) {
                r.software = "Microsoft-IIS";
                r.version  = header.contains("/") ? header.split("/")[1].split(" ")[0] : "?";
                r.osHint   = "Windows";
            } else if (lower.contains("cloudflare")) {
                r.software   = "Cloudflare";
                r.risk       = RISK_OK;
                r.riskDetail = "Behind Cloudflare CDN";
                return;
            } else if (lower.contains("lighttpd")) {
                r.software = "lighttpd";
                r.version  = header.contains("/") ? header.split("/")[1].split(" ")[0] : "?";
            } else {
                r.software = header.split("/")[0];
                r.version  = header.contains("/") ? header.split("/")[1].split(" ")[0] : "?";
            }
        }

        private void assessHTTP(FingerprintResult r) {
            String sw = r.software.toLowerCase();
            double v  = parseVersion(r.version);

            if (sw.equals("apache")) {
                if (v > 0 && v < 2.2) {
                    r.risk = RISK_CRITICAL; r.riskDetail = "Apache < 2.2 — severely outdated, many CVEs";
                } else if (v < 2.4) {
                    r.risk = RISK_HIGH; r.riskDetail = "Apache 2.2.x — EOL, multiple vulnerabilities";
                } else if (v < 2.4 + 0.50) {
                    r.risk = RISK_MEDIUM; r.riskDetail = "Apache 2.4.x — check for latest patch";
                } else {
                    r.risk = RISK_OK; r.riskDetail = "Apache — version looks current";
                }
            } else if (sw.equals("nginx")) {
                if (v > 0 && v < 1.14) {
                    r.risk = RISK_HIGH; r.riskDetail = "nginx < 1.14 — CVE-2017-7529 memory disclosure";
                } else {
                    r.risk = RISK_OK; r.riskDetail = "nginx — version looks current";
                }
            } else if (sw.equals("microsoft-iis")) {
                if (v > 0 && v < 8.5) {
                    r.risk = RISK_HIGH; r.riskDetail = "IIS < 8.5 — outdated, check Windows patching";
                } else {
                    r.risk = RISK_LOW; r.riskDetail = "IIS — ensure Windows Updates are current";
                }
            } else {
                r.risk = RISK_LOW; r.riskDetail = "HTTP — verify server is patched";
            }
        }

        // ── MySQL ──────────────────────────────────────────────────────────────
        // MySQL sends a binary handshake packet immediately on connect.
        // Bytes: [4-byte packet header][1-byte protocol][null-terminated version string]
        private void probeMySQL(String host, int port, FingerprintResult r) {
            r.serviceName = "MySQL";
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), timeoutMs);
                socket.setSoTimeout(timeoutMs);

                InputStream in = socket.getInputStream();
                byte[] buf = new byte[256];
                int    len = in.read(buf);
                if (len < 6) return;

                // Skip 4-byte packet length header + 1-byte protocol version
                // Then read null-terminated version string starting at byte 5
                StringBuilder version = new StringBuilder();
                for (int i = 5; i < len; i++) {
                    if (buf[i] == 0) break; // null terminator
                    version.append((char) buf[i]);
                }

                r.version   = version.toString(); // e.g. "8.0.32" or "5.5.62-MariaDB"
                r.rawBanner = r.version;

                if (r.version.toLowerCase().contains("mariadb")) {
                    r.software = "MariaDB";
                } else {
                    r.software = "MySQL";
                }

                assessMySQL(r, buf, len);

            } catch (Exception e) {
                r.riskDetail = "Could not read MySQL handshake";
            }
        }

        private void assessMySQL(FingerprintResult r, byte[] buf, int len) {
            double v = parseVersion(r.version);

            // Check capability flags for auth requirement
            // Bytes 18-19 in the handshake contain capability flags
            boolean hasAuth = len > 19 && (buf[18] & 0x08) != 0;

            if (!hasAuth) {
                r.risk       = RISK_CRITICAL;
                r.riskDetail = "MySQL accepting unauthenticated connections!";
                return;
            }

            if (r.software.equals("MySQL")) {
                if (v > 0 && v < 5.6) {
                    r.risk = RISK_CRITICAL; r.riskDetail = "MySQL < 5.6 — EOL, many unpatched CVEs";
                } else if (v < 5.7) {
                    r.risk = RISK_HIGH; r.riskDetail = "MySQL 5.6 — EOL since 2021";
                } else if (v < 8.0) {
                    r.risk = RISK_MEDIUM; r.riskDetail = "MySQL 5.7 — EOL since 2023";
                } else {
                    r.risk = RISK_OK; r.riskDetail = "MySQL 8.x — check latest patch level";
                }
            } else {
                r.risk = RISK_LOW; r.riskDetail = "MariaDB — verify version is supported";
            }
        }

        // ── Telnet ─────────────────────────────────────────────────────────────
        private void probeTelnet(String host, int port, FingerprintResult r) {
            r.serviceName = "Telnet";
            r.software    = "Telnet";
            r.version     = "N/A";
            r.risk        = RISK_CRITICAL;
            r.riskDetail  = "Telnet transmits EVERYTHING in plaintext including passwords!";
            String banner = readBanner(host, port, null);
            if (banner != null) r.rawBanner = banner;
        }

        // ── POP3 ───────────────────────────────────────────────────────────────
        private void probePOP3(String host, int port, FingerprintResult r) {
            r.serviceName = "POP3";
            String banner = readBanner(host, port, null);
            if (banner == null) return;
            r.rawBanner   = banner;
            // e.g. "+OK Dovecot ready"
            String lower = banner.toLowerCase();
            if      (lower.contains("dovecot"))  r.software = "Dovecot";
            else if (lower.contains("courier"))  r.software = "Courier";
            else if (lower.contains("exchange")) r.software = "Exchange";
            else                                 r.software = "POP3 Server";
            r.risk       = RISK_MEDIUM;
            r.riskDetail = "POP3 — use POP3S (port 995) instead";
        }

        // ── IMAP ───────────────────────────────────────────────────────────────
        private void probeIMAP(String host, int port, FingerprintResult r) {
            r.serviceName = "IMAP";
            String banner = readBanner(host, port, null);
            if (banner == null) return;
            r.rawBanner   = banner;
            String lower  = banner.toLowerCase();
            if      (lower.contains("dovecot"))  r.software = "Dovecot";
            else if (lower.contains("courier"))  r.software = "Courier";
            else if (lower.contains("exchange")) r.software = "Exchange";
            else                                 r.software = "IMAP Server";
            r.risk       = RISK_MEDIUM;
            r.riskDetail = "IMAP — use IMAPS (port 993) instead";
        }

        // ── SMB ────────────────────────────────────────────────────────────────
        private void probeSMB(String host, int port, FingerprintResult r) {
            r.serviceName = "SMB";
            r.software    = "SMB/Samba";
            r.risk        = RISK_HIGH;
            r.riskDetail  = "SMB exposed — check for EternalBlue (MS17-010) if Windows";
            r.rawBanner   = "SMB port open — no safe banner grab";
        }

        // ── RDP ────────────────────────────────────────────────────────────────
        private void probeRDP(String host, int port, FingerprintResult r) {
            r.serviceName = "RDP";
            r.software    = "Remote Desktop";
            r.osHint      = "Windows";
            r.risk        = RISK_HIGH;
            r.riskDetail  = "RDP exposed — BlueKeep (CVE-2019-0708) if unpatched Windows 7/2008";
            r.rawBanner   = "RDP port open";
        }

        // ── VNC ────────────────────────────────────────────────────────────────
        private void probeVNC(String host, int port, FingerprintResult r) {
            r.serviceName = "VNC";
            String banner = readBanner(host, port, null);
            if (banner != null) {
                r.rawBanner = banner;
                // e.g. "RFB 003.008" — RFB is the VNC protocol
                if (banner.startsWith("RFB")) {
                    r.software = "VNC";
                    r.version  = banner.replace("RFB ", "").trim();
                }
            }
            r.risk       = RISK_HIGH;
            r.riskDetail = "VNC exposed — ensure strong password and consider tunneling over SSH";
        }

        // ── DNS ────────────────────────────────────────────────────────────────
        private void probeDNS(String host, int port, FingerprintResult r) {
            r.serviceName = "DNS";
            r.software    = "DNS Server";
            r.risk        = RISK_LOW;
            r.riskDetail  = "DNS — verify recursion is restricted to authorized clients";
            r.rawBanner   = "DNS port open (UDP/TCP)";
        }

        // ── Generic fallback ───────────────────────────────────────────────────
        private void probeGeneric(String host, int port, FingerprintResult r) {
            r.serviceName = knownServiceName(port);
            String banner = readBanner(host, port, "\r\n");
            if (banner != null && !banner.isEmpty()) {
                r.rawBanner = banner;
                r.software  = "Unknown";
                r.version   = "?";
                r.risk      = RISK_UNKNOWN;
                r.riskDetail = "Unrecognized service — manual investigation recommended";
            }
        }

        // ══════════════════════════════════════════════════════════════════════
        //   NETWORK HELPERS
        // ══════════════════════════════════════════════════════════════════════

        /** Connect to port, optionally send a probe, read the first line back */
        private String readBanner(String host, int port, String probe) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), timeoutMs);
                socket.setSoTimeout(timeoutMs);

                if (probe != null) {
                    socket.getOutputStream().write(probe.getBytes());
                    socket.getOutputStream().flush();
                }

                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));
                String line = reader.readLine();
                if (line != null) {
                    line = line.replaceAll("[^\\x20-\\x7E]", "").trim();
                }
                return line;
            } catch (Exception e) {
                return null;
            }
        }

        /** Fetch the Server: header from an HTTP/HTTPS response */
        private String fetchHeader(String host, int port, boolean https) {
            try {
                java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder()
                        .connectTimeout(java.time.Duration.ofMillis(timeoutMs))
                        .followRedirects(java.net.http.HttpClient.Redirect.NEVER)
                        .build();

                String url = (https ? "https" : "http") + "://" + host +
                        (port != 80 && port != 443 ? ":" + port : "") + "/";

                java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                        .uri(java.net.URI.create(url))
                        .timeout(java.time.Duration.ofMillis(timeoutMs))
                        .header("User-Agent", "Mozilla/5.0")
                        .GET()
                        .build();

                java.net.http.HttpResponse<Void> resp =
                        client.send(req, java.net.http.HttpResponse.BodyHandlers.discarding());

                return resp.headers().firstValue("server").orElse(null);

            } catch (Exception e) {
                return null;
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //   THREAD BUILDER
    // ══════════════════════════════════════════════════════════════════════════

    static List<FingerprintThread> buildThreads(
            String host, List<Integer> ports, int numThreads, int timeoutMs) {

        int actual       = Math.min(numThreads, ports.size());
        int portsPerT    = ports.size() / actual;
        int remainder    = ports.size() % actual;

        List<FingerprintThread> threads = new ArrayList<>();
        int cursor = 0;

        for (int i = 0; i < actual; i++) {
            int slice = portsPerT + (i < remainder ? 1 : 0);
            List<Integer> chunk = new ArrayList<>(ports.subList(cursor, cursor + slice));
            threads.add(new FingerprintThread(host, chunk, timeoutMs));
            cursor += slice;
        }
        return threads;
    }

    // ══════════════════════════════════════════════════════════════════════════
    //   PROGRESS BAR
    // ══════════════════════════════════════════════════════════════════════════

    static void printProgress(int done, int total) {
        int    barWidth = 40;
        double pct      = (double) done / total;
        int    filled   = (int) (pct * barWidth);
        StringBuilder bar = new StringBuilder("[");
        for (int i = 0; i < barWidth; i++) bar.append(i < filled ? "█" : "░");
        bar.append("]");
        System.out.printf("\r  %s  %5.1f%%  (%d / %d ports)", bar, pct * 100, done, total);
        System.out.flush();
    }

    // ══════════════════════════════════════════════════════════════════════════
    //   RESULTS PRINTER
    // ══════════════════════════════════════════════════════════════════════════

    static void printResults(String host, long elapsedMs) {
        // Sort by port number
        results.sort(Comparator.comparingInt(r -> r.port));

        System.out.println("\n");
        System.out.println("╔══════════════════════════════════════════════════════════════════════════════════════╗");
        System.out.printf ("║  Service Fingerprint Results — %-54s║%n", host);
        System.out.println("╠════════╦══════════════╦═══════════════════╦════════════╦══════════════════════════════╣");
        System.out.println("║ Port   ║ Service      ║ Software          ║ Version    ║ Risk                         ║");
        System.out.println("╠════════╬══════════════╬═══════════════════╬════════════╬══════════════════════════════╣");

        int critical = 0, high = 0, medium = 0;

        for (FingerprintResult r : results) {
            String version = r.version.length() > 10 ? r.version.substring(0, 10) : r.version;
            String detail  = r.riskDetail.length() > 28 ? r.riskDetail.substring(0, 28) + "…" : r.riskDetail;
            String risk    = r.risk;

            System.out.printf("║ %-6d ║ %-12s ║ %-17s ║ %-10s ║ %s %-19s║%n",
                    r.port, r.serviceName, r.software, version, risk, detail);

            if (risk.contains("CRITICAL")) critical++;
            else if (risk.contains("HIGH"))     high++;
            else if (risk.contains("MEDIUM"))   medium++;
        }

        System.out.println("╠════════╩══════════════╩═══════════════════╩════════════╩══════════════════════════════╣");
        System.out.printf ("║  Ports: %-3d  🔴 Critical: %-3d  🟠 High: %-3d  ⚠️  Medium: %-3d  Time: %-10s║%n",
                results.size(), critical, high, medium,
                String.format("%.2fs", elapsedMs / 1000.0));
        System.out.println("╚══════════════════════════════════════════════════════════════════════════════════════╝");

        // Print detailed findings for anything not OK
        boolean hasFindings = results.stream().anyMatch(r ->
                !r.risk.equals(RISK_OK) && !r.risk.equals(RISK_LOW));

        if (hasFindings) {
            System.out.println("\n  ── Detailed Findings ────────────────────────────────────────");
            for (FingerprintResult r : results) {
                if (r.risk.equals(RISK_OK) || r.risk.equals(RISK_LOW)) continue;
                System.out.printf("  %s  Port %-5d (%s %s)%n",
                        r.risk, r.port, r.software, r.version);
                System.out.printf("         └─ %s%n", r.riskDetail);
                if (!r.rawBanner.isEmpty()) {
                    System.out.printf("         └─ Banner: %s%n", r.rawBanner);
                }
                if (!r.osHint.isEmpty()) {
                    System.out.printf("         └─ OS Hint: %s%n", r.osHint);
                }
                System.out.println();
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //   UTILITY HELPERS
    // ══════════════════════════════════════════════════════════════════════════

    /** Parse first numeric part of a version string: "8.9p1" → 8.9 */
    static double parseVersion(String version) {
        try {
            String cleaned = version.replaceAll("[^0-9.]", ".");
            String[] parts = cleaned.split("\\.");
            if (parts.length >= 2) {
                return Double.parseDouble(parts[0] + "." + parts[1]);
            } else if (parts.length == 1 && !parts[0].isEmpty()) {
                return Double.parseDouble(parts[0]);
            }
        } catch (Exception ignored) {}
        return -1;
    }

    /** Extract version string that appears after a keyword */
    static void extractVersionAfter(FingerprintResult r, String keyword) {
        String lower = r.rawBanner.toLowerCase();
        int idx = lower.indexOf(keyword);
        if (idx >= 0) {
            String after = r.rawBanner.substring(idx + keyword.length()).trim();
            String[] parts = after.split("\\s+");
            if (parts.length > 0) r.version = parts[0];
        }
    }

    /** Map well-known port numbers to service names */
    static String knownServiceName(int port) {
        return switch (port) {
            case 21   -> "FTP";
            case 22   -> "SSH";
            case 23   -> "Telnet";
            case 25   -> "SMTP";
            case 53   -> "DNS";
            case 80   -> "HTTP";
            case 110  -> "POP3";
            case 135  -> "RPC";
            case 139  -> "NetBIOS";
            case 143  -> "IMAP";
            case 443  -> "HTTPS";
            case 445  -> "SMB";
            case 587  -> "SMTP";
            case 993  -> "IMAPS";
            case 995  -> "POP3S";
            case 1433 -> "MSSQL";
            case 3306 -> "MySQL";
            case 3389 -> "RDP";
            case 5432 -> "PostgreSQL";
            case 5900 -> "VNC";
            case 6379 -> "Redis";
            case 8080 -> "HTTP-Alt";
            case 8443 -> "HTTPS-Alt";
            case 8888 -> "HTTP-Alt";
            case 27017-> "MongoDB";
            default   -> "Unknown";
        };
    }

    // ══════════════════════════════════════════════════════════════════════════
    //   MAIN — standalone usage
    // ══════════════════════════════════════════════════════════════════════════

    public static void main(String[] args) throws InterruptedException {
        if (args.length < 2) {
            System.out.println("Usage: java ServiceFingerprinter <host> <port1,port2,...> [timeoutMs]");
            System.out.println("  Example: java ServiceFingerprinter 192.168.1.1 22,80,443,3306");
            System.exit(1);
        }

        String   host      = args[0];
        String[] portStrs  = args[1].split(",");
        int      timeoutMs = args.length >= 3 ? Integer.parseInt(args[2]) : 500;

        List<Integer> ports = new ArrayList<>();
        for (String p : portStrs) {
            try { ports.add(Integer.parseInt(p.trim())); }
            catch (NumberFormatException e) {
                System.err.println("  [!] Invalid port: " + p);
            }
        }

        if (ports.isEmpty()) {
            System.err.println("  [!] No valid ports provided.");
            System.exit(1);
        }

        totalPorts = ports.size();

        System.out.println();
        System.out.printf("  Target  : %s%n", host);
        System.out.printf("  Ports   : %s%n", args[1]);
        System.out.printf("  Timeout : %d ms%n%n", timeoutMs);

        List<FingerprintThread> threads = buildThreads(host, ports, ports.size(), timeoutMs);

        long start = System.currentTimeMillis();
        for (FingerprintThread t : threads) t.start();
        for (FingerprintThread t : threads) t.join();
        long elapsed = System.currentTimeMillis() - start;

        printResults(host, elapsed);
    }
}