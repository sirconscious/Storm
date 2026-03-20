import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.atomic.*;

/**
 * HostDiscovery — Multithreaded network host discovery tool.
 *
 * Discovery method:
 *   1. ICMP ping via InetAddress.isReachable()
 *   2. If ICMP fails → TCP connect fallback on common ports (80, 443, 22, 21, 8080)
 *   3. If either succeeds → host is marked alive → mini port scan runs
 *
 * Usage:
 *   java HostDiscovery <target> [threads] [timeoutMs]
 *
 * Target formats:
 *   CIDR range  →  192.168.1.0/24
 *   IP range    →  192.168.1.1-192.168.1.254
 *   Single IP   →  192.168.1.1
 *
 * Examples:
 *   java HostDiscovery 192.168.1.0/24
 *   java HostDiscovery 192.168.1.1-192.168.1.50 50 300
 *   java HostDiscovery 192.168.1.1
 */
public class HostDiscovery {

    // ─── Common ports used for TCP fallback & mini scan ───────────────────────
    private static final int[] COMMON_PORTS = {
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
            443, 445, 3306, 3389, 5900, 8080, 8443, 8888
    };

    // ─── Shared state ──────────────────────────────────────────────────────────
    private static final Map<String, List<Integer>> aliveHosts =
            Collections.synchronizedMap(new LinkedHashMap<>());

    private static final AtomicInteger scannedCount = new AtomicInteger(0);
    private static int totalHosts = 0;

    // ─── DiscoveryThread ───────────────────────────────────────────────────────

    static class DiscoveryThread extends Thread {

        private final List<String> ipSlice;
        private final int timeoutMs;

        DiscoveryThread(List<String> ipSlice, int timeoutMs) {
            this.ipSlice   = ipSlice;
            this.timeoutMs = timeoutMs;
        }

        @Override
        public void run() {
            for (String ip : ipSlice) {
                boolean alive = icmpProbe(ip) || tcpProbe(ip);

                if (alive) {
                    List<Integer> openPorts = miniPortScan(ip);
                    aliveHosts.put(ip, openPorts);
                }

                int done = scannedCount.incrementAndGet();
                printProgress(done, totalHosts);
            }
        }

        // ── 1. ICMP ping ───────────────────────────────────────────────────────

        private boolean icmpProbe(String ip) {
            try {
                InetAddress addr = InetAddress.getByName(ip);
                return addr.isReachable(timeoutMs);
            } catch (Exception e) {
                return false;
            }
        }

        // ── 2. TCP fallback — try common ports ─────────────────────────────────

        private boolean tcpProbe(String ip) {
            for (int port : new int[]{80, 443, 22, 21, 8080}) {
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress(ip, port), timeoutMs);
                    return true; // any one port responding = host is alive
                } catch (Exception ignored) {}
            }
            return false;
        }

        // ── 3. Mini port scan on discovered hosts ──────────────────────────────

        private List<Integer> miniPortScan(String ip) {
            List<Integer> open = new ArrayList<>();
            for (int port : COMMON_PORTS) {
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress(ip, port), timeoutMs);
                    open.add(port);
                } catch (Exception ignored) {}
            }
            return open;
        }
    }

    // ─── Progress bar ──────────────────────────────────────────────────────────

    private static void printProgress(int done, int total) {
        int    barWidth = 40;
        double pct      = (double) done / total;
        int    filled   = (int) (pct * barWidth);

        StringBuilder bar = new StringBuilder("[");
        for (int i = 0; i < barWidth; i++) bar.append(i < filled ? "█" : "░");
        bar.append("]");

        System.out.printf("\r  %s  %5.1f%%  (%d / %d hosts)", bar, pct * 100, done, total);
        System.out.flush();
    }

    // ─── Input parsers ─────────────────────────────────────────────────────────

    /** 192.168.1.0/24  →  list of all host IPs in that subnet */
    private static List<String> parseCidr(String cidr) throws Exception {
        String[] parts   = cidr.split("/");
        String   baseIp  = parts[0];
        int      prefix  = Integer.parseInt(parts[1]);

        int totalBits  = 32 - prefix;
        int hostCount  = (int) Math.pow(2, totalBits);
        long baseInt   = ipToLong(baseIp) & (0xFFFFFFFFL << totalBits);

        List<String> ips = new ArrayList<>();
        // skip network address (i=0) and broadcast (i=hostCount-1)
        for (int i = 1; i < hostCount - 1; i++) {
            ips.add(longToIp(baseInt + i));
        }
        return ips;
    }

    /** 192.168.1.1-192.168.1.50  →  list of IPs in that range */
    private static List<String> parseRange(String range) throws Exception {
        String[] parts = range.split("-");
        long     start = ipToLong(parts[0].trim());
        long     end   = ipToLong(parts[1].trim());

        List<String> ips = new ArrayList<>();
        for (long i = start; i <= end; i++) ips.add(longToIp(i));
        return ips;
    }

    private static long ipToLong(String ip) throws Exception {
        String[] o = ip.split("\\.");
        return (Long.parseLong(o[0]) << 24) | (Long.parseLong(o[1]) << 16)
                | (Long.parseLong(o[2]) << 8)  |  Long.parseLong(o[3]);
    }

    private static String longToIp(long ip) {
        return ((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "."
                + ((ip >> 8)  & 0xFF) + "." + (ip & 0xFF);
    }

    /** Detect format and return the full IP list */
    private static List<String> resolveTargets(String target) throws Exception {
        if (target.contains("/"))  return parseCidr(target);
        if (target.contains("-"))  return parseRange(target);
        return Collections.singletonList(target); // single IP
    }

    // ─── Thread builder — split IP list evenly across threads ──────────────────

    private static List<DiscoveryThread> buildThreads(
            List<String> ips, int numThreads, int timeoutMs) {

        int actual         = Math.min(numThreads, ips.size());
        int hostsPerThread = ips.size() / actual;
        int remainder      = ips.size() % actual;

        List<DiscoveryThread> threads = new ArrayList<>();
        int cursor = 0;

        for (int i = 0; i < actual; i++) {
            int slice = hostsPerThread + (i < remainder ? 1 : 0);
            List<String> chunk = new ArrayList<>(ips.subList(cursor, cursor + slice));
            threads.add(new DiscoveryThread(chunk, timeoutMs));
            cursor += slice;
        }
        return threads;
    }

    // ─── Results printer ──────────────────────────────────────────────────────

    private static String getServiceName(int port) {
        switch (port) {
            case 21:   return "FTP";
            case 22:   return "SSH";
            case 23:   return "Telnet";
            case 25:   return "SMTP";
            case 53:   return "DNS";
            case 80:   return "HTTP";
            case 110:  return "POP3";
            case 135:  return "RPC";
            case 139:  return "NetBIOS";
            case 143:  return "IMAP";
            case 443:  return "HTTPS";
            case 445:  return "SMB";
            case 3306: return "MySQL";
            case 3389: return "RDP";
            case 5900: return "VNC";
            case 8080: return "HTTP-Alt";
            case 8443: return "HTTPS-Alt";
            case 8888: return "HTTP-Alt";
            default:   return "Unknown";
        }
    }

    private static void printResults(String target, long elapsedMs) {
        System.out.println("\n");
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.printf ("║  Host Discovery Results — %-36s║%n", target);
        System.out.println("╠══════════════════╦═══════════════════════════════════════════╣");
        System.out.println("║ Host             ║ Open Ports                                ║");
        System.out.println("╠══════════════════╬═══════════════════════════════════════════╣");

        if (aliveHosts.isEmpty()) {
            System.out.println("║  No live hosts found.                                         ║");
        } else {
            for (Map.Entry<String, List<Integer>> entry : aliveHosts.entrySet()) {
                String ip    = entry.getKey();
                List<Integer> ports = entry.getValue();

                // Build port string: "80(HTTP) 443(HTTPS) 22(SSH)"
                StringBuilder portStr = new StringBuilder();
                if (ports.isEmpty()) {
                    portStr.append("alive — no common ports open");
                } else {
                    for (int port : ports) {
                        portStr.append(port).append("(").append(getServiceName(port)).append(") ");
                    }
                }

                String portDisplay = portStr.toString().trim();
                if (portDisplay.length() > 41) portDisplay = portDisplay.substring(0, 41) + "…";
                System.out.printf("║ %-16s ║ %-41s ║%n", ip, portDisplay);
            }
        }

        System.out.println("╠══════════════════╩═══════════════════════════════════════════╣");
        System.out.printf ("║  Alive: %-4d  Scanned: %-4d  Time: %-22s║%n",
                aliveHosts.size(), totalHosts,
                String.format("%.2fs", elapsedMs / 1000.0));
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    // ─── main ─────────────────────────────────────────────────────────────────

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java HostDiscovery <target> [threads] [timeoutMs]");
            System.out.println();
            System.out.println("  Target formats:");
            System.out.println("    CIDR   →  192.168.1.0/24");
            System.out.println("    Range  →  192.168.1.1-192.168.1.254");
            System.out.println("    Single →  192.168.1.1");
            System.out.println();
            System.out.println("  Defaults: threads=50  timeoutMs=300");
            System.exit(1);
        }

        String target    = args[0];
        int    threads   = args.length >= 2 ? Integer.parseInt(args[1]) : 50;
        int    timeoutMs = args.length >= 3 ? Integer.parseInt(args[2]) : 300;

        List<String> ips;
        try {
            ips = resolveTargets(target);
        } catch (Exception e) {
            System.err.println("Invalid target format: " + e.getMessage());
            System.exit(1);
            return;
        }

        totalHosts = ips.size();

        System.out.println();
        System.out.printf("  Target  : %s%n", target);
        System.out.printf("  Hosts   : %d%n", totalHosts);
        System.out.printf("  Threads : %d%n", threads);
        System.out.printf("  Timeout : %d ms%n", timeoutMs);
        System.out.printf("  Method  : ICMP ping → TCP fallback (80,443,22,21,8080)%n");
        System.out.println();

        List<DiscoveryThread> threadList = buildThreads(ips, threads, timeoutMs);

        long start = System.currentTimeMillis();
        for (DiscoveryThread t : threadList) t.start();
        for (DiscoveryThread t : threadList) {
            try { t.join(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        long elapsed = System.currentTimeMillis() - start;

        printResults(target, elapsed);
    }
}