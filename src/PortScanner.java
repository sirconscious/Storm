import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.atomic.*;

/**
 * PortScanner — Multi-threaded port scanner with banner grabbing.
 *
 * Usage:
 *   java PortScanner <host> <startPort> <endPort> [threads] [timeoutMs]
 *
 * Examples:
 *   java PortScanner 127.0.0.1 1 1024
 *   java PortScanner 192.168.1.1 1 65535 100 300
 */
public class PortScanner {

    // ─── Shared state across all scanner threads ───────────────────────────────

    /** Collects results: port → banner (or empty string) */
    private static final Map<Integer, String> results =
            Collections.synchronizedMap(new TreeMap<>());

    /** Tracks how many ports have been scanned so far (for progress bar) */
    private static final AtomicInteger scannedCount = new AtomicInteger(0);

    /** Total ports being scanned — set once before threads start */
    private static int totalPorts = 0;

    // ─── ScannerThread ─────────────────────────────────────────────────────────

    /**
     * Each ScannerThread owns a slice of the port range.
     * It scans every port in that slice, then grabs banners from open ones.
     */
    static class ScannerThread extends Thread {

        private final String host;
        private final int startPort;
        private final int endPort;
        private final int timeoutMs;

        ScannerThread(String host, int startPort, int endPort, int timeoutMs) {
            this.host      = host;
            this.startPort = startPort;
            this.endPort   = endPort;
            this.timeoutMs = timeoutMs;
        }

        @Override
        public void run() {
            for (int port = startPort; port <= endPort; port++) {
                if (isPortOpen(port)) {
                    String banner = grabBanner(port);
                    results.put(port, banner != null ? banner : "");
                }
                // Increment global counter and redraw the progress bar
                int done = scannedCount.incrementAndGet();
                printProgress(done, totalPorts);
            }
        }

        // ── TCP connect — returns true if port is open ──────────────────────

        private boolean isPortOpen(int port) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), timeoutMs);
                return true;
            } catch (Exception e) {
                return false;
            }
        }

        // ── Read the first line the service sends back ───────────────────────

        private String grabBanner(int port) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), timeoutMs);
                socket.setSoTimeout(timeoutMs);

                // Some services (HTTP, FTP, SSH, SMTP …) send a greeting immediately.
                // For others we send a newline to provoke a response.
                OutputStream out = socket.getOutputStream();
                out.write("\r\n".getBytes());
                out.flush();

                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));

                String line = reader.readLine();
                if (line != null) {
                    // Sanitise: strip non-printable chars and cap length
                    line = line.replaceAll("[^\\x20-\\x7E]", "").trim();
                    if (line.length() > 80) line = line.substring(0, 80) + "…";
                }
                return line;

            } catch (Exception e) {
                return null;   // service didn't respond — that's fine
            }
        }
    }

    // ─── Progress bar ──────────────────────────────────────────────────────────

    private static void printProgress(int done, int total) {
        int barWidth = 40;
        double pct    = (double) done / total;
        int    filled = (int) (pct * barWidth);

        StringBuilder bar = new StringBuilder("[");
        for (int i = 0; i < barWidth; i++) {
            bar.append(i < filled ? "█" : "░");
        }
        bar.append("]");

        // \r rewrites the same line in the terminal
        System.out.printf("\r  %s  %5.1f%%  (%d / %d ports)",
                bar, pct * 100, done, total);
        System.out.flush();
    }

    // ─── Port-range splitter ───────────────────────────────────────────────────

    /**
     * Divides [startPort, endPort] into (up to) numThreads contiguous slices
     * and returns one ScannerThread per slice.
     */
    private static List<ScannerThread> buildThreads(
            String host, int startPort, int endPort,
            int numThreads, int timeoutMs) {

        int portCount      = endPort - startPort + 1;
        // Never create more threads than there are ports
        int actualThreads  = Math.min(numThreads, portCount);
        int portsPerThread = portCount / actualThreads;
        int remainder      = portCount % actualThreads;

        List<ScannerThread> threads = new ArrayList<>();
        int current = startPort;

        for (int i = 0; i < actualThreads; i++) {
            // Distribute the remainder one port at a time to the first threads
            int slice = portsPerThread + (i < remainder ? 1 : 0);
            int from  = current;
            int to    = current + slice - 1;
            threads.add(new ScannerThread(host, from, to, timeoutMs));
            current = to + 1;
        }

        return threads;
    }

    // ─── Results printer ──────────────────────────────────────────────────────

    private static void printResults(String host, long elapsedMs) {
        System.out.println(); // end progress-bar line
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.printf ("║  Scan results for %-40s║%n", host);
        System.out.println("╠══════╦══════════════════════════════════════════════════╣");
        System.out.println("║ Port ║ Banner                                           ║");
        System.out.println("╠══════╬══════════════════════════════════════════════════╣");

        if (results.isEmpty()) {
            System.out.println("║  No open ports found.                                     ║");
        } else {
            for (Map.Entry<Integer, String> entry : results.entrySet()) {
                String banner = entry.getValue().isEmpty() ? "(no banner)" : entry.getValue();
                // Pad / truncate banner to fit the column
                if (banner.length() > 48) banner = banner.substring(0, 48);
                System.out.printf("║ %-4d ║ %-48s ║%n", entry.getKey(), banner);
            }
        }

        System.out.println("╠══════╩══════════════════════════════════════════════════╣");
        System.out.printf ("║  Open: %-3d   Time: %.2fs%-30s║%n",
                results.size(), elapsedMs / 1000.0, "");
        System.out.println("╚══════════════════════════════════════════════════════════╝");
    }

    // ─── main ─────────────────────────────────────────────────────────────────

    public static void main(String[] args) {

        // ── Argument parsing ─────────────────────────────────────────────────
        if (args.length < 3) {
            System.out.println("Usage: java PortScanner <host> <startPort> <endPort> [threads] [timeoutMs]");
            System.out.println("  Default threads  : 100");
            System.out.println("  Default timeoutMs: 200");
            System.exit(1);
        }

        String host      = args[0];
        int startPort    = Integer.parseInt(args[1]);
        int endPort      = Integer.parseInt(args[2]);
        int numThreads   = args.length >= 4 ? Integer.parseInt(args[3]) : 100;
        int timeoutMs    = args.length >= 5 ? Integer.parseInt(args[4]) : 200;

        // Basic validation
        if (startPort < 1 || endPort > 65535 || startPort > endPort) {
            System.err.println("Invalid port range. Use 1–65535 with start ≤ end.");
            System.exit(1);
        }

        totalPorts = endPort - startPort + 1;

        System.out.println();
        System.out.printf("  Target  : %s%n", host);
        System.out.printf("  Ports   : %d – %d  (%d total)%n", startPort, endPort, totalPorts);
        System.out.printf("  Threads : %d%n", numThreads);
        System.out.printf("  Timeout : %d ms%n%n", timeoutMs);

        // ── Build and start threads ──────────────────────────────────────────
        List<ScannerThread> threads =
                buildThreads(host, startPort, endPort, numThreads, timeoutMs);

        long startTime = System.currentTimeMillis();

        for (ScannerThread t : threads) {
            t.start();
        }

        // ── Wait for all threads to finish ───────────────────────────────────
        for (ScannerThread t : threads) {
            try {
                t.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        long elapsed = System.currentTimeMillis() - startTime;

        // ── Print final results ──────────────────────────────────────────────
        printResults(host, elapsed);
    }
}