import java.util.*;

/**
 * Storm — Unified CLI Entry Point v0.4
 *
 * Modules:
 *   [1] Directory Fuzzer
 *   [2] Subdomain Enumerator
 *   [3] Port Scanner
 *   [4] Host Discovery
 *   [5] Full Recon (all modules sequentially)
 *   [0] Exit
 */
public class Main {

    // ─── ANSI colors ───────────────────────────────────────────────────────────
    static final String RESET  = "\u001B[0m";
    static final String CYAN   = "\u001B[36m";
    static final String GREEN  = "\u001B[32m";
    static final String YELLOW = "\u001B[33m";
    static final String RED    = "\u001B[31m";
    static final String DIM    = "\u001B[2m";
    static final String BOLD   = "\u001B[1m";

    // ─── Defaults ──────────────────────────────────────────────────────────────
    static String wordlist           = "common.txt";
    static String subdomainsWordlist = "subdomains.txt";
    static int    threads            = 50;
    static int    timeoutMs          = 300;

    static final Scanner input = new Scanner(System.in);

    // ══════════════════════════════════════════════════════════════════════════
    //   ENTRY POINT
    // ══════════════════════════════════════════════════════════════════════════

    public static void main(String[] args) throws InterruptedException {
        printBanner();

        while (true) {
            printMenu();
            String choice = prompt("Select option").trim();

            switch (choice) {
                case "1" -> runDirFuzzer();
                case "2" -> runSubdomainEnum();
                case "3" -> runPortScanner();
                case "4" -> runHostDiscovery();
                case "5" -> runFullRecon();
                case "0" -> {
                    System.out.println(CYAN + "\n  [STORM] Goodbye.\n" + RESET);
                    System.exit(0);
                }
                default -> System.out.println(RED + "  [!] Invalid option. Try again.\n" + RESET);
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //   MODULE 1 — DIRECTORY FUZZER
    // ══════════════════════════════════════════════════════════════════════════

    static void runDirFuzzer() throws InterruptedException {
        System.out.println(CYAN + "\n  ── Directory Fuzzer ──────────────────────" + RESET);

        String target     = normalizeUrl(prompt("  Target URL (e.g. https://example.com)"));
        String wl         = promptDefault("  Wordlist", wordlist);
        int    numThreads = promptInt("  Threads", threads);

        printPhaseHeader("DIRECTORY FUZZING", target);

        WorldListReader reader = new WorldListReader(wl);
        reader.read();
        reader.splitToChunks(numThreads);

        long start = System.currentTimeMillis();

        FuzzerThread[] fuzzerThreads = new FuzzerThread[reader.chunks.size()];
        for (int i = 0; i < reader.chunks.size(); i++) {
            fuzzerThreads[i] = new FuzzerThread(reader.chunks.get(i), target);
            fuzzerThreads[i].setName("DirThread-" + (i + 1));
            fuzzerThreads[i].start();
        }
        for (FuzzerThread t : fuzzerThreads) t.join();

        printDone(System.currentTimeMillis() - start);
        Logger.printSummary();
    }

    // ══════════════════════════════════════════════════════════════════════════
    //   MODULE 2 — SUBDOMAIN ENUMERATOR
    // ══════════════════════════════════════════════════════════════════════════

    static void runSubdomainEnum() throws InterruptedException {
        System.out.println(CYAN + "\n  ── Subdomain Enumerator ──────────────────" + RESET);

        String target     = normalizeUrl(prompt("  Target URL (e.g. https://example.com)"));
        String wl         = promptDefault("  Wordlist", subdomainsWordlist);
        int    numThreads = promptInt("  Threads", threads);

        printPhaseHeader("SUBDOMAIN ENUMERATION", target);

        WorldListReader reader = new WorldListReader(wl);
        reader.read();
        reader.splitToChunks(numThreads);

        long start = System.currentTimeMillis();

        SubDomainFuzzer[] subThreads = new SubDomainFuzzer[reader.chunks.size()];
        for (int i = 0; i < reader.chunks.size(); i++) {
            subThreads[i] = new SubDomainFuzzer(reader.chunks.get(i), target);
            subThreads[i].setName("SubThread-" + (i + 1));
            subThreads[i].start();
        }
        for (SubDomainFuzzer t : subThreads) t.join();

        printDone(System.currentTimeMillis() - start);
        Logger.printSummary();
    }

    // ══════════════════════════════════════════════════════════════════════════
    //   MODULE 3 — PORT SCANNER
    // ══════════════════════════════════════════════════════════════════════════

    static void runPortScanner() throws InterruptedException {
        System.out.println(CYAN + "\n  ── Port Scanner ──────────────────────────" + RESET);

        String host       = prompt("  Host (e.g. 192.168.1.1 or scanme.nmap.org)");
        int    startPort  = promptInt("  Start port", 1);
        int    endPort    = promptInt("  End port",   1024);
        int    numThreads = promptInt("  Threads",    100);
        int    timeout    = promptInt("  Timeout ms", timeoutMs);

        if (startPort < 1 || endPort > 65535 || startPort > endPort) {
            System.out.println(RED + "  [!] Invalid port range." + RESET);
            return;
        }

        printPhaseHeader("PORT SCANNER", host);

        // Reset shared state between runs
        PortScanner.results.clear();
        PortScanner.scannedCount.set(0);
        PortScanner.totalPorts = endPort - startPort + 1;

        System.out.printf("  Target  : %s%n", host);
        System.out.printf("  Ports   : %d – %d  (%d total)%n", startPort, endPort, PortScanner.totalPorts);
        System.out.printf("  Threads : %d%n", numThreads);
        System.out.printf("  Timeout : %d ms%n%n", timeout);

        List<PortScanner.ScannerThread> scanThreads =
                PortScanner.buildThreads(host, startPort, endPort, numThreads, timeout);

        long start = System.currentTimeMillis();
        for (PortScanner.ScannerThread t : scanThreads) t.start();
        for (PortScanner.ScannerThread t : scanThreads) t.join();

        PortScanner.printResults(host, System.currentTimeMillis() - start);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //   MODULE 4 — HOST DISCOVERY
    // ══════════════════════════════════════════════════════════════════════════

    static void runHostDiscovery() throws InterruptedException {
        System.out.println(CYAN + "\n  ── Host Discovery ────────────────────────" + RESET);
        System.out.println(DIM + "  Formats: 192.168.1.0/24 | 192.168.1.1-192.168.1.50 | 192.168.1.1" + RESET);

        String target     = prompt("  Target");
        int    numThreads = promptInt("  Threads",    50);
        int    timeout    = promptInt("  Timeout ms", timeoutMs);

        printPhaseHeader("HOST DISCOVERY", target);

        // Reset shared state between runs
        HostDiscovery.aliveHosts.clear();
        HostDiscovery.scannedCount.set(0);

        List<String> ips;
        try {
            ips = HostDiscovery.resolveTargets(target);
        } catch (Exception e) {
            System.out.println(RED + "  [!] Invalid target: " + e.getMessage() + RESET);
            return;
        }

        HostDiscovery.totalHosts = ips.size();
        System.out.printf("  Hosts   : %d%n", HostDiscovery.totalHosts);
        System.out.printf("  Threads : %d%n", numThreads);
        System.out.printf("  Timeout : %d ms%n", timeout);
        System.out.printf("  Method  : ICMP ping → TCP fallback%n%n");

        List<HostDiscovery.DiscoveryThread> discThreads =
                HostDiscovery.buildThreads(ips, numThreads, timeout);

        long start = System.currentTimeMillis();
        for (HostDiscovery.DiscoveryThread t : discThreads) t.start();
        for (HostDiscovery.DiscoveryThread t : discThreads) t.join();

        HostDiscovery.printResults(target, System.currentTimeMillis() - start);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //   MODULE 5 — FULL RECON
    // ══════════════════════════════════════════════════════════════════════════

    static void runFullRecon() throws InterruptedException {
        System.out.println(CYAN + "\n  ── Full Recon ────────────────────────────" + RESET);
        System.out.println(DIM + "  Runs: Host Discovery → Port Scanner → Dir Fuzzer → Subdomain Enum\n" + RESET);

        String webTarget  = normalizeUrl(prompt("  Web target URL      (e.g. https://example.com)"));
        String netTarget  = prompt("  Network target      (e.g. 192.168.1.0/24)");
        String wl         = promptDefault("  Dir wordlist",       wordlist);
        String swl        = promptDefault("  Subdomain wordlist", subdomainsWordlist);
        int    numThreads = promptInt("  Threads",  threads);
        int    timeout    = promptInt("  Timeout ms", timeoutMs);

        long totalStart = System.currentTimeMillis();

        // ── Phase 1: Host Discovery ────────────────────────────────────────────
        printPhaseHeader("PHASE 1 — HOST DISCOVERY", netTarget);
        HostDiscovery.aliveHosts.clear();
        HostDiscovery.scannedCount.set(0);

        List<String> ips;
        try {
            ips = HostDiscovery.resolveTargets(netTarget);
        } catch (Exception e) {
            System.out.println(RED + "  [!] Invalid network target, skipping." + RESET);
            ips = new ArrayList<>();
        }

        if (!ips.isEmpty()) {
            HostDiscovery.totalHosts = ips.size();
            System.out.printf("  Scanning %d hosts...%n%n", HostDiscovery.totalHosts);
            List<HostDiscovery.DiscoveryThread> dt = HostDiscovery.buildThreads(ips, numThreads, timeout);
            long p1 = System.currentTimeMillis();
            for (HostDiscovery.DiscoveryThread t : dt) t.start();
            for (HostDiscovery.DiscoveryThread t : dt) t.join();
            HostDiscovery.printResults(netTarget, System.currentTimeMillis() - p1);
        }

        // ── Phase 2: Port Scanner ──────────────────────────────────────────────
        String host = extractHost(webTarget);
        printPhaseHeader("PHASE 2 — PORT SCANNER", host);
        PortScanner.results.clear();
        PortScanner.scannedCount.set(0);
        PortScanner.totalPorts = 1024;

        System.out.printf("  Scanning ports 1–1024 on %s...%n%n", host);
        List<PortScanner.ScannerThread> st = PortScanner.buildThreads(host, 1, 1024, numThreads, timeout);
        long p2 = System.currentTimeMillis();
        for (PortScanner.ScannerThread t : st) t.start();
        for (PortScanner.ScannerThread t : st) t.join();
        PortScanner.printResults(host, System.currentTimeMillis() - p2);

        // ── Phase 3: Directory Fuzzing ─────────────────────────────────────────
        printPhaseHeader("PHASE 3 — DIRECTORY FUZZING", webTarget);
        WorldListReader dirReader = new WorldListReader(wl);
        dirReader.read();
        dirReader.splitToChunks(numThreads);
        long p3 = System.currentTimeMillis();
        FuzzerThread[] ft = new FuzzerThread[dirReader.chunks.size()];
        for (int i = 0; i < dirReader.chunks.size(); i++) {
            ft[i] = new FuzzerThread(dirReader.chunks.get(i), webTarget);
            ft[i].setName("DirThread-" + (i + 1));
            ft[i].start();
        }
        for (FuzzerThread t : ft) t.join();
        printDone(System.currentTimeMillis() - p3);

        // ── Phase 4: Subdomain Enumeration ────────────────────────────────────
        printPhaseHeader("PHASE 4 — SUBDOMAIN ENUMERATION", webTarget);
        WorldListReader subReader = new WorldListReader(swl);
        subReader.read();
        subReader.splitToChunks(numThreads);
        long p4 = System.currentTimeMillis();
        SubDomainFuzzer[] sft = new SubDomainFuzzer[subReader.chunks.size()];
        for (int i = 0; i < subReader.chunks.size(); i++) {
            sft[i] = new SubDomainFuzzer(subReader.chunks.get(i), webTarget);
            sft[i].setName("SubThread-" + (i + 1));
            sft[i].start();
        }
        for (SubDomainFuzzer t : sft) t.join();
        printDone(System.currentTimeMillis() - p4);

        // ── Final Summary ──────────────────────────────────────────────────────
        long totalElapsed = (System.currentTimeMillis() - totalStart) / 1000;
        System.out.println(YELLOW);
        System.out.println("╔══════════════════════════════════════════╗");
        System.out.println("║           FULL RECON COMPLETE            ║");
        System.out.println("╠══════════════════════════════════════════╣");
        System.out.printf ("║  Live Hosts   : %-25s║%n", HostDiscovery.aliveHosts.size());
        System.out.printf ("║  Open Ports   : %-25s║%n", PortScanner.results.size());
        System.out.printf ("║  Total Time   : %-25s║%n", totalElapsed + "s");
        System.out.println("╚══════════════════════════════════════════╝" + RESET);
        Logger.printSummary();
    }

    // ══════════════════════════════════════════════════════════════════════════
    //   UI HELPERS
    // ══════════════════════════════════════════════════════════════════════════

    static void printBanner() {
        System.out.println(CYAN);
        System.out.println(" ░▒▓███████▓▒░▒▓████████▓▒░▒▓██████▓▒░░▒▓███████▓▒░░▒▓██████████████▓▒░  ");
        System.out.println("░▒▓█▓▒░         ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println("░▒▓█▓▒░         ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println(" ░▒▓██████▓▒░   ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println("       ░▒▓█▓▒░  ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println("       ░▒▓█▓▒░  ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println("░▒▓███████▓▒░   ░▒▓█▓▒░   ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println(RESET);
        System.out.println(DIM + "              Made by: sirconscious | v0.4" + RESET);
        System.out.println();
    }

    static void printMenu() {
        System.out.println(YELLOW + "╔══════════════════════════════════════════╗");
        System.out.println("║              SELECT A MODULE             ║");
        System.out.println("╠══════════════════════════════════════════╣");
        System.out.println("║  [1]  Directory Fuzzer                   ║");
        System.out.println("║  [2]  Subdomain Enumerator               ║");
        System.out.println("║  [3]  Port Scanner                       ║");
        System.out.println("║  [4]  Host Discovery                     ║");
        System.out.println("║  [5]  Full Recon  (all modules)          ║");
        System.out.println("║  [0]  Exit                               ║");
        System.out.println("╚══════════════════════════════════════════╝" + RESET);
    }

    static void printPhaseHeader(String phase, String target) {
        System.out.println();
        System.out.println(CYAN + "┌─────────────────────────────────────────────┐");
        System.out.printf ("│  %-45s│%n", phase);
        System.out.printf ("│  Target: %-37s│%n",
                target.length() > 37 ? target.substring(0, 37) + "…" : target);
        System.out.println("└─────────────────────────────────────────────┘" + RESET);
        System.out.println();
    }

    static void printDone(long elapsedMs) {
        System.out.printf(GREEN + "%n  [✓] Done in %.2fs%n" + RESET, elapsedMs / 1000.0);
    }

    // ── Input helpers ──────────────────────────────────────────────────────────

    static String prompt(String label) {
        System.out.print(BOLD + label + " > " + RESET);
        return input.nextLine().trim();
    }

    static String promptDefault(String label, String defaultVal) {
        System.out.print(BOLD + label + " [" + defaultVal + "] > " + RESET);
        String val = input.nextLine().trim();
        return val.isEmpty() ? defaultVal : val;
    }

    static int promptInt(String label, int defaultVal) {
        System.out.print(BOLD + label + " [" + defaultVal + "] > " + RESET);
        String val = input.nextLine().trim();
        if (val.isEmpty()) return defaultVal;
        try { return Integer.parseInt(val); }
        catch (NumberFormatException e) { return defaultVal; }
    }

    /** Extracts the hostname from a URL: "https://example.com/path" → "example.com" */
    static String extractHost(String url) {
        try {
            return url.replaceFirst("https?://", "").split("/")[0].split(":")[0];
        } catch (Exception e) {
            return url;
        }
    }

    /** Auto-adds https:// if the user forgot it */
    static String normalizeUrl(String url) {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return "https://" + url;
        }
        return url;
    }
}