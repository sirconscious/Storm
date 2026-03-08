public class Main {
    // ══════════════════════════════════════════════
    //              STORM CONFIGURATION
    // ══════════════════════════════════════════════
    static String target             = "https://41.111.144.117";
    static String wordlist           = "common.txt";
    static String subdomainsWordlist = "subdomains.txt";
    static int    threads            = 50;

    // ── Toggle scans on/off ────────────────────────
    static boolean runDirFuzz    = true;
    static boolean runSubDomains = false;

    public static void main(String[] args) throws InterruptedException {
        printBanner();
        printConfig();

        long startTime = System.currentTimeMillis();

        // ══════════════════════════════════════════
        //          PHASE 1 — DIR FUZZING
        // ══════════════════════════════════════════
        if (runDirFuzz) {
            System.out.println("\033[36m[STORM] Starting directory fuzzing...\033[0m\n");

            WorldListReader dirReader = new WorldListReader(wordlist);
            dirReader.read();
            dirReader.splitToChunks(threads);

            FuzzerThread[] fuzzerThreads = new FuzzerThread[dirReader.chunks.size()];
            for (int i = 0; i < dirReader.chunks.size(); i++) {
                fuzzerThreads[i] = new FuzzerThread(dirReader.chunks.get(i), target);
                fuzzerThreads[i].setName("DirThread-" + (i + 1));
                fuzzerThreads[i].start();
            }

            for (FuzzerThread t : fuzzerThreads) t.join();

            System.out.println("\033[36m[STORM] Directory fuzzing complete.\033[0m\n");
        }

        // ══════════════════════════════════════════
        //          PHASE 2 — SUBDOMAIN FUZZING
        // ══════════════════════════════════════════
        if (runSubDomains) {
            System.out.println("\033[36m[STORM] Starting subdomain enumeration...\033[0m\n");

            WorldListReader subReader = new WorldListReader(subdomainsWordlist);
            subReader.read();
            subReader.splitToChunks(threads);

            SubDomainFuzzer[] subThreads = new SubDomainFuzzer[subReader.chunks.size()];
            for (int i = 0; i < subReader.chunks.size(); i++) {
                subThreads[i] = new SubDomainFuzzer(subReader.chunks.get(i), target);
                subThreads[i].setName("SubThread-" + (i + 1));
                subThreads[i].start();
            }

            for (SubDomainFuzzer t : subThreads) t.join();

            System.out.println("\033[36m[STORM] Subdomain enumeration complete.\033[0m\n");
        }

        // ══════════════════════════════════════════
        //          DONE
        // ══════════════════════════════════════════
        long elapsed = (System.currentTimeMillis() - startTime) / 1000;
        System.out.println("[STORM] Total scan time: " + elapsed + "s");
        Logger.printSummary();
    }

    static void printBanner() {
        System.out.println("\033[36m");
        System.out.println(" ░▒▓███████▓▒░▒▓████████▓▒░▒▓██████▓▒░░▒▓███████▓▒░░▒▓██████████████▓▒░  ");
        System.out.println("░▒▓█▓▒░         ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println("░▒▓█▓▒░         ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println(" ░▒▓██████▓▒░   ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println("       ░▒▓█▓▒░  ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println("       ░▒▓█▓▒░  ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println("░▒▓███████▓▒░   ░▒▓█▓▒░   ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println("\033[0m");
        System.out.println("\033[90m              Made by: sirconscious | v0.3\033[0m");
        System.out.println();
    }

    static void printConfig() {
        System.out.println("\033[33m╔══════════════════════════════════════╗");
        System.out.println("║           STORM - DIR FUZZER         ║");
        System.out.println("╠══════════════════════════════════════╣");
        System.out.println("║  Target     : " + target);
        System.out.println("║  Wordlist   : " + wordlist);
        System.out.println("║  Subdomains : " + subdomainsWordlist);
        System.out.println("║  Threads    : " + threads);
        System.out.println("║  Dir Fuzz   : " + (runDirFuzz    ? "ON" : "OFF"));
        System.out.println("║  Subdomains : " + (runSubDomains ? "ON" : "OFF"));
        System.out.println("╚══════════════════════════════════════╝\033[0m");
        System.out.println();
    }
}