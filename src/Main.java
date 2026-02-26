public class Main {
    // ══════════════════════════════════════════════
    //              STORM CONFIGURATION
    // ══════════════════════════════════════════════
    static String target     = "https://sberdiltek.com";
    static String wordlist   = "common.txt";
    static int    threads    = 50;

    public static void main(String[] args) throws InterruptedException {
        printBanner();
        printConfig();

        // ── Load & split wordlist ──────────────────
        WorldListReader reader = new WorldListReader(wordlist);
        reader.read();
        reader.splitToChunks(threads);

        long startTime = System.currentTimeMillis();

        // ── Launch threads ─────────────────────────
        FuzzerThread[] fuzzerThreads = new FuzzerThread[reader.chunks.size()];
        for (int i = 0; i < reader.chunks.size(); i++) {
            fuzzerThreads[i] = new FuzzerThread(reader.chunks.get(i), target);
            fuzzerThreads[i].setName("Thread-" + (i + 1));
            fuzzerThreads[i].start();
        }

        // ── Wait for all threads to finish ─────────
        for (FuzzerThread t : fuzzerThreads) {
            t.join();
        }

        long elapsed = (System.currentTimeMillis() - startTime) / 1000;

        // ── Done ───────────────────────────────────
        System.out.println("\n[STORM] Scan complete in " + elapsed + "s");
        System.out.println("[STORM] Results saved to success.log and failed.log");
    }

    static void printBanner() {
        System.out.println("\033[36m"); // cyan color
        System.out.println(" ░▒▓███████▓▒░▒▓████████▓▒░▒▓██████▓▒░░▒▓███████▓▒░░▒▓██████████████▓▒░  ");
        System.out.println("░▒▓█▓▒░         ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println("░▒▓█▓▒░         ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println(" ░▒▓██████▓▒░   ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println("       ░▒▓█▓▒░  ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println("       ░▒▓█▓▒░  ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println("░▒▓███████▓▒░   ░▒▓█▓▒░   ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ ");
        System.out.println("\033[0m"); // reset color
        System.out.println("\033[90m              Made by: sirconscious | v0.2\033[0m");
        System.out.println();
    }

    static void printConfig() {
        System.out.println("\033[33m╔══════════════════════════════════════╗");
        System.out.println("║           STORM - DIR FUZZER         ║");
        System.out.println("╠══════════════════════════════════════╣");
        System.out.println("║  Target   : " + target);
        System.out.println("║  Wordlist : " + wordlist);
        System.out.println("║  Threads  : " + threads);
        System.out.println("╚══════════════════════════════════════╝\033[0m");
        System.out.println();
    }
}