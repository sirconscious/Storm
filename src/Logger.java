import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class Logger {

    // ══════════════════════════════════════════════
    //              LOGGER CONFIGURATION
    // ══════════════════════════════════════════════
    private static final String SUCCESS_FILE = "success.log";
    private static final String FAILED_FILE  = "failed.log";
    private static final boolean LOG_FAILED  = false; // toggle failed logging (can slow things down)

    private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("HH:mm:ss");

    // ── Queue & stats ──────────────────────────────
    private static final BlockingQueue<LogEntry> queue = new LinkedBlockingQueue<>();
    private static final AtomicLong successCount       = new AtomicLong(0);
    private static final AtomicLong failedCount        = new AtomicLong(0);

    // ── Internal record ────────────────────────────
    private record LogEntry(String fileName, String message) {}

    // ── Background writer thread ───────────────────
    static {
        Thread writer = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    LogEntry entry = queue.poll(500, TimeUnit.MILLISECONDS);
                    if (entry != null) {
                        writeToFile(entry.fileName(), entry.message());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();

                    // drain remaining entries before exit
                    LogEntry remaining;
                    while ((remaining = queue.poll()) != null) {
                        writeToFile(remaining.fileName(), remaining.message());
                    }
                }
            }
        }, "Logger-Writer");

        writer.setDaemon(true);
        writer.start();
    }

    // ══════════════════════════════════════════════
    //              PUBLIC API
    // ══════════════════════════════════════════════
    public static void logSuccess(String threadName, String url, int status) {
        successCount.incrementAndGet();
        String message = format(threadName, url, status);

        // always print hits to console with color
        System.out.println(colorForStatus(status) + "[HIT] " + message + "\033[0m");

        queue.offer(new LogEntry(SUCCESS_FILE, message));
    }

    public static void logFailed(String threadName, String url, int status) {
        failedCount.incrementAndGet();
        if (LOG_FAILED) {
            queue.offer(new LogEntry(FAILED_FILE, format(threadName, url, status)));
        }
    }

    public static void printSummary() {
        System.out.println("\033[33m");
        System.out.println("╔══════════════════════════════════════╗");
        System.out.println("║             SCAN SUMMARY             ║");
        System.out.println("╠══════════════════════════════════════╣");
        System.out.println("║  Hits   : " + successCount.get());
        System.out.println("║  Missed : " + failedCount.get());
        System.out.println("║  Total  : " + (successCount.get() + failedCount.get()));
        System.out.println("╚══════════════════════════════════════╝");
        System.out.println("\033[0m");
    }

    // ══════════════════════════════════════════════
    //              INTERNAL HELPERS
    // ══════════════════════════════════════════════
    private static String format(String threadName, String url, int status) {
        String time = LocalDateTime.now().format(TIMESTAMP);
        return "[" + time + "] " + threadName + " | " + url + " --> " + status;
    }

    private static String colorForStatus(int status) {
        return switch (status) {
            case 200       -> "\033[32m"; // green
            case 301, 302  -> "\033[36m"; // cyan
            case 403       -> "\033[33m"; // yellow
            default        -> "\033[0m";  // reset
        };
    }

    private static void writeToFile(String fileName, String message) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(fileName, true))) {
            bw.write(message);
            bw.newLine();
        } catch (IOException e) {
            System.out.println("\033[31m[ERROR] Could not write to log: " + e.getMessage() + "\033[0m");
        }
    }
}