import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class Logger {

    public static synchronized void logSuccess(String message) {
        writeToFile("success.log", message);
    }

    public static synchronized void logFailed(String message) {
        writeToFile("failed.log", message);
    }

    private static void writeToFile(String fileName, String message) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(fileName, true))) {
            bw.write(message);
            bw.newLine();
        } catch (IOException e) {
            System.out.println("[ERROR] Could not write to log: " + e.getMessage());
        }
    }
}