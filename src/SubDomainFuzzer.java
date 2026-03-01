import java.util.List;

public class SubDomainFuzzer extends Thread {
    private final List<String> wordsChunk;
    private final String protocol;   // e.g. "http"
    private final String baseDomain; // e.g. "example.com"

    SubDomainFuzzer(List<String> wordsChunk, String url) {
        this.wordsChunk = wordsChunk;

        // split "http://example.com" → protocol="http", baseDomain="example.com"
        String[] parts = url.split("://", 2);
        this.protocol   = parts[0];
        this.baseDomain = parts[1];
    }

    @Override
    public void run() {
        for (String word : wordsChunk) {
            String target = protocol + "://" + word + "." + baseDomain;
            int status = RequestSender.send(target);

            if (status == 200 || status == 301 || status == 302 || status == 403) {
                Logger.logSuccess(Thread.currentThread().getName(), target, status);
            } else {
                Logger.logFailed(Thread.currentThread().getName(), target, status);
            }
        }
    }
}