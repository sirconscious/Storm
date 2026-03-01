import java.util.List;

public class FuzzerThread extends Thread {
    public List<String> wordsChunk;
    public String url;

    FuzzerThread(List<String> wordsChunk, String url) {
        this.wordsChunk = wordsChunk;
        this.url = url;
    }

    @Override
    public void run() {
        for (String word : wordsChunk) {
            String endPoint = url + "/" + word;
            int status = RequestSender.send(endPoint);

            if (status == 200 || status == 301 || status == 302 || status == 403) {
                Logger.logSuccess(Thread.currentThread().getName(), endPoint, status);
            } else {
                Logger.logFailed(Thread.currentThread().getName(), endPoint, status);
            }
        }
    }
}