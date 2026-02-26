import java.util.List;

public class FuzzerThread extends Thread {
    public List<String> wordsChunk;
    public String url;
    public final RequestSender sender = new RequestSender();

    FuzzerThread(List<String> wordsChunk, String url) {
        this.wordsChunk = wordsChunk;
        this.url = url;
    }

    @Override
    public void run() {
        for (String word : wordsChunk) {
            String endPoint = url + "/" + word;
            int status = sender.send(endPoint);
            String result = Thread.currentThread().getName() + " | " + endPoint + " --> " + status;

            System.out.println(result);

            if (status == 200 || status == 301 || status == 302 || status == 403) {
                Logger.logSuccess(result);
            } else {
                Logger.logFailed(result);
            }
        }
    }
}