import java.util.List;

public class FuzzerThread extends Thread{
    public List<String> wordsChunk;
    public String url;
    public final RequestSender sender= new RequestSender();

    FuzzerThread(List<String> wordsChunk ,String url){
        this.wordsChunk = wordsChunk;
        this.url=url;
    }

    @Override
    public void run() {
        for (int i = 0; i < wordsChunk.size(); i++) {
            String endPoint = url+"/"+wordsChunk.get(i);
            int status = sender.send(endPoint) ;
            System.out.println(Thread.currentThread().getName() + ":   " + endPoint+" --> " + status);
        }
    }
}
