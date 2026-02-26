//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main{
    public static void main(String[] args){

            WorldListReader reader = new WorldListReader("common.txt");
            reader.read();
            reader.splitToChunks(10);

            for (int i = 0; i < reader.chunks.size(); i++) {
                FuzzerThread t = new FuzzerThread( reader.chunks.get(i), "https://twinfragrance.shop");
                t.start();
            }
//    RequestSender sender = new RequestSender();
//     int status=  sender.send("https://emsi.ma");
//        System.out.println(status);
 }
}

