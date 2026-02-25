import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class WorldListReader {
    public String fileName ;
    public ArrayList<String> worldList;
    public ArrayList<List<String>> chunks;

    WorldListReader(String fileName){
        this.fileName = fileName;
        this.worldList = new ArrayList<>();
        this.chunks = new ArrayList<>();
    }

    public  void read( ) {
        File myObj = new File(fileName);

        try (Scanner myReader = new Scanner(myObj)) {
            while (myReader.hasNextLine()) {
                String data = myReader.nextLine();
                worldList.add(data);
            }
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }
    public void splitToChunks(int threadCount) {
        int totalWords = worldList.size();
        int chunkSize = (int) Math.ceil((double) totalWords / threadCount);

        for (int i = 0; i < totalWords; i += chunkSize) {
            int end = Math.min(i + chunkSize, totalWords);
            chunks.add(new ArrayList<>(worldList.subList(i, end)));
        }

        System.out.println("[STORM] Split into " + chunks.size() + " chunks:");
        for (int i = 0; i < chunks.size(); i++) {
            System.out.println("  Thread-" + (i + 1) + " -> " + chunks.get(i).size() + " words");
        }
    }
}

