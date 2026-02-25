import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class RequestSender {

    private static final HttpClient client = HttpClient.newHttpClient();

    public static int send(String url) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .header("User-Agent", "Mozilla/5.0")
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode();

        } catch (Exception e) {
            System.out.println("[ERROR] " + url + " -> " + e.getMessage());
            return -1; // -1 means request failed
        }
    }
}