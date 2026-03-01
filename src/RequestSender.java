import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class RequestSender {

    private static final HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_2)             // HTTP/2 is faster, falls back to HTTP/1.1 automatically
            .connectTimeout(Duration.ofSeconds(5))          // connection timeout
            .followRedirects(HttpClient.Redirect.NEVER)     // don't follow redirects, just get the status code
            .build();

    public static int send(String url) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(5))          // per request timeout
                    .header("User-Agent", "Mozilla/5.0")
                    .header("Accept", "*/*")
                    .build();

            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
            return response.statusCode();

        } catch (Exception e) {
            return -1;
        }
    }
}