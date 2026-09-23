package com.securenet.dashboard;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securenet.dashboard.model.Attacker;
import com.securenet.dashboard.model.BanRow;
import com.securenet.dashboard.model.DayCount;
import com.securenet.dashboard.model.EventRow;
import com.securenet.dashboard.model.Snapshot;
import com.securenet.dashboard.model.Stats;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

/**
 * Read-only client for the SecureNet Lab REST API (src/api/server.py).
 *
 * <p>Blocking by design: the dashboard calls it from a background task,
 * never from the JavaFX application thread. Every failure (network,
 * HTTP status, bad JSON) surfaces as an {@link ApiException}.
 */
public final class ApiClient {

    /** Used when neither -Dsecurenet.api nor SECURENET_API_URL is set. */
    public static final String DEFAULT_URL = "http://localhost:8000";

    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final URI base;
    private final HttpClient http;
    private final ObjectMapper json;

    public ApiClient(String baseUrl) {
        String url = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
        URI uri = URI.create(url);
        if (!"http".equals(uri.getScheme()) && !"https".equals(uri.getScheme())) {
            throw new IllegalArgumentException("API URL must be http(s): " + baseUrl);
        }
        this.base = uri;
        this.http = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
        this.json = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    /** API base URL from -Dsecurenet.api, then SECURENET_API_URL, then the default. */
    public static String configuredBaseUrl() {
        String prop = System.getProperty("securenet.api");
        if (prop != null && !prop.isBlank()) {
            return prop.trim();
        }
        String env = System.getenv("SECURENET_API_URL");
        if (env != null && !env.isBlank()) {
            return env.trim();
        }
        return DEFAULT_URL;
    }

    public URI baseUri() {
        return base;
    }

    public Stats stats() {
        return get("api/stats", new TypeReference<Stats>() { });
    }

    public List<EventRow> events(int limit) {
        return get("api/events?limit=" + limit, new TypeReference<List<EventRow>>() { });
    }

    public List<BanRow> bans() {
        return get("api/bans", new TypeReference<List<BanRow>>() { });
    }

    public List<DayCount> timeseries(int days) {
        return get("api/timeseries?days=" + days, new TypeReference<List<DayCount>>() { });
    }

    public List<Attacker> topAttackers(int limit) {
        return get("api/top-attackers?limit=" + limit, new TypeReference<List<Attacker>>() { });
    }

    /** Everything the dashboard shows, in one call. */
    public Snapshot snapshot() {
        return new Snapshot(stats(), events(100), bans(), timeseries(14), topAttackers(10));
    }

    private <T> T get(String path, TypeReference<T> type) {
        HttpRequest request = HttpRequest.newBuilder(base.resolve(path))
                .timeout(TIMEOUT)
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new ApiException("cannot reach " + base + " (" + e.getClass().getSimpleName() + ")", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ApiException("interrupted while calling " + path, e);
        }
        if (response.statusCode() != 200) {
            throw new ApiException("/" + path + " returned HTTP " + response.statusCode());
        }
        try {
            return json.readValue(response.body(), type);
        } catch (IOException e) {
            throw new ApiException("unexpected JSON from /" + path, e);
        }
    }
}
