package com.securenet.dashboard;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.securenet.dashboard.model.Attacker;
import com.securenet.dashboard.model.BanRow;
import com.securenet.dashboard.model.EventRow;
import com.securenet.dashboard.model.Snapshot;
import com.securenet.dashboard.model.Stats;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Runs the client against a local HTTP server that serves JSON captured
 * from the real Python API (src/test/resources/fixtures), so a change to
 * the API's response shape shows up here.
 */
class ApiClientTest {

    private HttpServer server;
    private ApiClient api;
    private final List<String> requested = new CopyOnWriteArrayList<>();

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        serve("/api/stats", 200, fixture("stats.json"));
        serve("/api/events", 200, fixture("events.json"));
        serve("/api/bans", 200, fixture("bans.json"));
        serve("/api/timeseries", 200, fixture("timeseries.json"));
        serve("/api/top-attackers", 200, fixture("top_attackers.json"));
        server.start();
        api = new ApiClient("http://127.0.0.1:" + server.getAddress().getPort());
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void parsesStats() {
        Stats s = api.stats();
        assertEquals(3, s.totalEvents());
        assertEquals(1, s.activeBans());
        assertEquals(2, s.uniqueAttackers());
        assertTrue(s.lastEventAt().startsWith("20"));
        assertEquals(1L, s.eventsBySeverity().get("critical"));
    }

    @Test
    void parsesEventsAndIgnoresFieldsTheTableDoesNotUse() {
        List<EventRow> events = api.events(50);
        assertEquals(3, events.size());
        EventRow first = events.get(0);
        assertEquals("203.0.113.5", first.sourceIp());
        assertEquals("ids_alert", first.eventType());
        assertEquals("medium", first.severity());
        // details, raw_log, created_at exist in the JSON and are skipped
    }

    @Test
    void parsesBansAndTopAttackers() {
        BanRow ban = api.bans().get(0);
        assertEquals("192.168.56.10", ban.ip());
        assertEquals("port_scan (critical)", ban.reason());
        assertEquals("active", ban.status());

        Attacker top = api.topAttackers(10).get(0);
        assertEquals("192.168.56.10", top.ip());
        assertEquals(2, top.count());
        assertEquals("critical", top.worstSeverity());
    }

    @Test
    void snapshotFetchesEverythingWithTheRightQueries() {
        Snapshot s = api.snapshot();
        assertEquals(3, s.events().size());
        assertEquals(1, s.timeseries().size());
        assertTrue(requested.contains("/api/events?limit=100"), requested.toString());
        assertTrue(requested.contains("/api/timeseries?days=14"), requested.toString());
        assertTrue(requested.contains("/api/top-attackers?limit=10"), requested.toString());
    }

    @Test
    void nullLastEventIsAllowed() throws IOException {
        server.removeContext("/api/stats");
        serve("/api/stats", 200,
                "{\"total_events\":0,\"active_bans\":0,\"unique_attackers\":0,\"last_event_at\":null}");
        assertNull(api.stats().lastEventAt());
    }

    @Test
    void httpErrorBecomesApiException() {
        server.removeContext("/api/bans");
        serve("/api/bans", 500, "{\"detail\":\"boom\"}");
        ApiException e = assertThrows(ApiException.class, api::bans);
        assertTrue(e.getMessage().contains("500"), e.getMessage());
    }

    @Test
    void badJsonBecomesApiException() {
        server.removeContext("/api/stats");
        serve("/api/stats", 200, "<html>not json</html>");
        assertThrows(ApiException.class, api::stats);
    }

    @Test
    void unreachableServerBecomesApiException() {
        server.stop(0);
        assertThrows(ApiException.class, api::stats);
    }

    @Test
    void rejectsNonHttpUrls() {
        assertThrows(IllegalArgumentException.class, () -> new ApiClient("file:///etc/passwd"));
    }

    @Test
    void baseUrlWithOrWithoutTrailingSlashResolvesTheSame() {
        String port = String.valueOf(server.getAddress().getPort());
        assertEquals(3, new ApiClient("http://127.0.0.1:" + port + "/").stats().totalEvents());
    }

    @Test
    void systemPropertyOverridesDefaultUrl() {
        String old = System.getProperty("securenet.api");
        try {
            System.setProperty("securenet.api", " http://10.0.0.5:9000 ");
            assertEquals("http://10.0.0.5:9000", ApiClient.configuredBaseUrl());
        } finally {
            if (old == null) {
                System.clearProperty("securenet.api");
            } else {
                System.setProperty("securenet.api", old);
            }
        }
    }

    // -- helpers ----------------------------------------------------------------

    private void serve(String path, int status, String body) {
        server.createContext(path, exchange -> {
            requested.add(exchange.getRequestURI().toString());
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
    }

    private static String fixture(String name) throws IOException {
        try (InputStream in = ApiClientTest.class.getResourceAsStream("/fixtures/" + name)) {
            if (in == null) {
                throw new IOException("missing fixture " + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
