# SecureNet Lab — Java dashboard

JavaFX desktop client for the pipeline's REST API (`src/api/server.py`).
It polls the API every 5 seconds on a background thread and shows:

- totals: events, active bans, unique attackers, last event
- events per day (14 days) and the busiest attacking IPs
- recent events, colour-coded by severity, with MITRE technique
- active firewall bans with their expiry ("permanent" if none)

If the API goes away the window keeps the last data, shows
"connection lost - retrying" with the reason, backs off to at most 30 s
between attempts, and recovers on its own when the API is back.

## Requirements

- Java 21+
- Maven 3.8+ (downloads JavaFX 21 and Jackson from Maven Central)
- The API running on the monitor VM:
  `uvicorn src.api.server:app --host 0.0.0.0 --port 8000`

## Run

```bash
cd dashboard
SECURENET_API_URL=http://192.168.56.30:8000 mvn clean javafx:run
```

Use your monitor VM's address. The URL is read from `-Dsecurenet.api`,
then `SECURENET_API_URL`, then defaults to `http://localhost:8000`.

From an IDE, run `com.securenet.dashboard.Launcher`: launching the
`Application` subclass directly from the classpath fails with
"JavaFX runtime components are missing".

## Test

```bash
mvn test
```

`ApiClientTest` serves JSON captured from the real Python API
(`src/test/resources/fixtures/`) from a local HTTP server, so a change in
the API's response shape fails here. No display is needed for the tests.

## Layout

```
src/main/java/com/securenet/dashboard/
  App.java                  JavaFX entry point
  Launcher.java             plain main() for IDE / classpath runs
  ApiClient.java            HTTP + JSON, blocking, called off the UI thread
  DashboardController.java  polling (ScheduledService) and rendering
  Format.java               time/severity formatting (unit tested)
  model/                    records mirroring the API's JSON
src/main/resources/
  fxml/dashboard.fxml       layout
  css/dashboard.css         dark theme, same palette as the web dashboard
```

Table columns are bound in code rather than with `PropertyValueFactory`,
which needs `getX()` getters and cannot read records.

## Verification status

Compiled with `javac -Xlint:all -Werror`, all 16 unit tests passed, and the
app was run against a live API (normal data, API outage, API recovery).
That check used Ubuntu's JavaFX 11 packages because Maven Central was not
reachable from the build machine, so the code sticks to APIs present in
both JavaFX 11 and 21. `mvn javafx:run` with the pom's JavaFX 21 has not
been run yet: if your first run fails, the error text is what to look at.
