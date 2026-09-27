package com.securenet.dashboard;

import com.securenet.dashboard.model.Attacker;
import com.securenet.dashboard.model.BanRow;
import com.securenet.dashboard.model.DayCount;
import com.securenet.dashboard.model.EventRow;
import com.securenet.dashboard.model.Snapshot;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.concurrent.ScheduledService;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.scene.control.Label;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.util.Duration;
import javafx.util.StringConverter;

/** Polls the API every few seconds on a background thread and renders the result. */
public class DashboardController {

    private static final Duration PERIOD = Duration.seconds(5);
    private static final DateTimeFormatter CLOCK = DateTimeFormatter.ofPattern("HH:mm:ss");

    @FXML private Label status;
    @FXML private Label totalEvents;
    @FXML private Label activeBans;
    @FXML private Label uniqueAttackers;
    @FXML private Label lastEvent;

    @FXML private LineChart<String, Number> timeline;
    @FXML private BarChart<Number, String> attackersChart;  // horizontal: IPs read in full

    @FXML private TableView<EventRow> eventsTable;
    @FXML private TableColumn<EventRow, String> evTime;
    @FXML private TableColumn<EventRow, String> evIp;
    @FXML private TableColumn<EventRow, String> evType;
    @FXML private TableColumn<EventRow, String> evSeverity;
    @FXML private TableColumn<EventRow, String> evMitre;

    @FXML private TableView<BanRow> bansTable;
    @FXML private TableColumn<BanRow, String> banIp;
    @FXML private TableColumn<BanRow, String> banReason;
    @FXML private TableColumn<BanRow, String> banSince;
    @FXML private TableColumn<BanRow, String> banExpires;

    private ScheduledService<Snapshot> poller;

    @FXML
    private void initialize() {
        // Records have ip() rather than getIp(), so PropertyValueFactory
        // cannot read them: every column is wired explicitly.
        bind(evTime, e -> Format.time(e.timestamp()));
        bind(evIp, EventRow::sourceIp);
        bind(evType, EventRow::eventType);
        bind(evSeverity, EventRow::severity);
        bind(evMitre, e -> Format.orDash(e.mitreTechnique()));
        evSeverity.setCellFactory(col -> new SeverityCell<>());

        bind(banIp, BanRow::ip);
        bind(banReason, b -> Format.orDash(b.reason()));
        bind(banSince, b -> Format.time(b.bannedAt()));
        bind(banExpires, b -> Format.expiry(b.expiresAt()));

        wholeNumbers((NumberAxis) timeline.getYAxis());
        wholeNumbers((NumberAxis) attackersChart.getXAxis());
    }

    /** Begin polling. Called once the window is showing. */
    void start(ApiClient api) {
        status.setText("connecting to " + api.baseUri() + " ...");
        poller = new ScheduledService<>() {
            @Override
            protected Task<Snapshot> createTask() {
                return new Task<>() {
                    @Override
                    protected Snapshot call() {
                        return api.snapshot();
                    }
                };
            }
        };
        poller.setPeriod(PERIOD);
        poller.setRestartOnFailure(true);
        // failures back off, but never to more than 30s between retries
        poller.setMaximumCumulativePeriod(Duration.seconds(30));
        poller.setOnSucceeded(e -> render(poller.getValue()));
        poller.setOnFailed(e -> showDisconnected(poller.getException()));
        poller.start();
    }

    void stop() {
        if (poller != null) {
            poller.cancel();
        }
    }

    private void render(Snapshot s) {
        totalEvents.setText(Long.toString(s.stats().totalEvents()));
        activeBans.setText(Long.toString(s.stats().activeBans()));
        uniqueAttackers.setText(Long.toString(s.stats().uniqueAttackers()));
        lastEvent.setText(Format.time(s.stats().lastEventAt()));

        eventsTable.getItems().setAll(s.events());
        bansTable.getItems().setAll(s.bans());

        XYChart.Series<String, Number> perDay = new XYChart.Series<>();
        for (DayCount d : s.timeseries()) {
            perDay.getData().add(new XYChart.Data<>(Format.day(d.day()), d.count()));
        }
        timeline.getData().setAll(List.of(perDay));

        // a horizontal chart draws categories bottom-up: reverse so the
        // busiest attacker ends up on top
        List<Attacker> attackers = new ArrayList<>(s.topAttackers());
        Collections.reverse(attackers);
        XYChart.Series<Number, String> top = new XYChart.Series<>();
        for (Attacker a : attackers) {
            top.getData().add(new XYChart.Data<>(a.count(), a.ip()));
        }
        attackersChart.getData().setAll(List.of(top));

        setStatus("live - updated " + LocalTime.now().format(CLOCK), true);
    }

    private void showDisconnected(Throwable error) {
        // keep the last good data on screen; just say it is stale
        String why = error == null ? "" : ": " + error.getMessage();
        setStatus("connection lost - retrying" + why, false);
    }

    private void setStatus(String text, boolean live) {
        status.setText(text);
        status.getStyleClass().removeAll("live", "down");
        status.getStyleClass().add(live ? "live" : "down");
    }

    /** Event counts are whole numbers: hide fractional tick labels like 2.5. */
    private static void wholeNumbers(NumberAxis axis) {
        axis.setTickLabelFormatter(new StringConverter<Number>() {
            @Override
            public String toString(Number n) {
                double v = n.doubleValue();
                return v == Math.rint(v) ? Long.toString((long) v) : "";
            }

            @Override
            public Number fromString(String text) {
                return Long.valueOf(text);
            }
        });
    }

    private static <S> void bind(TableColumn<S, String> column, Function<S, String> value) {
        column.setCellValueFactory(c -> new ReadOnlyStringWrapper(value.apply(c.getValue())));
    }

    /** Colours the severity text via the sev-* style classes in dashboard.css. */
    private static final class SeverityCell<S> extends TableCell<S, String> {
        @Override
        protected void updateItem(String severity, boolean empty) {
            super.updateItem(severity, empty);
            getStyleClass().removeIf(c -> c.startsWith("sev-"));
            if (empty || severity == null) {
                setText(null);
                return;
            }
            setText(severity);
            getStyleClass().add(Format.severityClass(severity));
        }
    }
}
