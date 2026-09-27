package com.securenet.dashboard.model;

import java.util.List;

/** Everything one dashboard refresh needs, fetched together off the UI thread. */
public record Snapshot(
        Stats stats,
        List<EventRow> events,
        List<BanRow> bans,
        List<DayCount> timeseries,
        List<Attacker> topAttackers) {
}
