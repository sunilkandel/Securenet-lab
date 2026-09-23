package com.securenet.dashboard.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

/** GET /api/stats */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Stats(
        @JsonProperty("total_events") long totalEvents,
        @JsonProperty("active_bans") long activeBans,
        @JsonProperty("unique_attackers") long uniqueAttackers,
        @JsonProperty("last_event_at") String lastEventAt,
        @JsonProperty("events_by_type") Map<String, Long> eventsByType,
        @JsonProperty("events_by_severity") Map<String, Long> eventsBySeverity) {
}
