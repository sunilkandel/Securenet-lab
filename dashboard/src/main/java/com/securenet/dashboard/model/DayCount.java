package com.securenet.dashboard.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** One element of GET /api/timeseries: events on one UTC day (YYYY-MM-DD). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DayCount(
        @JsonProperty("day") String day,
        @JsonProperty("count") long count) {
}
