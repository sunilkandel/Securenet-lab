package com.securenet.dashboard.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** One element of GET /api/top-attackers. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Attacker(
        @JsonProperty("ip") String ip,
        @JsonProperty("count") long count,
        @JsonProperty("worst_severity") String worstSeverity) {
}
