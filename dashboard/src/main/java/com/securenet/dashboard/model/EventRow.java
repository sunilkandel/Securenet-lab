package com.securenet.dashboard.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** One element of GET /api/events. Fields the table does not show are ignored. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record EventRow(
        @JsonProperty("id") Long id,
        @JsonProperty("source_ip") String sourceIp,
        @JsonProperty("event_type") String eventType,
        @JsonProperty("severity") String severity,
        @JsonProperty("mitre_technique") String mitreTechnique,
        @JsonProperty("timestamp") String timestamp) {
}
