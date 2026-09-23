package com.securenet.dashboard.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** One element of GET /api/bans. An empty expiresAt means a permanent ban. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record BanRow(
        @JsonProperty("ip") String ip,
        @JsonProperty("reason") String reason,
        @JsonProperty("banned_at") String bannedAt,
        @JsonProperty("expires_at") String expiresAt,
        @JsonProperty("status") String status) {
}
