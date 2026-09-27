package com.securenet.dashboard;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Set;

/** Display formatting, kept free of JavaFX so it can be unit tested. */
public final class Format {

    private static final DateTimeFormatter TIME =
            DateTimeFormatter.ofPattern("MMM d, HH:mm:ss", Locale.ENGLISH);
    private static final Set<String> SEVERITIES = Set.of("low", "medium", "high", "critical");

    private Format() {
    }

    /** API timestamps are ISO-8601 UTC; show them in the local time zone. */
    public static String time(String iso, ZoneId zone) {
        if (iso == null || iso.isBlank()) {
            return "-";
        }
        try {
            return OffsetDateTime.parse(iso).atZoneSameInstant(zone).format(TIME);
        } catch (DateTimeParseException e) {
            try {
                return LocalDateTime.parse(iso).format(TIME);
            } catch (DateTimeParseException e2) {
                return iso; // show it as-is rather than hide it
            }
        }
    }

    public static String time(String iso) {
        return time(iso, ZoneId.systemDefault());
    }

    /** Ban expiry: empty means the ban never expires. */
    public static String expiry(String iso) {
        return iso == null || iso.isBlank() ? "permanent" : time(iso);
    }

    /** "2026-09-23" becomes "09-23" for compact chart labels. */
    public static String day(String isoDay) {
        return isoDay != null && isoDay.length() >= 10 ? isoDay.substring(5, 10) : String.valueOf(isoDay);
    }

    /** CSS style class for a severity; unknown values get a neutral class. */
    public static String severityClass(String severity) {
        String s = severity == null ? "" : severity.toLowerCase(Locale.ROOT);
        return SEVERITIES.contains(s) ? "sev-" + s : "sev-unknown";
    }

    public static String orDash(String value) {
        return value == null || value.isBlank() ? "-" : value;
    }
}
