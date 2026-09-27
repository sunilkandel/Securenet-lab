package com.securenet.dashboard;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.ZoneId;
import org.junit.jupiter.api.Test;

class FormatTest {

    @Test
    void utcTimestampIsShownInTheGivenZone() {
        // the API stores UTC; Kathmandu is UTC+05:45
        assertEquals("Sep 23, 21:45:17",
                Format.time("2026-09-23T16:00:17.787958+00:00", ZoneId.of("Asia/Kathmandu")));
    }

    @Test
    void missingOrOddTimestamps() {
        assertEquals("-", Format.time(null, ZoneId.of("UTC")));
        assertEquals("-", Format.time("  ", ZoneId.of("UTC")));
        assertEquals("not-a-date", Format.time("not-a-date", ZoneId.of("UTC")));
        assertEquals("Oct 11, 10:00:00", Format.time("2026-10-11T10:00:00", ZoneId.of("UTC")));
    }

    @Test
    void emptyExpiryMeansPermanent() {
        assertEquals("permanent", Format.expiry(""));
        assertEquals("permanent", Format.expiry(null));
    }

    @Test
    void chartDayLabel() {
        assertEquals("09-23", Format.day("2026-09-23"));
    }

    @Test
    void severityClasses() {
        assertEquals("sev-critical", Format.severityClass("critical"));
        assertEquals("sev-high", Format.severityClass("HIGH"));
        assertEquals("sev-unknown", Format.severityClass("bogus"));
        assertEquals("sev-unknown", Format.severityClass(null));
    }
}
