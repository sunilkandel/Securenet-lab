#!/usr/bin/env Rscript
# =============================================================================
# SecureNet Lab - weekly attack analysis report
#
# Reads the pipeline's SQLite database and writes a dated report folder:
#
#   analysis/reports/<YYYY-MM-DD>/
#     report.md           the written report: tables, statistics, charts
#     events_per_day.png  daily volume, this period vs the previous one
#     severity_split.png  events by severity, low -> critical
#     top_attackers.png   top 10 source IPs
#     hour_of_day.png     when attacks happen (UTC hour)
#     summary.csv         events per attack type with MITRE technique
#
# Usage (from anywhere; paths resolve from this script's location):
#   Rscript analysis/scripts/attack_analysis.R [path/to/securenet.db] [--days N]
#
#   --days N  length of the report period in days (default 7: weekly). The
#             N days before it are the comparison baseline.
#
# Weekly on the monitor VM with cron (Mondays 07:00):
#   0 7 * * 1  cd /path/to/Securenet-lab && Rscript analysis/scripts/attack_analysis.R
#
# Requires R >= 4.0 with RSQLite, ggplot2 and dplyr:
#   install.packages(c("RSQLite", "ggplot2", "dplyr"))
# =============================================================================

suppressPackageStartupMessages({
  library(RSQLite)
  library(ggplot2)
  library(dplyr)
})

# -- arguments ----------------------------------------------------------------

args <- commandArgs(trailingOnly = TRUE)
period_days <- 7L
flag <- which(args == "--days")
if (length(flag) == 1) {
  if (flag == length(args)) stop("--days needs a number, e.g. --days 7")
  period_days <- suppressWarnings(as.integer(args[flag + 1]))
  if (is.na(period_days) || period_days < 1) stop("--days must be a whole number >= 1")
  args <- args[-c(flag, flag + 1)]
}

# Locate the project root from this script's own path. Rscript passes
# --file=; source() (e.g. RStudio) sets ofile instead; otherwise assume the
# working directory is the repository root.
file_arg <- grep("^--file=", commandArgs(), value = TRUE)
sourced <- tryCatch(sys.frame(1)$ofile, error = function(e) NULL)
script_dir <- if (length(file_arg) == 1) {
  dirname(normalizePath(sub("^--file=", "", file_arg)))
} else if (!is.null(sourced)) {
  dirname(normalizePath(sourced))
} else {
  file.path(getwd(), "analysis", "scripts")
}
project_root <- normalizePath(file.path(script_dir, "..", ".."), mustWork = FALSE)

db_path <- if (length(args) >= 1) args[1] else file.path(project_root, "data", "securenet.db")
if (!file.exists(db_path)) {
  stop(sprintf("database not found at %s - run the pipeline first", db_path))
}

# -- load ---------------------------------------------------------------------

con <- dbConnect(SQLite(), db_path)
events <- dbGetQuery(con, "
  SELECT id, source_ip, event_type, severity, timestamp, mitre_technique
  FROM events
")
bans <- dbGetQuery(con, "SELECT ip, reason, banned_at, expires_at, status FROM bans")
dbDisconnect(con)

# Pipeline timestamps are ISO-8601 UTC ("2026-09-23T16:00:17.787958+00:00").
parse_utc <- function(x) {
  as.POSIXct(substr(x, 1, 19), format = "%Y-%m-%dT%H:%M:%S", tz = "UTC")
}
events$ts <- parse_utc(events$timestamp)
bad <- sum(is.na(events$ts))
if (bad > 0) {
  warning(sprintf("skipping %d event(s) with an unreadable timestamp", bad))
  events <- events[!is.na(events$ts), ]
}
events$day <- as.Date(events$ts, tz = "UTC")
events$hour <- as.integer(format(events$ts, "%H", tz = "UTC"))
bans$day <- as.Date(parse_utc(bans$banned_at), tz = "UTC")

sev_levels <- c("low", "medium", "high", "critical")
events$severity <- factor(events$severity, levels = sev_levels)

# -- periods ------------------------------------------------------------------

today <- as.Date(format(Sys.time(), tz = "UTC"))
period_start <- today - period_days + 1
base_start <- period_start - period_days
base_end <- period_start - 1

cur <- events %>% filter(day >= period_start, day <= today)
prev <- events %>% filter(day >= base_start, day <= base_end)

out_dir <- file.path(project_root, "analysis", "reports", format(today))
dir.create(out_dir, showWarnings = FALSE, recursive = TRUE)

# -- statistics ---------------------------------------------------------------

daily_counts <- function(df, from, to) {
  all_days <- data.frame(day = seq(from, to, by = "day"))
  counts <- df %>% count(day, name = "events")
  out <- merge(all_days, counts, by = "day", all.x = TRUE)
  out$events[is.na(out$events)] <- 0L
  out
}
cur_daily <- daily_counts(cur, period_start, today)
prev_daily <- daily_counts(prev, base_start, base_end)

serious <- function(df) sum(df$severity %in% c("high", "critical"))
bans_in <- function(from, to) sum(!is.na(bans$day) & bans$day >= from & bans$day <= to)

change <- function(now, before) {
  if (now == before) return("no change")
  if (before == 0) return("new")
  sprintf("%+.0f%%", 100 * (now - before) / before)
}

overview <- data.frame(
  metric = c("events", "unique attackers", "high/critical events", "bans issued"),
  this_period = c(nrow(cur), n_distinct(cur$source_ip), serious(cur),
                  bans_in(period_start, today)),
  previous = c(nrow(prev), n_distinct(prev$source_ip), serious(prev),
               bans_in(base_start, base_end))
)
overview$change <- mapply(change, overview$this_period, overview$previous)

# "Unusual" = more than 2 standard deviations above the baseline's daily
# mean. With no baseline activity there is nothing to compare against, and
# the report says so rather than inventing a threshold.
base_mean <- mean(prev_daily$events)
base_sd <- sd(prev_daily$events)
if (nrow(prev) == 0 || is.na(base_sd) || base_sd == 0) {
  unusual_note <- "Not enough baseline history to flag unusual days (the previous period had no or constant activity)."
  unusual <- cur_daily[0, ]
} else {
  threshold <- base_mean + 2 * base_sd
  unusual <- cur_daily[cur_daily$events > threshold, ]
  unusual_note <- sprintf(
    "Threshold: baseline mean %.1f + 2 x sd %.1f = %.1f events/day.",
    base_mean, base_sd, threshold
  )
}

sev_rank <- setNames(seq_along(sev_levels), sev_levels)
worst <- function(s) {
  r <- sev_rank[as.character(s)]
  if (all(is.na(r))) return("-")
  sev_levels[max(r, na.rm = TRUE)]
}
active_bans <- unique(bans$ip[bans$status == "active"])

top_ips <- cur %>%
  group_by(source_ip) %>%
  summarise(
    events = n(),
    worst_severity = worst(severity),
    first_seen = format(min(ts), "%Y-%m-%d %H:%M"),
    last_seen = format(max(ts), "%Y-%m-%d %H:%M"),
    .groups = "drop"
  ) %>%
  arrange(desc(events)) %>%
  slice_head(n = 10) %>%
  mutate(banned = ifelse(source_ip %in% active_bans, "yes", "no"))

most_common <- function(x) {
  x <- x[!is.na(x) & x != ""]
  if (length(x) == 0) return("-")
  names(sort(table(x), decreasing = TRUE))[1]
}
by_type <- cur %>%
  group_by(event_type) %>%
  summarise(events = n(), mitre = most_common(mitre_technique), .groups = "drop") %>%
  arrange(desc(events))
write.csv(by_type, file.path(out_dir, "summary.csv"), row.names = FALSE)

by_sev <- data.frame(severity = factor(sev_levels, levels = sev_levels)) %>%
  left_join(cur %>% count(severity, name = "events"), by = "severity") %>%
  mutate(events = ifelse(is.na(events), 0L, events))

# -- charts (same palette as the web and JavaFX dashboards) --------------------

sev_colours <- c(low = "#8b949e", medium = "#d29922", high = "#f0883e", critical = "#f85149")
theme_sn <- theme_minimal(base_size = 12) +
  theme(
    plot.background = element_rect(fill = "#0d1117", colour = NA),
    panel.background = element_rect(fill = "#0d1117", colour = NA),
    panel.grid.major = element_line(colour = "#21262d"),
    panel.grid.minor = element_blank(),
    text = element_text(colour = "#e6edf3"),
    axis.text = element_text(colour = "#8b949e"),
    plot.title = element_text(colour = "#58a6ff", face = "bold"),
    legend.position = "none"
  )
save_chart <- function(plot, name, width, height) {
  ggsave(file.path(out_dir, name), plot, width = width, height = height,
         dpi = 120, bg = "#0d1117")
}
charts <- character(0)

if (nrow(cur) + nrow(prev) > 0) {
  both <- rbind(
    transform(prev_daily, period = "previous"),
    transform(cur_daily, period = "this period")
  )
  save_chart(
    ggplot(both, aes(x = day, y = events, fill = period)) +
      geom_col() +
      scale_fill_manual(values = c(previous = "#30363d", "this period" = "#58a6ff")) +
      labs(title = sprintf("Events per day (last %d days vs previous %d)", period_days, period_days),
           x = NULL, y = "events") +
      theme_sn,
    "events_per_day.png", 9, 4.5)
  charts <- c(charts, "events_per_day")
}

if (nrow(cur) > 0) {
  save_chart(
    ggplot(by_sev, aes(x = severity, y = events, fill = severity)) +
      geom_col() +
      scale_fill_manual(values = sev_colours, drop = FALSE) +
      scale_x_discrete(drop = FALSE) +
      labs(title = "Events by severity", x = NULL, y = "events") +
      theme_sn,
    "severity_split.png", 6, 4.5)

  save_chart(
    ggplot(top_ips, aes(x = reorder(source_ip, events), y = events)) +
      geom_col(fill = "#f0883e") +
      coord_flip() +
      labs(title = "Top attacking IPs", x = NULL, y = "events") +
      theme_sn,
    "top_attackers.png", 7, 5)

  hours <- data.frame(hour = 0:23) %>%
    left_join(cur %>% count(hour, name = "events"), by = "hour") %>%
    mutate(events = ifelse(is.na(events), 0L, events))
  save_chart(
    ggplot(hours, aes(x = hour, y = events)) +
      geom_col(fill = "#58a6ff") +
      scale_x_continuous(breaks = seq(0, 23, 3)) +
      labs(title = "Events by hour of day (UTC)", x = "hour (UTC)", y = "events") +
      theme_sn,
    "hour_of_day.png", 8, 4)
  charts <- c(charts, "severity_split", "top_attackers", "hour_of_day")
}

# -- written report -----------------------------------------------------------

md_table <- function(df) {
  if (nrow(df) == 0) return("_none_")
  cell <- function(x) gsub("\\|", "\\\\|", trimws(as.character(x)))
  rows <- vapply(seq_len(nrow(df)), function(i) {
    paste0("| ", paste(vapply(df[i, ], cell, ""), collapse = " | "), " |")
  }, "")
  paste(c(paste0("| ", paste(names(df), collapse = " | "), " |"),
          paste0("|", paste(rep("---", ncol(df)), collapse = "|"), "|"),
          rows), collapse = "\n")
}
img <- function(name, alt) if (name %in% charts) sprintf("![%s](%s.png)", alt, name) else ""

busiest <- cur_daily[which.max(cur_daily$events), ]
report <- c(
  "# SecureNet Lab - attack report",
  "",
  sprintf("Period: **%s to %s** (%d days, UTC) - baseline: %s to %s - generated %s UTC",
          period_start, today, period_days, base_start, base_end,
          format(Sys.time(), "%Y-%m-%d %H:%M", tz = "UTC")),
  sprintf("Database: `%s`", db_path),
  "",
  "## Overview",
  "",
  md_table(overview),
  ""
)
if (nrow(cur) == 0) {
  report <- c(report, "No attacks were recorded in this period.", "")
} else {
  report <- c(report,
    "## Daily volume",
    "",
    sprintf("Mean %.1f events/day, median %.1f, standard deviation %.1f. Busiest day: %s with %d events.",
            mean(cur_daily$events), median(cur_daily$events),
            ifelse(is.na(sd(cur_daily$events)), 0, sd(cur_daily$events)),
            busiest$day, as.integer(busiest$events)),
    "",
    sprintf("Unusual days: %s", if (nrow(unusual) == 0) "none" else
      paste(sprintf("%s (%d)", unusual$day, as.integer(unusual$events)), collapse = ", ")),
    unusual_note,
    "",
    img("events_per_day", "events per day"),
    "",
    "## By severity",
    "",
    md_table(by_sev),
    "",
    img("severity_split", "events by severity"),
    "",
    "## By attack type",
    "",
    md_table(by_type),
    "",
    "## Top attackers",
    "",
    md_table(top_ips),
    "",
    img("top_attackers", "top attacking IPs"),
    "",
    "## Time of day",
    "",
    sprintf("Busiest hour: %02d:00 UTC.",
            as.integer(names(sort(table(cur$hour), decreasing = TRUE))[1])),
    "",
    img("hour_of_day", "events by hour of day")
  )
}
writeLines(report, file.path(out_dir, "report.md"))

# -- console summary ----------------------------------------------------------

cat(sprintf("SecureNet Lab report %s to %s (%d days)\n", period_start, today, period_days))
print(overview, row.names = FALSE)
cat(sprintf("\nwrote %s\n", normalizePath(file.path(out_dir, "report.md"))))
