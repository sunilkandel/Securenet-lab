# SecureNet Lab — architecture

A self-hosted network security monitor for a three-VM VirtualBox lab. It
reads the target's logs and IDS output, detects attacks, bans attackers on
the target's firewall, alerts, and reports.

## Machines

All three VMs share a VirtualBox host-only network, `192.168.56.0/24` by
default (the VirtualBox host itself is `192.168.56.1`).

| VM | OS | Role |
|---|---|---|
| Attacker | Kali Linux | nmap, hydra, nikto, sqlmap, gobuster ... |
| Target | Rocky Linux 9 | Apache, sshd, Suricata IDS, firewalld. Set up with `scripts/setup/setup_target.sh` |
| Monitor | Ubuntu Server 24.04 | the Python pipeline, SQLite, REST API, weekly R report. Set up with `scripts/setup/setup_monitor.sh` |

The Java dashboard runs anywhere that can reach the monitor's API.

```
 Kali ──attacks──▶ Rocky target ◀──────────── firewall-cmd over SSH (bans) ─┐
                   ├ /var/log/secure         (sshd)                          │
                   ├ /var/log/httpd/access_log (Apache)                      │
                   └ /var/log/suricata/eve.json (Suricata alerts + flows)    │
                          │                                                  │
                          │ SSH: sudo -n securenet-logread (read-only)       │
                          ▼                                                  │
   Ubuntu monitor:  collector ─▶ detector ─▶ SQLite ─▶ threat intel ─▶ auto-ban
                                                │                 └─▶ alerts: Telegram / email
                                                ├─▶ REST API + web dashboard (:8000) ─▶ JavaFX dashboard
                                                └─▶ weekly R report (analysis/reports/)
```

## Components

| Module | File | Job |
|---|---|---|
| Config | `src/config.py` | One typed `Settings` object from `config.env` (or `SECURENET_CONFIG`). |
| Models / storage | `src/models.py`, `src/storage.py` | Event, Ban, Alert, ThreatIntel records; SQLite persistence. |
| Collector | `src/collector/collector.py` | Tails the target's logs over SSH by byte offset; pure parsers for Apache, sshd, maillog (Postfix/Dovecot) and Suricata EVE lines. |
| Detector | `src/detector/detector.py` | Per-IP sliding windows and signatures turn log records into events. |
| Threat intel | `src/threat_intel/threat_intel.py` | AbuseIPDB lookups with a SQLite cache. |
| Auto-ban | `src/auto_ban/auto_ban.py` | firewalld or ufw rules on the target over SSH; expiry sweep. |
| Alerts | `src/alerts/alerts.py` | Telegram (primary) and SMTP, per-IP cooldown. |
| Orchestrator | `src/orchestrator/main.py` | The loop that wires everything; `--once` for a single cycle. |
| API | `src/api/server.py`, `src/api/static/dashboard.html` | Read-only FastAPI over the DB plus a single-file web dashboard. |
| Java dashboard | `dashboard/` | JavaFX desktop client of the API. |
| R report | `analysis/scripts/attack_analysis.R` | Weekly statistical report into `analysis/reports/<date>/`. |
| Suricata rules | `suricata/rules/custom.rules` | 18 custom signatures (SIDs 9000000+). |

## One pipeline cycle (every `COLLECT_INTERVAL` seconds)

1. **Collect.** For each log file: ask the target for its size, read what
   was appended since the last offset (at most 5 MB per cycle), and consume
   only complete lines. A file that shrank was rotated and is read from the
   top. `eve.json` starts at its current end on first connect, so history is
   not replayed as new attacks.
2. **Detect.** Each record updates its source IP's sliding window
   (`DETECTION_WINDOW`) and may produce events. A per-(IP, event type)
   cooldown stops one sustained attack from producing an event per attempt.
3. **Store** every event and update the IP's risk score.
4. **Threat intel.** Public IPs are looked up in AbuseIPDB (cached for
   `ABUSEIPDB_CACHE_TTL`). Private and loopback addresses are never looked
   up: AbuseIPDB has nothing on them, so in the lab every attacker skips this.
5. **Ban** when the event is high/critical severity, or AbuseIPDB scores the
   IP at or above `ABUSEIPDB_MIN_SCORE`.
6. **Alert** over each configured channel, with a per-IP cooldown
   (`ALERT_COOLDOWN`). Every attempt is recorded in the DB.
7. **Expire** temporary bans whose time is up.

## Detection

| Event type | Source | Trigger | MITRE |
|---|---|---|---|
| `ssh_brute_force` | sshd log, Suricata 9000001 | `BRUTE_FORCE_THRESHOLD` failures in the window (critical at 4x) | T1110 |
| `mail_brute_force` | maillog: Postfix SMTP AUTH, Dovecot IMAP/POP3 | `BRUTE_FORCE_THRESHOLD` failed logins in the window, counted apart from SSH (critical at 4x) | T1110 |
| `port_scan` | Suricata flows, 9000002-9000004 | `PORT_SCAN_THRESHOLD` distinct ports in the window; SYN/NULL/XMAS scans | T1046 |
| `web_enumeration` | Apache log, Suricata 9000030-32 | `WEB_ENUM_THRESHOLD` 404s in the window, or a sensitive path (`/.env`, `/.git`, `/wp-login.php` ...) | T1595.003 |
| `sql_injection` | Apache log, Suricata 9000010-11 | SQLi patterns in the path | T1190 |
| `directory_traversal` | Apache log, Suricata 9000012-14 | `../`, `%2e%2e`, `/etc/passwd` ... | T1083 |
| `suspicious_user_agent` | Apache log, Suricata 9000020-23 | sqlmap, nikto, gobuster, nuclei ... | T1595.002 |
| `ids_alert` | Suricata, any other signature | Shellshock (9000040), reverse shell (9000050, critical), Emerging Threats rules | from the rule |

Log-side and network-side detections of the same attack map to the same
event type, so they share one cooldown instead of alerting twice.

## Auto-ban

- **firewalld** (Rocky default): a temporary ban is a runtime rich rule with
  `--timeout`, so the target lifts it on its own even if the monitor is
  down. A permanent ban (`BAN_DURATION=0`) goes into both the saved and the
  running configuration. There is never a `--reload`: it would wipe every
  timed ban.
- **ufw**: `ufw prepend deny from <ip>`, so the rule sits above any existing
  allow rule. ufw has no timeouts, so the pipeline removes expired bans itself.
- Every remote command runs with `sudo -n`. A missing sudo rule fails at
  once instead of hanging the pipeline on a password prompt.

## Security model

The attacker controls the log lines (usernames, URLs, user agents), the
packets Suricata sees, and (by spoofing) source addresses. The pipeline
turns that input into **root firewall commands on the target**, so input
handling is the core of the design.

| Risk | Defence |
|---|---|
| Command injection via log text (e.g. an SSH username `x from $(cmd)`) | Parsers classify lines by their fixed prefix and take the IP from sshd's fixed tail; anything that is not a literal IP is dropped. Auto-ban validates the IP again and shell-quotes every argument. |
| Locking the pipeline out (a scan spoofing the monitor's address) | Loopback, `TARGET_IP` and `NEVER_BAN` entries are never banned. Put the monitor VM and `192.168.56.1` in `NEVER_BAN`. |
| Over-privileged SSH account | `/etc/sudoers.d/securenet` allows only `firewall-cmd` and `securenet-logread`. The reader only sizes/reads files in `/etc/securenet/logread.allow` and rejects any other path, action or offset. |
| Stored XSS in the web dashboard | Every API value is HTML-escaped before it is inserted; Chart.js is pinned with Subresource Integrity. |
| Secrets in logs | The Telegram bot token is redacted from error messages (requests puts the API URL, token included, in its exceptions). `config.env` is created `chmod 600`. |

Known limits, by design or left for later:

- The REST API is **unauthenticated and read-only**. Expose it only on the
  lab network.
- SSH to the target trusts the host key on first use (`AutoAddPolicy`).
- The monitor's account can change the target's firewall: that is what
  auto-ban needs.
- Spoofed scans can still get a third party's IP banned; `NEVER_BAN`
  protects only the lab's own machines.
- Syslog timestamps have no time zone; the lab VMs should share one.

## Configuration reference

`config.env` in the repository root (created from `config.env.example`),
or the file named by `SECURENET_CONFIG`. The test suite sets
`SECURENET_CONFIG` to an empty file so a real `config.env` never changes
test results.

| Variable | Default | Meaning |
|---|---|---|
| `TARGET_IP` | `192.168.56.20` | Target VM address (never banned) |
| `SSH_USER`, `SSH_PORT`, `SSH_KEY_PATH` | -, `22`, - | Login to the target |
| `APACHE_LOG_PATH` | `/var/log/httpd/access_log` | |
| `SSHD_LOG_PATH` | `/var/log/secure` | |
| `MAIL_LOG_PATH` | `/var/log/maillog` | Read when present; stays empty unless the target runs a mail server |
| `COLLECT_INTERVAL` | `10` | Seconds between cycles |
| `LOG_READ_HELPER` | empty | `/usr/local/sbin/securenet-logread` after `setup_target.sh`; empty = read directly |
| `BRUTE_FORCE_THRESHOLD` | `5` | Failed SSH logins per window |
| `PORT_SCAN_THRESHOLD` | `20` | Distinct ports per window |
| `WEB_ENUM_THRESHOLD` | `10` | 404s per window |
| `DETECTION_WINDOW` | `300` | Sliding window, seconds |
| `SURICATA_ENABLED`, `SURICATA_EVE_PATH` | `true`, `/var/log/suricata/eve.json` | |
| `ABUSEIPDB_API_KEY` | empty | Empty disables lookups |
| `ABUSEIPDB_CACHE_TTL`, `ABUSEIPDB_MIN_SCORE` | `3600`, `50.0` | |
| `AUTO_BAN_ENABLED` | `true` | |
| `BAN_DURATION` | `3600` | Seconds; `0` = permanent |
| `FIREWALL_BACKEND` | `firewalld` | or `ufw` |
| `NEVER_BAN` | empty | Comma-separated IPs/CIDRs |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | empty | |
| `ALERT_COOLDOWN` | `300` | Seconds between alerts for one IP; `0` = none |
| `SMTP_HOST`, `SMTP_PORT`, `ALERT_FROM`, `ALERT_TO` | -, `25`, -, - | Email fallback |
| `API_HOST`, `API_PORT` | `0.0.0.0`, `8000` | |
| `LOG_LEVEL`, `LOG_FORMAT`, `LOG_FILE_ENABLED` | `INFO`, `json`, `true` | Log file: `logs/securenet.log` |

## Testing

- `python -m pytest -q`: unit tests for every module, including hostile
  input, the SSH tailing logic against a scripted fake target, and the
  generated firewall commands.
- `python scripts/smoke_test.py`: end-to-end check without pytest.
- `mvn test` in `dashboard/`: the Java client against JSON captured from
  the real API.
- `suricata -T` validates the rules; `suricata/config/README.md` lists Kali
  commands that should trigger each detection.
