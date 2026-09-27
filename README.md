# Securenet-lab
A self-hosted network security monitoring system with IDS, threat intelligence, auto-ban, and live dashboard. Built on Linux with Python, Java/JavaFX, and R.

## What It Does

- Collects logs in real time from a target Linux server (Apache, SSH, Mail)
- Detects attacks: brute force, port scans, web enumeration
- Checks attacking IPs against AbuseIPDB threat intelligence
- Automatically bans malicious IPs via firewall rules
- Sends real-time alerts via Telegram
- Displays live attack data on a Java/JavaFX desktop dashboard
- Generates weekly statistical reports using R

## Architecture

```
 [Kali attacker] --- attacks ---> [Rocky Linux target]
                                   Apache, sshd, Suricata IDS, firewalld
                                        ^                  |
                  bans: firewall-cmd    |                  | logs + Suricata eve.json,
                  over SSH              |                  | read over SSH
                                        |                  v
                                  [Ubuntu monitor]
                                   Python pipeline:
                                   collector -> detector -> threat intel
                                   -> auto-ban -> alerts (Telegram / email)
                                   SQLite, REST API + web dashboard (:8000),
                                   weekly R report
                                        |
                                        v
                                  Java/JavaFX desktop dashboard
```

Components, data flow, detection rules, security model and every setting:
[docs/architecture.md](docs/architecture.md).

## Tech Stack

| Layer | Technology |
|---|---|
| Infrastructure | VirtualBox, Rocky Linux, Ubuntu, Kali |
| IDS | Suricata |
| Log Pipeline | Python 3.12+ (tested on 3.12 and 3.14) |
| Threat Intelligence | AbuseIPDB API |
| Alerting | Telegram Bot API |
| Dashboard | Java 21 + JavaFX + Maven |
| REST API / web dashboard | FastAPI + uvicorn + Chart.js |
| Analysis | R + ggplot2 |
| Firewall Automation | Python + firewalld + UFW |

## Setup

### Requirements
- VirtualBox 7.x
- Three VMs: Kali Linux, Rocky Linux 9, Ubuntu Server 24.04
- Python 3.12+
- Java 21+
- R 4.x

### Quick Start

1. Clone the repo on the monitor VM, and put a copy on the target VM too
```bash
git clone https://github.com/sunilkandel/Securenet-lab.git
cd Securenet-lab
```

2. Target VM (Rocky Linux), as root: web server, firewall, Suricata, and
   read-only log access for the account the monitor logs in as
```bash
sudo bash scripts/setup/setup_target.sh --user <ssh-user>
```

3. Monitor VM (Ubuntu), as your normal user: Python environment, config,
   SSH key and a self-test. `--with-r` adds the weekly R report, `--systemd`
   runs the pipeline and API as services.
```bash
bash scripts/setup/setup_monitor.sh --with-r
ssh-copy-id -i ~/.ssh/securenet_ed25519.pub <ssh-user>@<target-ip>  # check and accept the host key fingerprint
nano config.env   # both setup scripts print the values to set
```

4. Check one cycle, then run the pipeline and the API
```bash
.venv/bin/python -m src.orchestrator.main --once
.venv/bin/python -m src.orchestrator.main
.venv/bin/python -m src.api.server   # listens on API_HOST:API_PORT (default 0.0.0.0:8000)
```
Web dashboard: `http://<monitor-ip>:8000/`

5. Desktop dashboard (any machine with Java 21 + Maven) and the report
```bash
cd dashboard && SECURENET_API_URL=http://<monitor-ip>:8000 mvn clean javafx:run
Rscript analysis/scripts/attack_analysis.R   # writes analysis/reports/<date>/report.md
```

6. Tests
```bash
.venv/bin/python -m pytest -q
.venv/bin/python scripts/smoke_test.py
```

## Project Status

- [x] Phase 0 — Lab Setup
- [x] Phase 1 — Log Collection
- [x] Phase 2 — Attack Detection
- [x] Phase 3 — Suricata IDS
- [x] Phase 4 — Threat Intelligence + Auto-Ban
- [x] Phase 5 — Alert System
- [x] Phase 6 — Java Dashboard
- [x] Phase 7 — R Analysis
- [x] Phase 8 — Integration


## Documentation

- [docs/architecture.md](docs/architecture.md): components, data flow, detection, security model, configuration
- [suricata/config/README.md](suricata/config/README.md): Suricata on the target, rule notes, Kali test commands
- [dashboard/README.md](dashboard/README.md): the Java desktop dashboard

## Author

**Sunil Kandel** — IT Student, Infomax College / APU Nepal  
Cybersecurity & Ethical Hacking Enthusiast
