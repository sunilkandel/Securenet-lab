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
[Kali Attacker VM] ──attack──▶ [Rocky Linux Target VM]
│
logs pulled
│
▼
[Ubuntu Monitor VM]
┌─────────────────────┐
│  Python Pipeline    │
│  - Log Collector    │
│  - Attack Detector  │
│  - Threat Intel     │
│  - Auto-Ban         │
│  - Alert System     │
└─────────────────────┘
│
┌─────────────────────┐
│  Java Dashboard     │
│  R Analysis Reports │
└─────────────────────┘



## Tech Stack

| Layer | Technology |
|---|---|
| Infrastructure | VirtualBox, Rocky Linux, Ubuntu, Kali |
| IDS | Suricata |
| Log Pipeline | Python 3.12 |
| Threat Intelligence | AbuseIPDB API |
| Alerting | Telegram Bot API |
| Dashboard | Java 21 + JavaFX + Maven |
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

1. Clone the repo
```bash
   git clone https://github.com/YOUR_USERNAME/securenet-lab.git
   cd securenet-lab
```

2. Copy and fill in your config
```bash
   cp config.env.example config.env
   nano config.env
```

3. Install Python dependencies
```bash
   pip3 install -r requirements.txt
```

4. Run the setup script on Monitor VM
```bash
   bash scripts/setup/setup_monitor.sh
```

5. Start the pipeline
```bash
   python3 src/orchestrator/main.py
```

## Project Status

- [x] Phase 0 — Lab Setup
- [ ] Phase 1 — Log Collection
- [ ] Phase 2 — Attack Detection
- [ ] Phase 3 — Suricata IDS
- [ ] Phase 4 — Threat Intelligence + Auto-Ban
- [ ] Phase 5 — Alert System
- [ ] Phase 6 — Java Dashboard
- [ ] Phase 7 — R Analysis
- [ ] Phase 8 — Integration


## Author

**Sunil Kandel** — IT Student, Infomax College / APU Nepal  
Cybersecurity & Ethical Hacking Enthusiast
