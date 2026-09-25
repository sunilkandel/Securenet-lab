#!/usr/bin/env bash
# =============================================================================
# SecureNet Lab - monitor VM setup (Ubuntu 24.04). Run from the repository,
# as the normal user that will run the pipeline (sudo is used where needed):
#
#   bash scripts/setup/setup_monitor.sh [--with-r] [--systemd]
#
# Options:
#   --with-r    also install R + packages and a weekly report cron job
#               (Mondays 07:00, analysis/scripts/attack_analysis.R)
#   --systemd   install and start systemd services for the pipeline and API
#
# What it does (safe to re-run; never overwrites an existing config.env):
#   1. installs Python venv support (and R with --with-r) with apt
#   2. creates .venv and installs requirements.txt
#   3. creates config.env from the example, data/ and logs/
#   4. creates an SSH key for logging in to the target
#   5. runs the test suite and the smoke test
#   6. optionally installs the services and the weekly report job
# =============================================================================
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
WITH_R=0
SYSTEMD=0

usage() {
  sed -n '3,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}
log() { printf '\n==> %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --with-r)  WITH_R=1; shift ;;
    --systemd) SYSTEMD=1; shift ;;
    -h|--help) usage 0 ;;
    *)         echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

[ "$(id -u)" -ne 0 ] || die "run as your normal user, not root (sudo is used where needed)"
command -v apt-get >/dev/null || die "this script is for Ubuntu/Debian (apt-get not found)"
cd "$REPO"

# -- 1. packages ----------------------------------------------------------------
log "system packages"
pkgs=(python3-venv python3-pip sqlite3 openssh-client)
if [ "$WITH_R" -eq 1 ]; then
  pkgs+=(r-base-core r-cran-rsqlite r-cran-ggplot2 r-cran-dplyr cron)
fi
# one broken third-party repository should not stop the setup: the
# install below still has to succeed with the package lists we have
sudo apt-get update -qq || echo "warning: apt-get update reported errors - continuing"
sudo apt-get install -y -qq "${pkgs[@]}"

# -- 2. python environment ------------------------------------------------------
log "python environment (.venv)"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt

# -- 3. config and folders ------------------------------------------------------
log "config.env, data/ and logs/"
mkdir -p data logs
if [ -f config.env ]; then
  echo "config.env already exists - left unchanged"
else
  cp config.env.example config.env
  chmod 600 config.env   # it will hold the Telegram token and AbuseIPDB key
  echo "created config.env from config.env.example"
fi

# -- 4. SSH key -----------------------------------------------------------------
log "SSH key for the target"
KEY="$HOME/.ssh/securenet_ed25519"
if [ -f "$KEY" ]; then
  echo "using existing $KEY"
else
  install -d -m 700 "$HOME/.ssh"
  ssh-keygen -q -t ed25519 -N "" -f "$KEY" -C "securenet-monitor@$(hostname)"
  echo "created $KEY"
fi

# -- 5. self-test ---------------------------------------------------------------
log "self-test"
.venv/bin/python -m pytest -q -p no:cacheprovider
.venv/bin/python scripts/smoke_test.py >/dev/null && echo "smoke test passed"

# -- 6a. services ---------------------------------------------------------------
write_unit() {  # name, description, command
  sudo tee "/etc/systemd/system/$1.service" >/dev/null <<EOF
[Unit]
Description=SecureNet Lab $2
After=network-online.target
Wants=network-online.target

[Service]
User=$USER
WorkingDirectory=$REPO
ExecStart=$3
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

if [ "$SYSTEMD" -eq 1 ]; then
  log "systemd services"
  [ -d /run/systemd/system ] || die "--systemd needs a machine running systemd"
  write_unit securenet-pipeline "pipeline" "\"$REPO/.venv/bin/python\" -m src.orchestrator.main"
  write_unit securenet-api "REST API" \
    "\"$REPO/.venv/bin/uvicorn\" src.api.server:app --host 0.0.0.0 --port 8000"
  sudo systemctl daemon-reload
  sudo systemctl enable --now securenet-pipeline securenet-api
  echo "status: systemctl status securenet-pipeline securenet-api"
fi

# -- 6b. weekly report ----------------------------------------------------------
if [ "$WITH_R" -eq 1 ]; then
  log "weekly R report (cron, Mondays 07:00)"
  job="0 7 * * 1 cd \"$REPO\" && Rscript analysis/scripts/attack_analysis.R >> \"$REPO/logs/report.log\" 2>&1"
  # keep every other cron line; replace only our own job
  current=$(crontab -l 2>/dev/null || true)
  others=$(printf '%s\n' "$current" | grep -vF 'analysis/scripts/attack_analysis.R' || true)
  printf '%s\n%s\n' "$others" "$job" | sed '/^$/d' | crontab -
  echo "installed: $job"
fi

# -- next steps -----------------------------------------------------------------
MONITOR_IPS=$(hostname -I 2>/dev/null | tr ' ' ',' | sed 's/,$//')
cat <<EOF

Done. Next steps:

1. On the target (Rocky), from a copy of this repo:
     sudo bash scripts/setup/setup_target.sh --user <ssh-user>

2. Copy the key to the target:
     ssh-copy-id -i $KEY.pub <ssh-user>@<target-ip>

3. Edit config.env here:
     TARGET_IP=<target-ip>
     SSH_USER=<ssh-user>
     SSH_KEY_PATH=$KEY
     LOG_READ_HELPER=/usr/local/sbin/securenet-logread
     NEVER_BAN=192.168.56.1${MONITOR_IPS:+,$MONITOR_IPS}
     TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID / ABUSEIPDB_API_KEY as needed

4. One test cycle:
     .venv/bin/python -m src.orchestrator.main --once
EOF
if [ "$SYSTEMD" -eq 1 ]; then
  echo "   then: sudo systemctl restart securenet-pipeline securenet-api"
else
  cat <<EOF

5. Run it:
     .venv/bin/python -m src.orchestrator.main
     .venv/bin/uvicorn src.api.server:app --host 0.0.0.0 --port 8000
EOF
fi
