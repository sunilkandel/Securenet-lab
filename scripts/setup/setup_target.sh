#!/usr/bin/env bash
# =============================================================================
# SecureNet Lab - target VM setup (Rocky Linux 9). Run as root ON THE TARGET,
# from a copy of this repository:
#
#   sudo bash scripts/setup/setup_target.sh --user <monitor-ssh-user> [options]
#
# Options:
#   --user NAME       account the monitor VM logs in as (required, must exist)
#   --iface NAME      interface Suricata listens on (default: enp0s8)
#   --home-net CIDR   lab network for Suricata's HOME_NET (default: 192.168.56.0/24)
#   --no-suricata     skip installing and configuring Suricata
#
# What it does (safe to re-run):
#   1. installs and starts httpd and firewalld, allows http and ssh
#   2. installs /usr/local/sbin/securenet-logread and its allowlist, so the
#      monitor can read the root-only logs it needs - and no other file
#   3. writes /etc/sudoers.d/securenet, validated with visudo first: the
#      monitor user may run firewall-cmd (auto-ban) and the log reader, only
#   4. installs Suricata 7 (official OISF COPR), sets HOME_NET, the capture
#      interface and custom.rules, checks the config with suricata -T, starts it
# =============================================================================
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
USER_NAME=""
IFACE="enp0s8"
HOME_NET="192.168.56.0/24"
WITH_SURICATA=1

usage() {
  sed -n '3,23p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}
log() { printf '\n==> %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --user)        USER_NAME=${2:?--user needs a value}; shift 2 ;;
    --iface)       IFACE=${2:?--iface needs a value}; shift 2 ;;
    --home-net)    HOME_NET=${2:?--home-net needs a value}; shift 2 ;;
    --no-suricata) WITH_SURICATA=0; shift ;;
    -h|--help)     usage 0 ;;
    *)             echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root: sudo bash $0 --user <name>"
command -v dnf >/dev/null || die "this script is for Rocky/RHEL (dnf not found)"
[ -n "$USER_NAME" ] || die "--user is required (the account the monitor VM logs in as)"
# The name goes into a sudoers file: allow plain account names only.
[[ "$USER_NAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "invalid user name: $USER_NAME"
id "$USER_NAME" >/dev/null 2>&1 || die "user '$USER_NAME' does not exist on this machine"
[[ "$HOME_NET" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || die "--home-net must look like 192.168.56.0/24"
[[ "$IFACE" =~ ^[A-Za-z0-9_.-]+$ ]] || die "invalid interface name: $IFACE"
[ -f "$REPO/scripts/setup/securenet-logread" ] || die "run this from a full copy of the repository"

# -- 1. web server and firewall -------------------------------------------------
log "web server and firewall"
dnf install -y httpd firewalld
systemctl enable --now httpd firewalld
for svc in http ssh; do
  # runtime + permanent instead of --reload, which would drop active timed bans
  firewall-cmd --add-service="$svc" >/dev/null
  firewall-cmd --permanent --add-service="$svc" >/dev/null
done

# -- 2. read-only log access for the monitor ------------------------------------
log "log reader (/usr/local/sbin/securenet-logread)"
install -d -m 0755 -o root -g root /etc/securenet
cat > /etc/securenet/logread.allow <<'EOF'
/var/log/secure
/var/log/httpd/access_log
/var/log/maillog
/var/log/suricata/eve.json
EOF
chown root:root /etc/securenet/logread.allow
chmod 0644 /etc/securenet/logread.allow
install -m 0755 -o root -g root "$REPO/scripts/setup/securenet-logread" /usr/local/sbin/securenet-logread

# -- 3. sudo rules --------------------------------------------------------------
log "sudo rules for $USER_NAME"
FIREWALL_CMD=$(command -v firewall-cmd)
tmp=$(mktemp)
cat > "$tmp" <<EOF
# SecureNet Lab (installed by scripts/setup/setup_target.sh).
# The monitor VM's account may change the firewall (auto-ban) and read the
# monitored logs through the allowlisted reader. Nothing else.
$USER_NAME ALL=(root) NOPASSWD: $FIREWALL_CMD, /usr/local/sbin/securenet-logread
EOF
if ! visudo -cf "$tmp" >/dev/null; then
  rm -f "$tmp"
  die "generated sudoers file failed visudo validation - nothing installed"
fi
install -m 0440 -o root -g root "$tmp" /etc/sudoers.d/securenet
rm -f "$tmp"

# -- 4. Suricata ----------------------------------------------------------------
if [ "$WITH_SURICATA" -eq 1 ]; then
  log "Suricata (OISF COPR, 7.0)"
  dnf install -y epel-release dnf-plugins-core
  dnf copr enable -y @oisf/suricata-7.0
  dnf install -y suricata

  yaml=/etc/suricata/suricata.yaml
  [ -f "$yaml.securenet.bak" ] || cp -p "$yaml" "$yaml.securenet.bak"
  sed -i -E "s|^(    HOME_NET: ).*|\\1\"[$HOME_NET]\"|" "$yaml"
  grep -q '^  - custom.rules$' "$yaml" \
    || sed -i -E 's|^(  - suricata\.rules)$|\1\n  - custom.rules|' "$yaml"
  rules=/var/lib/suricata/rules
  mkdir -p "$rules"   # not install -d: keep the package's owner/mode if it exists
  install -m 0644 "$REPO/suricata/rules/custom.rules" "$rules/custom.rules"
  sed -i -E "s|^OPTIONS=.*|OPTIONS=\"-i $IFACE --user suricata\"|" /etc/sysconfig/suricata

  suricata-update >/dev/null 2>&1 \
    || echo "note: suricata-update failed (no internet?) - running with custom.rules only"
  # Suricata 7 refuses to start (and fails -T) when a listed rule file is
  # missing. Without suricata-update there is no suricata.rules yet, so
  # leave an empty one; a later suricata-update fills it in.
  [ -f "$rules/suricata.rules" ] || install -m 0644 /dev/null "$rules/suricata.rules"
  suricata -T -c "$yaml" >/dev/null \
    || die "suricata -T rejected the config; the original is saved as $yaml.securenet.bak"
  systemctl enable suricata >/dev/null
  systemctl restart suricata
fi

# -- summary --------------------------------------------------------------------
TARGET_IP=$(ip -4 -o addr show "$IFACE" 2>/dev/null | awk '{sub(/\/.*/, "", $4); print $4; exit}')
SHOW_IP=${TARGET_IP:-"<this machine's host-only IP>"}
SHOW_HOST=${TARGET_IP:-"<target>"}
cat <<EOF

Done. On the monitor VM, set these in config.env:

  TARGET_IP=$SHOW_IP
  SSH_USER=$USER_NAME
  LOG_READ_HELPER=/usr/local/sbin/securenet-logread
  FIREWALL_BACKEND=firewalld

Then check the access from the monitor VM:

  ssh $USER_NAME@$SHOW_HOST sudo -n /usr/local/sbin/securenet-logread size /var/log/secure

It should print a number. "a password is required" means the sudo rule is
not active for that account.
EOF
