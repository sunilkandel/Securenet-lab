# Suricata setup (target VM)

Suricata runs on the **Rocky Linux target VM**, the machine being attacked,
so it sees every packet aimed at it. It writes its detections to
`/var/log/suricata/eve.json`, and the monitor VM's collector pulls that file
over SSH, the same way it pulls the Apache and sshd logs.

```
[Kali] --attack--> [Rocky target: Apache, sshd, Suricata -> eve.json]
                                  |
                   SSH (tail by byte offset)
                                  v
            [Ubuntu monitor: collector -> detector -> ban / alert]
```

The pipeline reads two kinds of EVE records and ignores the rest:

| EVE record | Used for |
|---|---|
| `alert` | A rule in `../rules/custom.rules` (or any other loaded rule) fired. Custom SIDs map onto the pipeline's own event types (brute force, SQLi, ...), everything else becomes `ids_alert`. |
| `flow` | One per connection. Distinct destination ports per source IP feed port-scan detection. |

## 1. Install (Rocky Linux 9)

From the official Suricata docs (OISF COPR repository):

```bash
sudo dnf install -y epel-release dnf-plugins-core
sudo dnf copr enable -y @oisf/suricata-7.0
sudo dnf install -y suricata
```

The rules were validated against **Suricata 7.0.3**. The same COPR also
offers `@oisf/suricata-8.0`; the rules use only keywords that exist in 8.0,
but that version has not been tested with them.

## 2. Configure

**Capture interface.** The RPM runs Suricata as the `suricata` user and
reads its command line from `/etc/sysconfig/suricata`. Set the interface
on the host-only network (find it with `ip -br addr`, usually `enp0s8`):

```bash
sudo sed -i 's/^OPTIONS=.*/OPTIONS="-i enp0s8 --user suricata"/' /etc/sysconfig/suricata
```

**`/etc/suricata/suricata.yaml`:** three settings.

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.56.0/24]"      # the lab's host-only network

rule-files:
  - suricata.rules                     # keep the default set
  - custom.rules                       # add SecureNet's rules

outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
      filemode: 640                    # group-readable, see step 3
      types:
        - alert:
            metadata: yes              # carries the MITRE technique IDs
        - flow                         # required for port-scan counting
```

**Install the rules:**

```bash
sudo cp suricata/rules/custom.rules /var/lib/suricata/rules/custom.rules
sudo suricata -T -c /etc/suricata/suricata.yaml   # must end with "successfully loaded"
sudo systemctl enable --now suricata
```

## 3. Let the collector read eve.json

The collector logs in as `SSH_USER` from `config.env` and cannot read a
root/suricata-only file. Put that user in the `suricata` group (which is
why `filemode: 640` above):

```bash
sudo usermod -aG suricata <SSH_USER>
sudo chmod 640 /var/log/suricata/eve.json
```

Log out and back in as that user, then check: `tail -n1 /var/log/suricata/eve.json`.

On the monitor side nothing else is needed: `SURICATA_ENABLED=true` (the
default) makes the collector tail `SURICATA_EVE_PATH`. On first connect it
starts at the **end** of eve.json rather than replaying old history as new
attacks.

## 4. Verify from Kali

Each command should produce the listed events on the monitor
(`python -m src.orchestrator.main --once`, or the API at `/api/events`):

| From Kali | Expected event |
|---|---|
| `sudo nmap -sS -p1-100 <target>` | `port_scan` |
| `sudo nmap -sN <target>` / `-sX` | `port_scan` (NULL / XMAS scan SIDs) |
| `nikto -h http://<target>` | `suspicious_user_agent` |
| `curl "http://<target>/item?id=1%20UNION%20SELECT%201"` | `sql_injection` |
| `curl --path-as-is "http://<target>/../../etc/passwd"` | `directory_traversal` |
| `curl http://<target>/.env` | `web_enumeration` |

## Rule notes

All SIDs are in the 9000000+ range, clear of Emerging Threats. Fixes made
while validating (each rule's `rev` was bumped):

- **9000001**: added `flow:to_server`. Without a direction, Suricata
  disabled the rule for the reverse side and warned at load time.
- **9000012**: switched to `http.uri.raw`. The normalized `http.uri`
  buffer collapses `/../../etc/passwd` to `/etc/passwd` before matching,
  so the `../` content could never hit. Added **9000014** for the
  URL-encoded `%2e%2e` variant.
- **9000040**: one `http.header` buffer with `"() {"` instead of declaring
  the buffer twice (duplicate-buffer warning).
