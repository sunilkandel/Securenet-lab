"""
Tests for the log parsers.

The parser is the front door for hostile input, so the edge cases here
matter more than the happy path: truncated lines, missing user agents,
odd request formats, and IPv6-ish sources should all be handled without
raising.
"""

import json
from datetime import timezone

from src.collector.collector import (
    _parser_for,
    parse_apache_line,
    parse_eve_line,
    parse_sshd_line,
)


class TestApacheParser:
    def test_parses_combined_format(self):
        line = (
            '192.168.56.10 - - [10/Oct/2026:13:55:36 -0700] '
            '"GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"'
        )
        rec = parse_apache_line(line)
        assert rec is not None
        assert rec.kind == "apache"
        assert rec.source_ip == "192.168.56.10"
        assert rec.method == "GET"
        assert rec.path == "/index.html"
        assert rec.status == 200
        assert rec.user_agent == "Mozilla/5.0"
        assert rec.timestamp.year == 2026

    def test_captures_scanner_user_agent(self):
        line = (
            '10.0.0.5 - - [11/Oct/2026:02:14:15 +0000] '
            '"GET /admin HTTP/1.1" 404 153 "-" "sqlmap/1.7#stable"'
        )
        rec = parse_apache_line(line)
        assert rec is not None
        assert rec.status == 404
        assert "sqlmap" in rec.user_agent

    def test_captures_sqli_payload_in_path(self):
        line = (
            "10.0.0.5 - - [11/Oct/2026:02:14:15 +0000] "
            '"GET /item?id=1%27+UNION+SELECT+1,2,3-- HTTP/1.1" 500 12 "-" "curl"'
        )
        rec = parse_apache_line(line)
        assert rec is not None
        assert "UNION" in rec.path.upper()
        assert rec.status == 500

    def test_handles_missing_user_agent(self):
        line = (
            "10.0.0.5 - - [11/Oct/2026:02:14:15 +0000] "
            '"GET / HTTP/1.1" 200 5'
        )
        rec = parse_apache_line(line)
        assert rec is not None
        assert rec.status == 200

    def test_malformed_line_returns_none(self):
        assert parse_apache_line("this is not a log line") is None
        assert parse_apache_line("") is None
        assert parse_apache_line("192.168.1.1 ") is None

    def test_odd_but_valid_request_line(self):
        line = (
            '10.0.0.5 - - [11/Oct/2026:02:14:15 +0000] '
            '"OPTIONS * HTTP/1.1" 400 0 "-" "-"'
        )
        rec = parse_apache_line(line)
        assert rec is not None
        assert rec.method == "OPTIONS"


class TestSshdParser:
    def test_parses_failed_password(self):
        line = (
            "Oct 11 22:14:15 srv sshd[1234]: Failed password for root "
            "from 192.168.56.10 port 51234 ssh2"
        )
        rec = parse_sshd_line(line)
        assert rec is not None
        assert rec.kind == "sshd"
        assert rec.action == "failed"
        assert rec.user == "root"
        assert rec.source_ip == "192.168.56.10"

    def test_parses_invalid_user(self):
        line = (
            "Oct 11 22:14:16 srv sshd[1234]: Failed password for invalid "
            "user admin from 192.168.56.10 port 51235 ssh2"
        )
        rec = parse_sshd_line(line)
        assert rec is not None
        assert rec.action == "failed"
        assert rec.user == "admin"

    def test_parses_accepted_password(self):
        line = (
            "Oct 11 22:15:00 srv sshd[1234]: Accepted password for sunil "
            "from 10.0.0.1 port 51236 ssh2"
        )
        rec = parse_sshd_line(line)
        assert rec is not None
        assert rec.action == "accepted"
        assert rec.user == "sunil"

    def test_parses_invalid_user_line(self):
        line = (
            "Oct 11 22:14:17 srv sshd[1234]: Invalid user oracle "
            "from 192.168.56.10 port 51237"
        )
        rec = parse_sshd_line(line)
        assert rec is not None
        assert rec.action == "invalid_user"
        assert rec.user == "oracle"

    def test_ignores_unrelated_lines(self):
        assert parse_sshd_line(
            "Oct 11 22:14:15 srv systemd[1]: Started Session 4."
        ) is None
        assert parse_sshd_line("") is None

    def test_ignores_disconnect_noise(self):
        line = "Oct 11 22:14:20 srv sshd[1234]: Received disconnect from 1.2.3.4"
        assert parse_sshd_line(line) is None


# Real eve.json lines, captured from Suricata 7.0.3 replaying a crafted
# attack pcap against suricata/rules/custom.rules.
EVE_ALERT = (
    '{"timestamp":"2026-10-11T06:26:40.210000+0000","flow_id":124247895338299,'
    '"pcap_cnt":22,"event_type":"alert","src_ip":"192.168.56.10","src_port":40003,'
    '"dest_ip":"192.168.56.20","dest_port":80,"proto":"TCP","pkt_src":"wire/pcap",'
    '"tx_id":0,"alert":{"action":"allowed","gid":1,"signature_id":9000040,"rev":2,'
    '"signature":"SECURENET Shellshock exploitation attempt","category":'
    '"Web Application Attack","severity":1,"metadata":{"mitre_technique":["T1190"]}},'
    '"http":{"hostname":"t","url":"/cgi-bin/x","http_user_agent":'
    '"() { :; }; /bin/bash -c id","http_method":"GET","protocol":"HTTP/1.1",'
    '"status":404,"length":0},"app_proto":"http","direction":"to_server","flow":'
    '{"pkts_toserver":4,"pkts_toclient":2,"bytes_toserver":236,"bytes_toclient":125,'
    '"start":"2026-10-11T06:26:40.160000+0000","src_ip":"192.168.56.10",'
    '"dest_ip":"192.168.56.20","src_port":40003,"dest_port":80}}'
)
EVE_FLOW = (
    '{"timestamp":"2026-10-11T06:26:40.000000+0000","flow_id":162594569519573,'
    '"event_type":"flow","src_ip":"192.168.56.10","src_port":41006,'
    '"dest_ip":"192.168.56.20","dest_port":22,"proto":"TCP","flow":{"pkts_toserver":1,'
    '"pkts_toclient":0,"bytes_toserver":40,"bytes_toclient":0,"start":'
    '"2026-10-11T06:26:40.300000+0000","end":"2026-10-11T06:26:40.300000+0000",'
    '"age":0,"state":"new","reason":"shutdown","alerted":false},"tcp":{"tcp_flags":"12",'
    '"tcp_flags_ts":"12","tcp_flags_tc":"00","syn":true,"ack":true,"state":"syn_sent",'
    '"ts_max_regions":1,"tc_max_regions":1}}'
)


class TestEveParser:
    def test_parses_real_alert(self):
        rec = parse_eve_line(EVE_ALERT)
        assert rec is not None
        assert rec.kind == "suricata"
        assert rec.action == "alert"
        assert rec.source_ip == "192.168.56.10"
        assert rec.dest_ip == "192.168.56.20"
        assert rec.dest_port == 80
        assert rec.signature_id == 9000040
        assert "Shellshock" in rec.signature
        assert rec.ids_severity == 1
        assert rec.mitre_technique == "T1190"
        assert rec.timestamp.year == 2026 and rec.timestamp.tzinfo is not None

    def test_parses_real_flow(self):
        rec = parse_eve_line(EVE_FLOW)
        assert rec is not None
        assert rec.action == "flow"
        assert rec.dest_port == 22
        assert rec.signature_id == 0

    def test_ignores_other_eve_types(self):
        for kind in ("http", "dns", "tls", "stats", "fileinfo"):
            line = json.dumps({"event_type": kind, "src_ip": "1.2.3.4"})
            assert parse_eve_line(line) is None

    def test_malformed_input_returns_none(self):
        for line in ["", "not json", "{", "[]", "42", '"alert"',
                     '{"event_type": "alert"}',                      # no src_ip
                     '{"event_type": "alert", "src_ip": "1.2.3.4"}',  # no alert body
                     '{"event_type": "alert", "src_ip": "1.2.3.4", '
                     '"alert": {"signature_id": "abc"}}']:
            assert parse_eve_line(line) is None, line

    def test_alert_without_metadata(self):
        line = json.dumps({
            "event_type": "alert", "src_ip": "1.2.3.4", "dest_port": 80,
            "alert": {"signature_id": 2010935, "signature": "ET SCAN x",
                      "severity": 2},
        })
        rec = parse_eve_line(line)
        assert rec is not None
        assert rec.mitre_technique == ""
        assert rec.timestamp is None  # missing timestamp tolerated

    def test_bad_port_does_not_drop_record(self):
        line = json.dumps({"event_type": "flow", "src_ip": "1.2.3.4",
                           "dest_port": "http"})
        rec = parse_eve_line(line)
        assert rec is not None and rec.dest_port == 0


class TestParserRouting:
    def test_routes_by_path(self):
        assert _parser_for("/var/log/suricata/eve.json") is parse_eve_line
        assert _parser_for("/var/log/httpd/access_log") is parse_apache_line
        assert _parser_for("/var/log/apache2/other.log") is parse_apache_line
        assert _parser_for("/var/log/secure") is parse_sshd_line


class TestHostileInput:
    """The username in an sshd line is attacker-chosen. It must never be
    able to decide the source IP: that IP ends up in a root firewall
    command on the target."""

    def test_username_cannot_inject_source_ip(self):
        line = ("Oct 11 22:14:15 srv sshd[1]: Failed password for invalid user "
                "x from $(id>/tmp/pwned) from 1.2.3.4 port 22 ssh2")
        rec = parse_sshd_line(line)
        assert rec is not None
        assert rec.source_ip == "1.2.3.4"
        assert "$(id" in rec.user

    def test_username_cannot_fake_the_tail(self):
        line = ("Oct 11 22:14:15 srv sshd[1]: Invalid user "
                "a from 6.6.6.6 port 1 from 1.2.3.4 port 5555")
        rec = parse_sshd_line(line)
        assert rec is not None and rec.source_ip == "1.2.3.4"

    def test_username_cannot_change_classification(self):
        line = ("Oct 11 22:14:15 srv sshd[1]: Invalid user "
                "Accepted password for x from 1.2.3.4 port 5")
        rec = parse_sshd_line(line)
        assert rec is not None and rec.action == "invalid_user"

    def test_non_ip_address_is_dropped(self):
        for bad in ("evil.example.com", "$(reboot)", "1.2.3.4;id", "'", "999.1.1.1"):
            line = f"Oct 11 22:14:15 srv sshd[1]: Failed password for root from {bad} port 22 ssh2"
            assert parse_sshd_line(line) is None, bad

    def test_publickey_line_with_key_suffix(self):
        line = ("Oct 11 22:15:00 srv sshd[1]: Accepted publickey for sunil from "
                "10.0.0.1 port 51236 ssh2: RSA SHA256:abcdef")
        rec = parse_sshd_line(line)
        assert rec is not None and rec.source_ip == "10.0.0.1"

    def test_ipv6_source(self):
        line = "Oct 11 22:14:15 srv sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2"
        rec = parse_sshd_line(line)
        assert rec is not None and rec.source_ip == "2001:db8::1"

    def test_apache_non_ip_client_is_dropped(self):
        line = ('$(id) - - [11/Oct/2026:02:14:15 +0000] '
                '"GET / HTTP/1.1" 200 5 "-" "curl"')
        assert parse_apache_line(line) is None



# -- transport: a fake SSH target that runs the collector's shell commands ----

import shlex as _shlex  # noqa: E402

from src.collector.collector import SSHLogCollector  # noqa: E402
from src.storage import Database  # noqa: E402


class _Stream:
    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data


class FakeTarget:
    """Understands exactly the size/read commands the collector sends,
    with or without the sudo helper, and serves in-memory files."""

    def __init__(self):
        self.files: dict[str, bytes] = {}
        self.denied: set[str] = set()
        self.commands: list[str] = []
        self.grow_during_read: bytes = b""

    # paramiko surface used by the collector
    def get_transport(self):
        return self

    def is_active(self):
        return True

    def exec_command(self, cmd, timeout=None):
        self.commands.append(cmd)
        out, err = self._run(cmd)
        return None, _Stream(out), _Stream(err)

    def close(self):
        pass

    def _run(self, cmd):
        first = cmd.split("|")[0]
        words = _shlex.split(first)
        if words[:2] == ["sudo", "-n"]:
            words = words[3:]                   # drop "sudo -n <helper>"
            action, path = words[0], words[1]
            offset = int(words[2]) if action == "read" else 0
        elif words[0] == "stat":
            action, path, offset = "size", words[3], 0
        else:                                   # tail -c +N path
            action, path, offset = "read", words[3], int(words[2][1:]) - 1
        if action == "size":
            return str(len(self.files.get(path, b""))).encode(), b""
        if path in self.denied:
            return b"", f"tail: cannot open '{path}' for reading: Permission denied".encode()
        data = self.files.get(path, b"")
        if self.grow_during_read:               # writer appended after stat
            data += self.grow_during_read
            self.files[path] = data
            self.grow_during_read = b""
        return data[offset:], b""


SSH1 = b"Oct 11 22:14:15 srv sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
SSH2 = b"Oct 11 22:14:16 srv sshd[1]: Failed password for root from 5.6.7.8 port 22 ssh2\n"


def make_collector(target, helper="", db=None, paths=None):
    col = SSHLogCollector(host="t", user="u",
                          log_paths=paths or ["/var/log/secure"],
                          read_helper=helper, db=db)
    col._client = target
    return col


class TestTransport:
    def test_reads_new_lines_once(self):
        t = FakeTarget(); t.files["/var/log/secure"] = SSH1
        col = make_collector(t)
        assert [r.source_ip for r in col.poll()] == ["1.2.3.4"]
        assert col.poll() == []                          # nothing new
        t.files["/var/log/secure"] += SSH2
        assert [r.source_ip for r in col.poll()] == ["5.6.7.8"]

    def test_partial_line_waits_for_the_rest(self):
        t = FakeTarget(); t.files["/var/log/secure"] = SSH1 + SSH2[:30]
        col = make_collector(t)
        assert [r.source_ip for r in col.poll()] == ["1.2.3.4"]
        t.files["/var/log/secure"] = SSH1 + SSH2        # writer finished the line
        assert [r.source_ip for r in col.poll()] == ["5.6.7.8"]

    def test_growth_between_size_and_read_is_not_read_twice(self):
        t = FakeTarget(); t.files["/var/log/secure"] = SSH1
        t.grow_during_read = SSH2
        col = make_collector(t)
        assert [r.source_ip for r in col.poll()] == ["1.2.3.4", "5.6.7.8"]
        assert col.poll() == []                          # no duplicate of SSH2

    def test_permission_denied_is_reported_and_retried(self, caplog):
        t = FakeTarget(); t.files["/var/log/secure"] = SSH1
        t.denied.add("/var/log/secure")
        col = make_collector(t)
        with caplog.at_level("ERROR"):
            assert col.poll() == []
        assert "Permission denied" in caplog.text and "LOG_READ_HELPER" in caplog.text
        assert col.files[0].offset == 0                  # not skipped past
        t.denied.clear()                                 # access fixed
        assert [r.source_ip for r in col.poll()] == ["1.2.3.4"]

    def test_rotation_restarts_from_the_top(self):
        t = FakeTarget(); t.files["/var/log/secure"] = SSH1 + SSH2
        col = make_collector(t)
        assert len(col.poll()) == 2
        t.files["/var/log/secure"] = SSH1                # rotated: smaller file
        assert [r.source_ip for r in col.poll()] == ["1.2.3.4"]

    def test_helper_mode_uses_sudo_n_and_quotes(self):
        t = FakeTarget(); t.files["/var/log/secure"] = SSH1
        col = make_collector(t, helper="/usr/local/sbin/securenet-logread")
        assert [r.source_ip for r in col.poll()] == ["1.2.3.4"]
        assert t.commands[0] == "sudo -n /usr/local/sbin/securenet-logread size /var/log/secure"
        assert t.commands[1].startswith(
            "sudo -n /usr/local/sbin/securenet-logread read /var/log/secure 0 | head -c ")


class TestTimestampsAndPorts:
    def test_apache_timestamp_keeps_its_offset(self):
        rec = parse_apache_line(
            '1.2.3.4 - - [10/Oct/2026:13:55:36 -0700] "GET / HTTP/1.1" 200 1 "-" "x"'
        )
        assert rec.timestamp.utcoffset().total_seconds() == -7 * 3600
        assert rec.timestamp.astimezone(timezone.utc).hour == 20

    def test_sshd_source_port_parsed(self):
        rec = parse_sshd_line(
            "Oct 11 22:14:17 srv sshd[1]: Invalid user oracle from 10.0.0.9 port 51237"
        )
        assert rec.port == 51237


class TestRestart:
    """Read offsets survive a restart when the collector has a database."""

    def test_restart_does_not_replay_the_log(self, tmp_path):
        db = Database(tmp_path / "c.db")
        t = FakeTarget(); t.files["/var/log/secure"] = SSH1
        first = make_collector(t, db=db)
        assert [r.source_ip for r in first.poll()] == ["1.2.3.4"]

        t.files["/var/log/secure"] += SSH2
        second = make_collector(t, db=db)           # process restarted
        assert [r.source_ip for r in second.poll()] == ["5.6.7.8"]
        db.close()

    def test_restart_after_rotation_reads_new_file(self, tmp_path):
        db = Database(tmp_path / "c.db")
        t = FakeTarget(); t.files["/var/log/secure"] = SSH1 + SSH2
        assert len(make_collector(t, db=db).poll()) == 2
        t.files["/var/log/secure"] = SSH1           # rotated while stopped
        assert [r.source_ip for r in make_collector(t, db=db).poll()] == ["1.2.3.4"]
        db.close()

    def test_eve_resumes_instead_of_skipping_to_end(self, tmp_path):
        db = Database(tmp_path / "c.db")
        eve = "/var/log/suricata/eve.json"
        flow = (json.dumps({"event_type": "flow", "src_ip": "9.9.9.9",
                            "dest_port": 22}) + "\n").encode()
        t = FakeTarget(); t.files[eve] = flow
        col = make_collector(t, db=db, paths=[eve])
        col.files[0].start_at_end = True
        assert col.poll() == []                     # history skipped once
        t.files[eve] += flow                        # arrives while stopped
        again = make_collector(t, db=db, paths=[eve])
        again.files[0].start_at_end = True
        assert [r.source_ip for r in again.poll()] == ["9.9.9.9"]
        db.close()
