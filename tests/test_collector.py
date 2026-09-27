"""
Tests for the log parsers.

The parser is the front door for hostile input, so the edge cases here
matter more than the happy path: truncated lines, missing user agents,
odd request formats, and IPv6-ish sources should all be handled without
raising.
"""

import json

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
