"""
Tests for the log parsers.

The parser is the front door for hostile input, so the edge cases here
matter more than the happy path: truncated lines, missing user agents,
odd request formats, and IPv6-ish sources should all be handled without
raising.
"""

from src.collector.collector import parse_apache_line, parse_sshd_line


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