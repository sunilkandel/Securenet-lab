"""
Tests for the FastAPI endpoints.

Uses TestClient with the app pointed at a throwaway database, so the
tests never read the real data/securenet.db. The API is read-only, so
each test seeds the DB directly and checks the JSON shape.
"""

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from src.models import Ban, Event, EventType, Severity  # noqa: E402
from src.storage import Database  # noqa: E402


@pytest.fixture
def client(tmp_path) -> TestClient:
    db_path = tmp_path / "api.db"
    db = Database(db_path)
    db.insert_event(Event(
        source_ip="1.2.3.4",
        event_type=EventType.SSH_BRUTE_FORCE,
        severity=Severity.HIGH,
        details={"attempts": 7},
    ))
    db.insert_event(Event(
        source_ip="5.6.7.8",
        event_type=EventType.PORT_SCAN,
        severity=Severity.CRITICAL,
    ))
    db.insert_ban(Ban(ip="1.2.3.4", reason="brute force"))
    db.close()

    import src.api.server as server
    server.configure_database(db_path)

    yield TestClient(server.app)
    server.configure_database(None)  # restore the settings default


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_stats(client):
    body = client.get("/api/stats").json()
    assert body["total_events"] == 2
    assert body["active_bans"] == 1
    assert body["unique_attackers"] == 2


def test_events_list(client):
    body = client.get("/api/events").json()
    assert len(body) == 2
    assert {"source_ip", "event_type", "severity", "timestamp"} <= body[0].keys()


def test_events_filtered_by_ip(client):
    body = client.get("/api/events?ip=1.2.3.4").json()
    assert len(body) == 1
    assert body[0]["source_ip"] == "1.2.3.4"


def test_events_limit_validation(client):
    assert client.get("/api/events?limit=0").status_code == 422
    assert client.get("/api/events?limit=99999").status_code == 422


def test_bans_endpoint(client):
    body = client.get("/api/bans").json()
    assert len(body) == 1
    assert body[0]["ip"] == "1.2.3.4"


def test_top_attackers(client):
    body = client.get("/api/top-attackers").json()
    assert len(body) == 2


def test_timeseries_shape(client):
    body = client.get("/api/timeseries?days=7").json()
    assert isinstance(body, list)


def test_dashboard_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "SecureNet" in resp.text



def test_dashboard_escapes_all_api_values(client):
    """Every ${...} rendered through innerHTML goes through esc()."""
    import re
    html = client.get("/").text
    templates = re.findall(r"innerHTML = .*?\.join", html, re.S)
    assert len(templates) == 3
    for t in templates:
        for expr in re.findall(r"\$\{(.*?)\}", t):
            assert expr.startswith("esc("), expr


def test_dashboard_pins_chartjs_with_sri(client):
    html = client.get("/").text
    assert 'integrity="sha384-' in html
    assert "chart.umd.min.js" not in html  # not a published, stable file


def test_top_attackers_reports_worst_severity(client):
    body = client.get("/api/top-attackers").json()
    worst = {t["ip"]: t["worst_severity"] for t in body}
    assert worst == {"1.2.3.4": "high", "5.6.7.8": "critical"}
