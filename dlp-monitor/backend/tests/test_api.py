from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.policy import evaluate_download

AGENT = {"X-Agent-Key": "agent-test"}
ADMIN = {"Authorization": "Bearer admin-test"}


@pytest.fixture
def client(tmp_path):
    s = Settings()
    s.db_path = str(tmp_path / "t.db")
    s.agent_key = "agent-test"
    s.admin_token = "admin-test"
    s.default_download_allowed = False
    s.alert_webhook_url = ""
    s.telegram_bot_token = ""
    s.burst_threshold = 3
    return TestClient(create_app(s))


def check(client, user, filename="a.pdf", size=1000):
    return client.post("/api/agent/check-download", headers=AGENT,
                       json={"username": user, "url": "https://portal/x/" + filename,
                             "filename": filename, "size_bytes": size}).json()


def test_auth_required(client):
    assert client.post("/api/agent/check-download", json={"username": "a"}).status_code == 401
    assert client.get("/api/admin/users").status_code == 401
    assert client.get("/api/admin/users", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_unknown_user_blocked_and_alerted(client):
    r = check(client, "Nguyen.Van.A")
    assert r["allowed"] is False
    alerts = client.get("/api/admin/alerts", headers=ADMIN).json()
    kinds = {a["kind"] for a in alerts}
    assert {"download_blocked", "new_user"} <= kinds
    users = client.get("/api/admin/users", headers=ADMIN).json()
    assert users[0]["username"] == "nguyen.van.a"  # đã chuẩn hóa chữ thường


def test_admin_grants_permission(client):
    client.put("/api/admin/users/bob", headers=ADMIN, json={"download_allowed": True})
    assert check(client, "bob")["allowed"] is True
    client.put("/api/admin/users/bob", headers=ADMIN, json={"download_allowed": False})
    assert check(client, "bob")["allowed"] is False


def test_extension_and_size_rules(client):
    client.put("/api/admin/users/c", headers=ADMIN,
               json={"download_allowed": True, "allowed_extensions": "pdf, .xlsx", "max_size_mb": 1})
    assert check(client, "c", "r.pdf")["allowed"] is True
    assert check(client, "c", "r.XLSX")["allowed"] is True
    assert check(client, "c", "dump.zip")["allowed"] is False
    assert check(client, "c", "big.pdf", size=2 * 1024 * 1024)["allowed"] is False


def test_temporary_permission_expiry():
    s = Settings()
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    assert not evaluate_download({"download_allowed": 1, "allow_until": past}, "a.pdf", 1, s).allowed
    assert evaluate_download({"download_allowed": 1, "allow_until": future}, "a.pdf", 1, s).allowed


def test_locked_user(client):
    client.put("/api/admin/users/d", headers=ADMIN, json={"download_allowed": True, "login_allowed": False})
    assert check(client, "d")["allowed"] is False
    client.post("/api/agent/event", headers=AGENT, json={"username": "d", "type": "login"})
    kinds = [a["kind"] for a in client.get("/api/admin/alerts", headers=ADMIN).json()]
    assert "blocked_user_login" in kinds


def test_burst_escalates_to_high(client):
    for _ in range(3):
        check(client, "e")
    alerts = [a for a in client.get("/api/admin/alerts", headers=ADMIN).json() if a["kind"] == "download_blocked"]
    assert alerts[0]["severity"] == "high"  # mới nhất
    assert alerts[-1]["severity"] == "medium"


def test_events_and_ack(client):
    r = client.post("/api/agent/event", headers=AGENT, json={"username": "f", "type": "bogus"})
    assert r.status_code == 400
    client.post("/api/agent/event", headers=AGENT, json={"username": "f", "type": "login"})
    ev = client.get("/api/admin/events?username=f&type=login", headers=ADMIN).json()
    assert len(ev) == 1
    alert = client.get("/api/admin/alerts?only_open=true", headers=ADMIN).json()[0]
    client.post(f"/api/admin/alerts/{alert['id']}/ack", headers=ADMIN, json={"by": "it"})
    ids = [a["id"] for a in client.get("/api/admin/alerts?only_open=true", headers=ADMIN).json()]
    assert alert["id"] not in ids


def test_brute_force_alert(client):
    for _ in range(5):
        client.post("/api/agent/event", headers=AGENT, json={"username": "g", "type": "login_failed"})
    kinds = [a["kind"] for a in client.get("/api/admin/alerts", headers=ADMIN).json()]
    assert "brute_force" in kinds


def test_gateway(client):
    h = {**AGENT, "X-Portal-User": "h", "X-Original-URI": "/files/report.xlsx"}
    assert client.get("/api/gate", headers=h).status_code == 403
    client.put("/api/admin/users/h", headers=ADMIN, json={"download_allowed": True})
    assert client.get("/api/gate", headers=h).status_code == 204
    h2 = {**AGENT, "X-Portal-User": "h", "X-Original-URI": "/home"}
    assert client.get("/api/gate", headers=h2).status_code == 204
    h3 = {**AGENT, "X-Portal-User": "h", "X-Original-URI": "/login", "X-Original-Method": "POST"}
    assert client.get("/api/gate", headers=h3).status_code == 204
    assert client.get("/api/admin/events?type=login", headers=ADMIN).json()[0]["source"] == "gateway"


def test_stats_and_dashboard(client):
    check(client, "i")
    s = client.get("/api/admin/stats", headers=ADMIN).json()
    assert s["last_24h"]["download_blocked"] == 1
    assert s["open_alerts"] >= 1
    assert "DLP Portal Monitor" in client.get("/").text
