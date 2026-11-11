import json

from ntfds import diagnostics

D = {"name": "Router", "ip": "192.168.1.1", "latitude": 33.3, "longitude": 44.4}


def test_crud_and_validation(client):
    r = client.post("/api/devices", json=D)
    assert r.status_code == 201 and r.json["host"] == "192.168.1.1" and r.json["ip"] == "192.168.1.1"
    assert client.post("/api/devices", json=D).status_code == 409
    for bad in [{"name": "x", "host": "1.1.1.1; ls"}, {"name": "", "host": "1.1.1.1"},
                {"name": "x", "host": "1.1.1.2", "check_type": "tcp"},
                {"name": "x", "host": "1.1.1.3", "port": 99999},
                {"name": "x", "host": "1.1.1.4", "latitude": 999, "longitude": 1},
                {"name": "x", "host": "1.1.1.5", "check_type": "http", "check_arg": "javascript:1"},
                {"name": "x", "host": "1.1.1.6", "kind": "toaster"}]:
        assert client.post("/api/devices", json=bad).status_code == 400, bad
    did = r.json["id"]
    u = client.put(f"/api/devices/{did}", json={"name": "Core", "check_type": "tcp", "port": 22, "group": "HQ"})
    assert u.status_code == 200 and u.json["check_type"] == "tcp" and u.json["group"] == "HQ"
    assert len(client.get("/api/devices").json) == 1
    assert client.delete(f"/api/devices/{did}").status_code == 200
    assert client.get(f"/api/devices/{did}").status_code == 404


def test_parent_cycle_rejected_and_reparent_on_delete(client):
    a = client.post("/api/devices", json={"name": "A", "host": "10.0.0.1"}).json["id"]
    b = client.post("/api/devices", json={"name": "B", "host": "10.0.0.2", "parent_id": a}).json["id"]
    c = client.post("/api/devices", json={"name": "C", "host": "10.0.0.3", "parent_id": b}).json["id"]
    assert client.put(f"/api/devices/{a}", json={"parent_id": c}).status_code == 400
    assert client.put(f"/api/devices/{a}", json={"parent_id": a}).status_code == 400
    client.delete(f"/api/devices/{b}")
    assert client.get(f"/api/devices/{c}").json["parent_id"] == a


def test_auth_token(app):
    app.config["API_TOKEN"] = "s3cret"
    c = app.test_client()
    assert c.get("/api/devices").status_code == 401
    assert c.get("/metrics").status_code == 401
    assert c.get("/api/health").status_code == 200
    assert c.get("/api/devices", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.get("/api/devices", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    assert c.get("/api/devices", headers={"X-API-Key": "s3cret"}).status_code == 200


def test_import_export_csv(client):
    csv_body = "name,host,kind,group\nSw1,10.1.1.1,switch,HQ\nBad,1.1.1.1;x,switch,HQ\nSw1dup,10.1.1.1,switch,HQ\n=cmd,10.1.1.2,other,"
    r = client.post("/api/devices/import", data=csv_body, content_type="text/csv")
    assert r.json["added"] == 2 and len(r.json["skipped"]) == 2
    out = client.get("/api/devices/export").get_data(as_text=True)
    assert "'=cmd" in out and "=cmd" not in out.replace("'=cmd", "")   # formula injection neutralised


def test_metrics_incidents_reports(app, client, engine):
    from ntfds.checks import CheckResult
    did = client.post("/api/devices", json={"name": "R", "host": "10.9.9.9"}).json["id"]
    with app.app_context():
        for _ in range(5):
            engine.process(did, CheckResult(True, 12.0, 0.0, 1.0, "ok"))
        engine.process(did, CheckResult(False, None, 100.0, None, "x"))
        engine.process(did, CheckResult(False, None, 100.0, None, "x"))
    m = client.get(f"/api/devices/{did}/metrics?range=1h").json
    assert m["series"] and m["stats"]["samples"] == 5 and m["stats"]["p95"] == 12.0
    assert m["uptime"]["24h"] == round(100 * 6 / 7, 3)  # 1st failed probe is debounced → still counted up
    assert client.get(f"/api/devices/{did}/metrics?range=bogus").status_code == 400
    inc = client.get("/api/incidents?status=open").json
    assert len(inc) == 1 and inc[0]["kind"] == "down"
    assert client.post(f"/api/incidents/{inc[0]['id']}/ack").json["acknowledged"]
    sla = client.get("/api/reports/sla?days=1").json["rows"][0]
    assert sla["incidents"] == 1 and sla["uptime"] is not None
    assert "uptime" in client.get("/api/reports/sla?days=1&format=csv").get_data(as_text=True)
    s = client.get("/api/summary").json
    assert s["total"] == 1 and s["counts"]["Offline"] == 1 and s["open_incidents"] == 1
    prom = client.get("/metrics").get_data(as_text=True)
    assert 'ntfds_device_up{device="R",host="10.9.9.9",group=""} 0' in prom
    assert len(client.get(f"/api/logs/{did}").json) == 7     # legacy endpoint


def test_settings_roundtrip(client):
    assert client.get("/api/settings").json["fail_threshold"] == 2
    assert client.put("/api/settings", json={"fail_threshold": 3, "warn_latency": 99.5}).json["fail_threshold"] == 3
    assert client.put("/api/settings", json={"interval": -1}).status_code == 400


def test_tools_reject_bad_input(client):
    assert client.post("/api/tools/ping", json={"target": "1.1.1.1; id"}).status_code == 400
    assert client.post("/api/tools/ping", json={"target": "-f"}).status_code == 400
    assert client.post("/api/tools/ports", json={"target": "8.8.8.8"}).status_code == 403
    assert client.post("/api/tools/ports", json={"target": "127.0.0.1", "ports": "1-9999"}).status_code == 400
    assert client.post("/api/tools/http", json={"target": "file:///etc/passwd"}).status_code == 400
    assert client.post("/api/discovery", json={"cidr": "8.8.8.0/24"}).status_code == 400
    assert client.post("/api/discovery", json={"cidr": "10.0.0.0/8"}).status_code == 400
    r = client.post("/api/tools/ports", json={"target": "127.0.0.1", "ports": "1-3"})
    assert r.status_code == 200 and r.json["scanned"] == 3


def test_diagnose_verdicts(monkeypatch):
    from ntfds.checks import CheckResult as CR
    monkeypatch.setattr(diagnostics, "default_gateway", lambda: "192.168.1.1")
    calls = {"192.168.1.1": CR(True, 1, 0, 0, "ok"), "1.1.1.1": CR(True, 9, 0, 0, "ok"), "10.0.0.50": CR(False, None, 100, None, "no reply")}
    monkeypatch.setattr(diagnostics, "icmp_check", lambda h, **k: calls[h])
    monkeypatch.setattr(diagnostics, "traceroute", type("T", (), {"__wrapped__": staticmethod(lambda h: {"available": True, "hops": [{"hop": 1, "ip": "192.168.1.1", "rtt": 1}], "reached": False})}))
    r = diagnostics.diagnose("10.0.0.50", reference_hosts=["1.1.1.1"])
    assert r["verdict"] == "target_down" and "192.168.1.1" in r["findings"][0]["text"]
    calls["192.168.1.1"] = CR(False, None, 100, None, "x")
    assert diagnostics.diagnose("10.0.0.50", reference_hosts=["1.1.1.1"])["verdict"] == "local_network"
    calls["192.168.1.1"] = CR(True, 1, 0, 0, "ok"); calls["1.1.1.1"] = CR(False, None, 100, None, "x")
    assert diagnostics.diagnose("10.0.0.50", reference_hosts=["1.1.1.1"])["verdict"] == "wan_down"
    calls["1.1.1.1"] = CR(True, 9, 0, 0, "ok"); calls["10.0.0.50"] = CR(True, 400, 25, 60, "ok")
    r = diagnostics.diagnose("10.0.0.50", reference_hosts=["1.1.1.1"])
    assert r["verdict"] == "degraded" and {f["code"] for f in r["findings"]} == {"packet_loss", "jitter", "high_latency"}


def test_legacy_db_migrates(tmp_path):
    import sqlite3
    from ntfds import create_app
    p = tmp_path / "old.db"
    con = sqlite3.connect(p)
    con.executescript("""CREATE TABLE devices (id INTEGER PRIMARY KEY, name VARCHAR(100) NOT NULL, ip VARCHAR(50) NOT NULL UNIQUE,
        latitude FLOAT, longitude FLOAT, last_status VARCHAR(20), last_response_time FLOAT, last_checked DATETIME);
        CREATE TABLE logs (id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL, status VARCHAR(20) NOT NULL, latency FLOAT, packet_loss FLOAT, timestamp DATETIME);
        INSERT INTO devices (name, ip, last_status) VALUES ('Old', '192.168.0.1', 'Online');
        INSERT INTO logs (device_id, status, latency, packet_loss, timestamp) VALUES (1, 'Online', 5, 0, '2025-01-01 00:00:00');""")
    con.commit(); con.close()
    app = create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{p}", "MONITOR_ENABLED": False})
    d = app.test_client().get("/api/devices").json[0]
    assert d["host"] == "192.168.0.1" and d["enabled"] is True and d["check_type"] == "icmp"
    assert app.test_client().post("/api/devices", json={"name": "New", "host": "192.168.0.2"}).status_code == 201
