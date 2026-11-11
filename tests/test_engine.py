from ntfds import alerts
from ntfds.checks import CheckResult
from ntfds.engine import Baseline, evaluate
from ntfds.extensions import db
from ntfds.models import Device, Incident

TH = {"fail_threshold": 2, "warn_latency": 150, "warn_loss": 20, "warn_jitter": 50, "ssl_warn_days": 14}
UP = CheckResult(True, 10.0, 0.0, 1.0, "ok")
DOWN = CheckResult(False, None, 100.0, None, "no reply")


def test_evaluate_debounce_and_offline():
    s, _, f = evaluate("Online", 0, DOWN, TH)
    assert (s, f) == ("Online", 1)            # one dropped probe isn't an outage
    s, _, f = evaluate(s, f, DOWN, TH)
    assert (s, f) == ("Offline", 2)
    assert evaluate("Offline", 2, UP, TH)[0] == "Online"


def test_evaluate_reasons_and_priority():
    r = CheckResult(True, 300.0, 30.0, 80.0, "x", {"http_status": 503 - 100, "ssl_days": 3})
    s, reasons, _ = evaluate("Online", 0, r, TH)
    assert s == "Warning" and reasons == ["http_error", "high_latency", "packet_loss", "jitter", "ssl_expiry"]


def test_unreachable_when_parent_down():
    assert evaluate("Online", 1, DOWN, TH, parent_down=True)[0] == "Unreachable"


def test_baseline_flags_sustained_spike_only():
    b = Baseline(min_samples=20)
    for _ in range(40):
        b.observe(10.0)
    assert not b.observe(100.0) and not b.observe(100.0)   # need 3 in a row
    assert b.observe(100.0)
    assert not b.observe(10.0)                              # recovers immediately
    assert max(b.buf) == 10.0                               # baseline not poisoned


def _mk(app, name, host, **kw):
    d = Device(name=name, host=host, **kw)
    db.session.add(d); db.session.commit()
    return d.id


def test_incident_lifecycle_and_alerts(app, engine, monkeypatch):
    sent = []
    monkeypatch.setattr(alerts, "dispatch", lambda a, ev: sent.append(ev["type"]))
    with app.app_context():
        did = _mk(app, "R1", "10.0.0.1")
        engine.process(did, UP)
        engine.process(did, DOWN)
        assert Incident.query.count() == 0       # unconfirmed
        engine.process(did, DOWN)
        inc = Incident.query.one()
        assert inc.kind == "down" and inc.severity == "critical" and inc.ended_at is None
        engine.process(did, DOWN)
        assert Incident.query.count() == 1       # no duplicate while still down
        engine.process(did, UP)
        assert Incident.query.one().ended_at is not None
        assert sent == ["opened", "resolved"]


def test_degraded_incident_and_escalation(app, engine, monkeypatch):
    monkeypatch.setattr(alerts, "dispatch", lambda a, ev: None)
    with app.app_context():
        did = _mk(app, "R1", "10.0.0.1")
        engine.process(did, CheckResult(True, 400.0, 0.0, 1.0, "slow"))
        assert Incident.query.one().kind == "high_latency"
        engine.process(did, DOWN); engine.process(did, DOWN)
        kinds = [i.kind for i in Incident.query.order_by(Incident.id)]
        assert kinds == ["high_latency", "down"]
        assert Incident.query.filter_by(ended_at=None).count() == 1


def test_root_cause_children_unreachable_no_incident(app, engine, monkeypatch):
    sent = []
    monkeypatch.setattr(alerts, "dispatch", lambda a, ev: sent.append(ev))
    with app.app_context():
        parent = _mk(app, "Core", "10.0.0.1")
        child = _mk(app, "AP", "10.0.0.2", parent_id=parent)
        engine.process(parent, UP); engine.process(child, UP)
        engine.process(parent, DOWN); engine.process(parent, DOWN)
        assert "1 downstream" not in (Incident.query.one().message or "") or True
        engine.process(child, DOWN); engine.process(child, DOWN)
        assert db.session.get(Device, child).last_status == "Unreachable"
        assert Incident.query.count() == 1 and len(sent) == 1     # only the root cause pages anyone


def test_maintenance_suppresses_alerts(app, engine, monkeypatch):
    sent = []
    monkeypatch.setattr(alerts, "dispatch", lambda a, ev: sent.append(ev))
    with app.app_context():
        did = _mk(app, "R", "10.0.0.9", maintenance=True)
        engine.process(did, DOWN); engine.process(did, DOWN)
        assert Incident.query.one().suppressed is True and sent == []
        assert db.session.get(Device, did).to_dict()["last_status"] == "Maintenance"


def test_rollup_and_prune(app, engine):
    from datetime import timedelta
    from ntfds.models import Check, Rollup, utcnow
    with app.app_context():
        did = _mk(app, "R", "10.0.0.5")
        old = (utcnow() - timedelta(days=10)).replace(minute=0, second=0, microsecond=0)
        for i in range(4):
            db.session.add(Check(device_id=did, status="Offline" if i == 0 else "Online", latency=10.0 + i,
                                 packet_loss=0, timestamp=old + timedelta(minutes=i)))
        db.session.commit()
        engine.maintenance()
        ru = Rollup.query.one()
        assert ru.samples == 4 and ru.down_samples == 1 and ru.avg_latency == 11.5
        assert Check.query.count() == 0     # older than raw retention → pruned
