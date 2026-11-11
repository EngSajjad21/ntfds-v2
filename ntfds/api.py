import csv
import io
import json
import math
import time
from datetime import timedelta

from flask import Blueprint, Response, current_app, jsonify, request

from . import analytics, alerts, diagnostics
from .extensions import db, socketio
from .models import CHECK_TYPES, DEVICE_KINDS, Channel, Check, Device, Incident, iso, utcnow
from .security import auth_required_response, is_private_target, valid_host, valid_port, valid_url
from .settings import get_settings, save_settings

bp = Blueprint("api", __name__)


@bp.before_request
def _auth():
    if request.endpoint in ("api.health",):
        return None
    return auth_required_response()


def engine():
    return current_app.extensions["ntfds_engine"]


def err(msg, code=400):
    return jsonify({"error": msg}), code


def _num(v, lo=None, hi=None):
    if v in (None, ""):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise ValueError("not a number")
    if math.isnan(f) or math.isinf(f) or (lo is not None and f < lo) or (hi is not None and f > hi):
        raise ValueError("out of range")
    return f


def clean_device(data, existing=None):
    """Validate and normalise a device payload. Returns (fields, error)."""
    f = {}
    try:
        if "name" in data or not existing:
            name = str(data.get("name", "")).strip()
            if not name or len(name) > 100:
                return None, "name is required (max 100 chars)"
            f["name"] = name
        if "host" in data or "ip" in data or not existing:
            host = str(data.get("host") or data.get("ip") or "").strip()
            if not valid_host(host):
                return None, "invalid host / IP address"
            f["host"] = host
        if "latitude" in data or "longitude" in data:
            f["latitude"] = _num(data.get("latitude"), -90, 90)
            f["longitude"] = _num(data.get("longitude"), -180, 180)
            if (f["latitude"] is None) != (f["longitude"] is None):
                f["latitude"] = f["longitude"] = None
        if "kind" in data:
            if data["kind"] not in DEVICE_KINDS:
                return None, "invalid kind"
            f["kind"] = data["kind"]
        for k, mx in (("group", 60), ("notes", 2000)):
            if k in data:
                v = (data[k] or "").strip()
                if len(v) > mx:
                    return None, f"{k} too long"
                f[k] = v or None
        ctype = data.get("check_type", existing.check_type if existing else "icmp") or "icmp"
        if ctype not in CHECK_TYPES:
            return None, "invalid check_type"
        f["check_type"] = ctype
        if "port" in data:
            p = data["port"]
            if p in (None, ""):
                f["port"] = None
            else:
                p = int(p)
                if not valid_port(p):
                    return None, "invalid port"
                f["port"] = p
        port = f.get("port", existing.port if existing else None)
        if ctype == "tcp" and not port:
            return None, "tcp check needs a port"
        if "check_arg" in data:
            a = (data["check_arg"] or "").strip()
            if a and ctype == "http" and not valid_url(a):
                return None, "check_arg must be an http(s) URL"
            if a and ctype == "dns" and not valid_host(a):
                return None, "check_arg must be a DNS name"
            f["check_arg"] = a or None
        if "interval" in data:
            v = _num(data["interval"], 2, 86400)
            f["interval"] = int(v) if v else None
        if "warn_latency" in data:
            f["warn_latency"] = _num(data["warn_latency"], 1, 60000)
        if "warn_loss" in data:
            f["warn_loss"] = _num(data["warn_loss"], 1, 100)
        for k in ("enabled", "maintenance"):
            if k in data:
                f[k] = bool(data[k])
        if "parent_id" in data:
            pid = data["parent_id"]
            if pid in (None, "", 0):
                f["parent_id"] = None
            else:
                pid = int(pid)
                if not db.session.get(Device, pid):
                    return None, "parent device not found"
                cur, seen = pid, set()
                while cur and cur not in seen:   # refuse cycles
                    if existing and cur == existing.id:
                        return None, "parent would create a loop"
                    seen.add(cur)
                    p = db.session.get(Device, cur)
                    cur = p.parent_id if p else None
                f["parent_id"] = pid
    except (ValueError, TypeError) as e:
        return None, f"invalid value: {e}"
    return f, None


# ─────────────── meta ───────────────

@bp.get("/health")
def health():
    eng = engine()
    return jsonify({"status": "ok", "engine": bool(eng.thread and eng.thread.is_alive()),
                    "auth": bool(current_app.config["API_TOKEN"]), "time": iso(utcnow())})


@bp.get("/summary")
def summary():
    devs = Device.query.all()
    counts = {s: 0 for s in ("Online", "Warning", "Offline", "Unreachable", "Maintenance", "Unknown")}
    for d in devs:
        counts[d.to_dict()["last_status"]] = counts.get(d.to_dict()["last_status"], 0) + 1
    lats = [d.last_response_time for d in devs if d.last_response_time is not None and d.last_status != "Offline"]
    ups = [u for u in (analytics.uptime(d.id, 86400) for d in devs) if u is not None]
    return jsonify({"total": len(devs), "counts": counts,
                    "avg_latency": round(sum(lats) / len(lats), 2) if lats else None,
                    "uptime_24h": round(sum(ups) / len(ups), 3) if ups else None,
                    "open_incidents": Incident.query.filter_by(ended_at=None, suppressed=False).count(),
                    "kinds": DEVICE_KINDS, "check_types": CHECK_TYPES,
                    "local": {"ip": diagnostics.local_ip(), "gateway": diagnostics.default_gateway()}})


@bp.route("/settings", methods=["GET", "PUT"])
def settings():
    if request.method == "PUT":
        errors = save_settings(request.get_json(silent=True) or {})
        if errors:
            return jsonify({"error": "invalid settings", "fields": errors}), 400
        engine().reload()
    return jsonify(get_settings())


# ─────────────── devices ───────────────

@bp.get("/devices")
def list_devices():
    return jsonify([d.to_dict() for d in Device.query.order_by(Device.name).all()])


@bp.post("/devices")
def add_device():
    f, e = clean_device(request.get_json(silent=True) or {})
    if e:
        return err(e)
    if Device.query.filter_by(host=f["host"]).first():
        return err("Device with this host already exists", 409)
    d = Device(**f)
    db.session.add(d)
    db.session.commit()
    engine().reload()
    socketio.emit("device_added", d.to_dict())
    return jsonify(d.to_dict()), 201


@bp.get("/devices/<int:did>")
def get_device(did):
    return jsonify(db.get_or_404(Device, did).to_dict())


@bp.put("/devices/<int:did>")
def update_device(did):
    d = db.get_or_404(Device, did)
    f, e = clean_device(request.get_json(silent=True) or {}, existing=d)
    if e:
        return err(e)
    if "host" in f and f["host"] != d.host and Device.query.filter_by(host=f["host"]).first():
        return err("Device with this host already exists", 409)
    for k, v in f.items():
        setattr(d, k, v)
    if "check_type" in f or "host" in f or "port" in f:
        d.consecutive_failures = 0
    db.session.commit()
    engine().reload()
    socketio.emit("device_updated", d.to_dict())
    return jsonify(d.to_dict())


@bp.delete("/devices/<int:did>")
def delete_device(did):
    d = db.get_or_404(Device, did)
    Device.query.filter_by(parent_id=did).update({"parent_id": d.parent_id})
    db.session.delete(d)
    db.session.commit()
    engine().reload()
    socketio.emit("device_removed", {"id": did})
    return jsonify({"message": "Device deleted"})


@bp.post("/devices/<int:did>/check")
def check_now(did):
    d = engine().check_now(did)
    return jsonify(d.to_dict()) if d else err("not found", 404)


@bp.post("/devices/<int:did>/diagnose")
def diagnose_device(did):
    d = db.get_or_404(Device, did)
    try:
        return jsonify(diagnostics.diagnose(d.host, d.check_type, d.port, d.check_arg if d.check_type == "http" else None,
                                            current_app.config["DIAG_REFERENCE_HOSTS"]))
    except diagnostics.Busy as e:
        return err(str(e), 429)


@bp.get("/devices/<int:did>/metrics")
def device_metrics(did):
    db.get_or_404(Device, did)
    rng = request.args.get("range", "1h")
    if rng not in analytics.RANGES:
        return err("invalid range")
    return jsonify({"series": analytics.series(did, rng), "stats": analytics.device_stats(did, rng),
                    "uptime": {k: analytics.uptime(did, s) for k, s in (("24h", 86400), ("7d", 7 * 86400), ("30d", 30 * 86400))}})


@bp.get("/logs/<int:did>")   # kept for backward compatibility
def device_logs(did):
    limit = min(request.args.get("limit", 50, type=int), 1000)
    rows = Check.query.filter_by(device_id=did).order_by(Check.timestamp.desc()).limit(limit).all()
    return jsonify([r.to_dict() for r in rows])


@bp.get("/devices/export")
def export_devices():
    cols = ["name", "host", "kind", "group", "check_type", "port", "check_arg", "interval", "latitude", "longitude", "notes"]
    rows = [d.to_dict() for d in Device.query.order_by(Device.name)]
    if request.args.get("format") == "json":
        return jsonify([{c: r[c] for c in cols} for r in rows])
    return _csv(cols, rows, "devices.csv")


@bp.post("/devices/import")
def import_devices():
    """Accepts JSON list, or text/csv with a header row (name,host,…)."""
    if request.is_json:
        items = request.get_json(silent=True)
    else:
        items = list(csv.DictReader(io.StringIO(request.get_data(as_text=True))))
    if not isinstance(items, list) or len(items) > 2000:
        return err("expected a list of ≤2000 devices")
    added, skipped = 0, []
    for i, it in enumerate(items):
        it = {k: (v if v != "" else None) for k, v in it.items() if isinstance(it, dict)}
        f, e = clean_device(it)
        if e or Device.query.filter_by(host=(f or {}).get("host")).first():
            skipped.append({"row": i + 1, "reason": e or "duplicate host"})
            continue
        db.session.add(Device(**f))
        added += 1
    db.session.commit()
    engine().reload()
    socketio.emit("device_added", {})
    return jsonify({"added": added, "skipped": skipped})


# ─────────────── incidents ───────────────

@bp.get("/incidents")
def list_incidents():
    q = Incident.query
    st = request.args.get("status")
    if st == "open":
        q = q.filter(Incident.ended_at.is_(None))
    elif st == "resolved":
        q = q.filter(Incident.ended_at.isnot(None))
    if request.args.get("device_id", type=int):
        q = q.filter_by(device_id=request.args.get("device_id", type=int))
    rows = q.order_by(Incident.started_at.desc()).limit(min(request.args.get("limit", 100, type=int), 1000)).all()
    return jsonify([i.to_dict() for i in rows])


@bp.post("/incidents/<int:iid>/ack")
def ack_incident(iid):
    i = db.get_or_404(Incident, iid)
    i.acknowledged, i.acknowledged_at = True, utcnow()
    db.session.commit()
    socketio.emit("incident_ack", i.to_dict())
    return jsonify(i.to_dict())


# ─────────────── reports ───────────────

@bp.get("/reports/sla")
def sla():
    days = min(max(request.args.get("days", 30, type=int), 1), 365)
    rows = analytics.sla_report(days)
    if request.args.get("format") == "csv":
        return _csv(["name", "host", "group", "uptime", "incidents", "mttr", "downtime", "avg_latency", "p95", "avg_loss"], rows, f"sla_{days}d.csv")
    return jsonify({"days": days, "rows": rows})


@bp.get("/reports/checks.csv")
def export_checks():
    did = request.args.get("device_id", type=int)
    hrs = min(request.args.get("hours", 24, type=int), 24 * 7)
    q = Check.query.filter(Check.timestamp >= utcnow() - timedelta(hours=hrs))
    if did:
        q = q.filter_by(device_id=did)
    rows = [r.to_dict() for r in q.order_by(Check.timestamp).limit(200000)]
    return _csv(["timestamp", "device_id", "status", "latency", "packet_loss", "jitter", "detail"], rows, "checks.csv")


def _csv(cols, rows, filename):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        # neutralise spreadsheet formula injection
        w.writerow([("'" + str(r.get(c))) if isinstance(r.get(c), str) and r.get(c)[:1] in "=+-@" else r.get(c) for c in cols])
    return Response(buf.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={filename}"})


# ─────────────── channels ───────────────

CHANNEL_FIELDS = {"webhook": ["url"], "slack": ["url"], "discord": ["url"], "telegram": ["bot_token", "chat_id"], "email": ["to"]}


@bp.route("/channels", methods=["GET", "POST"])
def channels():
    if request.method == "GET":
        return jsonify([c.to_dict() for c in Channel.query.all()])
    d = request.get_json(silent=True) or {}
    if d.get("type") not in CHANNEL_FIELDS or not str(d.get("name", "")).strip():
        return err("name and a valid type are required")
    cfg = d.get("config") or {}
    if any(not cfg.get(k) for k in CHANNEL_FIELDS[d["type"]]):
        return err("missing: " + ", ".join(CHANNEL_FIELDS[d["type"]]))
    if "url" in cfg and not valid_url(cfg["url"]):
        return err("url must be http(s)")
    ch = Channel(name=d["name"].strip()[:80], type=d["type"], config=json.dumps({k: cfg[k] for k in CHANNEL_FIELDS[d["type"]]}),
                 min_severity=d.get("min_severity", "warning") if d.get("min_severity") in ("warning", "critical") else "warning",
                 notify_resolved=bool(d.get("notify_resolved", True)), enabled=bool(d.get("enabled", True)))
    db.session.add(ch)
    db.session.commit()
    return jsonify(ch.to_dict()), 201


@bp.route("/channels/<int:cid>", methods=["PUT", "DELETE"])
def channel_one(cid):
    ch = db.get_or_404(Channel, cid)
    if request.method == "DELETE":
        db.session.delete(ch)
        db.session.commit()
        return jsonify({"message": "deleted"})
    d = request.get_json(silent=True) or {}
    for k in ("enabled", "notify_resolved"):
        if k in d:
            setattr(ch, k, bool(d[k]))
    if d.get("min_severity") in ("warning", "critical"):
        ch.min_severity = d["min_severity"]
    db.session.commit()
    return jsonify(ch.to_dict())


@bp.post("/channels/<int:cid>/test")
def channel_test(cid):
    ch = db.get_or_404(Channel, cid)
    c = current_app.config
    try:
        alerts.send(ch.type, ch.cfg(), "✅ NTFDS test notification — your alert channel works.", None,
                    {"host": c["SMTP_HOST"], "port": c["SMTP_PORT"], "user": c["SMTP_USER"], "password": c["SMTP_PASSWORD"], "from": c["SMTP_FROM"]})
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": f"{e.__class__.__name__}: {e}"}), 502


# ─────────────── active tools ───────────────

def _target():
    d = request.get_json(silent=True) or {}
    t = str(d.get("target", "")).strip()
    return d, (t if valid_host(t) else None)


@bp.post("/tools/<tool>")
def tools(tool):
    d, t = _target()
    if tool == "http":
        url = str(d.get("target", "")).strip()
        if not valid_url(url):
            return err("target must be an http(s) URL")
        try:
            return jsonify(diagnostics.http_probe(url))
        except diagnostics.Busy as e:
            return err(str(e), 429)
    if not t:
        return err("invalid target")
    try:
        if tool == "ping":
            from .checks import icmp_check
            r = icmp_check(t, count=min(int(d.get("count", 5)), 20), timeout=1.5)
            return jsonify({"ok": r.ok, "latency": r.latency, "loss": r.loss, "jitter": r.jitter, "detail": r.detail, **r.extra})
        if tool == "traceroute":
            return jsonify(diagnostics.traceroute(t))
        if tool == "dns":
            srv = d.get("server")
            if srv and not valid_host(srv):
                return err("invalid DNS server")
            return jsonify(diagnostics.dns_lookup(t, srv))
        if tool == "ports":
            if not current_app.config["ALLOW_PUBLIC_SCAN"] and not is_private_target(t):
                return err("port scanning is limited to private/loopback IP literals (NTFDS_ALLOW_PUBLIC_SCAN=1 to lift)", 403)
            ports = diagnostics.parse_ports(d["ports"]) if d.get("ports") else None
            return jsonify(diagnostics.port_scan(t, ports))
        if tool == "diagnose":
            return jsonify(diagnostics.diagnose(t, d.get("check_type", "icmp"), d.get("port"), None,
                                                current_app.config["DIAG_REFERENCE_HOSTS"]))
    except diagnostics.Busy as e:
        return err(str(e), 429)
    except (ValueError, TypeError) as e:
        return err(str(e))
    return err("unknown tool", 404)


@bp.post("/discovery")
def discovery_start():
    d = request.get_json(silent=True) or {}
    cidr = d.get("cidr")
    if not cidr:
        ip = diagnostics.local_ip()
        if not ip:
            return err("cannot detect local network; pass cidr")
        cidr = ip.rsplit(".", 1)[0] + ".0/24"
    try:
        job = diagnostics.start_discovery(cidr, current_app.config["DISCOVERY_MAX_HOSTS"], current_app.config["ALLOW_PUBLIC_SCAN"])
    except ValueError as e:
        return err(str(e))
    return jsonify(job), 202


@bp.get("/discovery/<jid>")
def discovery_status(jid):
    job = diagnostics.get_job(jid)
    if not job:
        return err("unknown job", 404)
    known = {d.host for d in Device.query.with_entities(Device.host)}
    return jsonify({**job, "found": [{**x, "known": x["ip"] in known} for x in job["found"]]})


# ─────────────── Prometheus ───────────────

metrics_bp = Blueprint("metrics", __name__)


@metrics_bp.before_request
def _m_auth():
    return auth_required_response()


@metrics_bp.get("/metrics")
def prometheus():
    def esc(s):
        return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    lines = ["# TYPE ntfds_device_up gauge", "# TYPE ntfds_device_latency_ms gauge",
             "# TYPE ntfds_device_packet_loss_percent gauge", "# TYPE ntfds_device_jitter_ms gauge",
             "# TYPE ntfds_open_incidents gauge"]
    for d in Device.query.all():
        lb = f'device="{esc(d.name)}",host="{esc(d.host)}",group="{esc(d.group or "")}"'
        lines.append(f"ntfds_device_up{{{lb}}} {1 if d.last_status in ('Online', 'Warning') else 0}")
        for name, v in (("latency_ms", d.last_response_time), ("packet_loss_percent", d.last_loss), ("jitter_ms", d.last_jitter)):
            if v is not None:
                lines.append(f"ntfds_device_{name}{{{lb}}} {v}")
    lines.append(f"ntfds_open_incidents {Incident.query.filter_by(ended_at=None, suppressed=False).count()}")
    return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4")
