"""Monitoring engine.

Worker threads only run network probes (no DB). A single coordinator thread owns all DB writes,
which avoids SQLite write contention and keeps state transitions (status → incident → alert) ordered.
"""
import logging
import queue
import statistics
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from . import alerts
from .checks import CheckResult, run_check
from .extensions import db, socketio
from .models import Check, Device, Incident, Rollup, Setting, iso, utcnow
from .settings import get_settings

log = logging.getLogger("ntfds.engine")

REASON_PRIORITY = ["http_error", "high_latency", "packet_loss", "jitter", "anomaly", "ssl_expiry"]
FLAP_WINDOW, FLAP_CHANGES = 600, 6


# ───────────────────────── pure decision logic (unit-tested) ─────────────────────────

def evaluate(prev_status, failures, r, th, parent_down=False):
    """Decide the new status from one probe result.
    Returns (status, reasons, failures). `th` = thresholds dict."""
    if not r.ok:
        failures += 1
        if failures < th["fail_threshold"]:
            # Not confirmed yet — keep the previous state to avoid false alarms on one dropped probe.
            return (prev_status if prev_status != "Unknown" else "Unknown"), [], failures
        return ("Unreachable" if parent_down else "Offline"), [], failures

    reasons = []
    ex = r.extra or {}
    if ex.get("http_status", 0) >= 400:
        reasons.append("http_error")
    if r.latency is not None and r.latency > th["warn_latency"]:
        reasons.append("high_latency")
    if r.loss is not None and r.loss >= th["warn_loss"]:
        reasons.append("packet_loss")
    if r.jitter is not None and r.jitter > th["warn_jitter"]:
        reasons.append("jitter")
    if ex.get("anomaly"):
        reasons.append("anomaly")
    d = ex.get("ssl_days")
    if d is not None and d < th["ssl_warn_days"]:
        reasons.append("ssl_expiry")
    reasons.sort(key=REASON_PRIORITY.index)
    return ("Warning" if reasons else "Online"), reasons, 0


def reason_message(kind, r, th, dev_name=""):
    ex = r.extra or {}
    return {
        "down": f"No response — {r.detail}",
        "http_error": f"HTTP {ex.get('http_status')} returned",
        "high_latency": f"Latency {r.latency} ms exceeds {th['warn_latency']:g} ms",
        "packet_loss": f"Packet loss {r.loss}% (threshold {th['warn_loss']:g}%)",
        "jitter": f"Jitter {r.jitter} ms exceeds {th['warn_jitter']:g} ms",
        "anomaly": f"Latency {r.latency} ms is far above this device's normal baseline",
        "ssl_expiry": f"TLS certificate expires in {ex.get('ssl_days')} days",
    }.get(kind, kind)


class Baseline:
    """Rolling latency baseline: flags sustained deviations (>2× mean and z>3) without poisoning itself."""
    def __init__(self, size=120, min_samples=30, need=3):
        self.buf, self.min, self.need, self.hits = deque(maxlen=size), min_samples, need, 0

    def observe(self, latency):
        if latency is None:
            return False
        anomalous = False
        if len(self.buf) >= self.min:
            mean = statistics.fmean(self.buf)
            sd = statistics.pstdev(self.buf)
            z = (latency - mean) / max(sd, 0.1 * mean, 1.0)
            anomalous = latency > 2 * mean and z > 3
        self.hits = self.hits + 1 if anomalous else 0
        if not anomalous:
            self.buf.append(latency)
        return self.hits >= self.need


# ───────────────────────────────── engine ─────────────────────────────────

class Engine:
    def __init__(self, app):
        self.app = app
        self.pool = ThreadPoolExecutor(max_workers=app.config["MAX_WORKERS"], thread_name_prefix="probe")
        self.results = queue.Queue()
        self.lock = threading.RLock()
        self.stop_evt = threading.Event()
        self.dirty = threading.Event()
        self.thread = None
        self.inflight, self.due, self.cfg = set(), {}, {}
        self.baselines = defaultdict(Baseline)
        self.changes = defaultdict(lambda: deque(maxlen=20))
        self.last_maint = 0

    # lifecycle
    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_evt.clear()
        self.thread = threading.Thread(target=self._loop, name="engine", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_evt.set()
        self.pool.shutdown(wait=False, cancel_futures=True)

    def reload(self):
        self.dirty.set()

    # scheduler
    def _reload_devices(self):
        gs = get_settings()
        rows = Device.query.filter_by(enabled=True).all()
        self.cfg = {d.id: (d.snapshot(), d.interval or gs["interval"]) for d in rows}
        for gone in set(self.due) - set(self.cfg):
            self.due.pop(gone, None)

    def _worker(self, snap):
        res = run_check(snap)
        self.results.put((snap["id"], res))

    def _loop(self):
        last_reload = 0
        while not self.stop_evt.is_set():
            try:
                with self.app.app_context():
                    now = time.time()
                    if self.dirty.is_set() or now - last_reload > 15:
                        self.dirty.clear()
                        self._reload_devices()
                        last_reload = now
                    for did, (snap, interval) in list(self.cfg.items()):
                        if did in self.inflight or self.due.get(did, 0) > now:
                            continue
                        self.inflight.add(did)
                        self.due[did] = now + interval + (did % 7) * 0.13  # light jitter spreads load
                        self.pool.submit(self._worker, snap)
                    deadline = time.time() + 1.0
                    while time.time() < deadline:
                        try:
                            did, res = self.results.get(timeout=0.25)
                        except queue.Empty:
                            continue
                        self.inflight.discard(did)
                        self.process(did, res)
                    if now - self.last_maint > 3600:
                        self.last_maint = now
                        self.maintenance()
            except Exception:
                log.exception("engine loop error")
                db.session.rollback()
                time.sleep(1)

    def check_now(self, device_id):
        """Synchronous probe for the 'Check now' button / API."""
        dev = db.session.get(Device, device_id)
        if not dev:
            return None
        res = run_check(dev.snapshot())
        self.process(device_id, res)
        return db.session.get(Device, device_id)

    # state machine
    def process(self, device_id, r: CheckResult):
        with self.lock:
            dev = db.session.get(Device, device_id)
            if dev is None:
                return
            gs = get_settings()
            th = {"fail_threshold": gs["fail_threshold"], "warn_jitter": gs["warn_jitter"],
                  "ssl_warn_days": gs["ssl_warn_days"],
                  "warn_latency": dev.warn_latency or gs["warn_latency"],
                  "warn_loss": dev.warn_loss or gs["warn_loss"]}
            if gs["anomaly_detection"] and r.ok:
                r.extra = dict(r.extra or {})
                r.extra["anomaly"] = self.baselines[device_id].observe(r.latency)

            parent = db.session.get(Device, dev.parent_id) if dev.parent_id else None
            parent_down = bool(parent and not parent.maintenance and parent.last_status in ("Offline", "Unreachable"))
            prev = dev.last_status
            status, reasons, failures = evaluate(prev, dev.consecutive_failures or 0, r, th, parent_down)
            now = utcnow()

            if status != prev:
                dev.last_change = now
                self.changes[device_id].append(time.time())
            flapping = sum(1 for t in self.changes[device_id] if time.time() - t < FLAP_WINDOW) >= FLAP_CHANGES

            dev.last_status, dev.consecutive_failures = status, failures
            dev.last_response_time, dev.last_loss, dev.last_jitter = r.latency, r.loss, r.jitter
            dev.last_detail = ("⚠ flapping — alerts muted. " if flapping else "") + (r.detail or "")[:230]
            dev.last_ssl_days = (r.extra or {}).get("ssl_days")
            dev.last_checked = now
            check = Check(device_id=device_id, status=status, latency=r.latency, packet_loss=r.loss,
                          jitter=r.jitter, detail=(r.detail or "")[:255], timestamp=now)
            db.session.add(check)

            events = self._incidents(dev, status, reasons, r, th, parent, flapping)
            db.session.commit()

            d = dev.to_dict()
            socketio.emit("device_update", {"device": d, "check": check.to_dict()})
            for ev in events:
                socketio.emit("incident_" + ev["type"], ev)
                if not ev["incident"].get("suppressed"):
                    alerts.dispatch(self.app, ev)

    def _descendants(self, dev_id):
        kids = defaultdict(list)
        for i, p in db.session.query(Device.id, Device.parent_id).filter(Device.parent_id.isnot(None)):
            kids[p].append(i)
        out, stack = [], list(kids.get(dev_id, []))
        while stack:
            n = stack.pop()
            out.append(n)
            stack.extend(kids.get(n, []))
        return out

    def _incidents(self, dev, status, reasons, r, th, parent, flapping):
        events = []
        open_inc = Incident.query.filter_by(device_id=dev.id, ended_at=None).first()
        suppress = bool(dev.maintenance or flapping)

        if status == "Online":
            wanted = None
        elif status == "Offline":
            wanted = "down"
        elif status == "Warning" and reasons:
            wanted = reasons[0]
        else:   # Unknown / Unreachable / unconfirmed failure → leave incidents untouched
            if status == "Unreachable" and open_inc and open_inc.kind == "down" and parent:
                open_inc.root_cause_id = parent.id
            return events

        if open_inc and open_inc.kind == wanted:
            return events
        if open_inc:
            open_inc.ended_at = utcnow()
            if wanted is None or open_inc.kind == "down":
                events.append({"type": "resolved", "incident": open_inc.to_dict(), "device": dev.to_dict()})
        if wanted:
            msg = reason_message(wanted, r, th)
            if wanted == "down":
                n = len([i for i in self._descendants(dev.id)])
                if n:
                    msg += f" · {n} downstream device(s) affected"
            inc = Incident(device_id=dev.id, kind=wanted, severity="critical" if wanted == "down" else "warning",
                           message=msg[:300], suppressed=suppress)
            db.session.add(inc)
            db.session.flush()
            events.append({"type": "opened", "incident": {**inc.to_dict(), "suppressed": suppress}, "device": dev.to_dict()})
        for ev in events:
            ev["incident"]["suppressed"] = suppress
        return events

    # housekeeping
    def maintenance(self):
        """Hourly: roll complete hours into `rollups`, then prune old raw rows."""
        cfg = self.app.config
        hour = utcnow().replace(minute=0, second=0, microsecond=0)
        row = db.session.get(Setting, "last_rollup")
        if row:
            start = datetime.fromisoformat(row.value)
        else:
            first = db.session.query(db.func.min(Check.timestamp)).scalar()
            start = (first or hour).replace(minute=0, second=0, microsecond=0)
        if start < hour:
            agg = defaultdict(lambda: {"n": 0, "down": 0, "lat": [], "loss": [], "jit": []})
            q = (db.session.query(Check.device_id, Check.timestamp, Check.status, Check.latency, Check.packet_loss, Check.jitter)
                 .filter(Check.timestamp >= start, Check.timestamp < hour).yield_per(5000))
            for did, ts, st, lat, loss, jit in q:
                a = agg[(did, ts.replace(minute=0, second=0, microsecond=0))]
                a["n"] += 1
                a["down"] += st in ("Offline", "Unreachable")
                if lat is not None: a["lat"].append(lat)
                if loss is not None: a["loss"].append(loss)
                if jit is not None: a["jit"].append(jit)
            for (did, b), a in agg.items():
                ru = Rollup.query.filter_by(device_id=did, bucket=b).first() or Rollup(device_id=did, bucket=b)
                ru.samples, ru.down_samples = a["n"], a["down"]
                ru.avg_latency = round(statistics.fmean(a["lat"]), 2) if a["lat"] else None
                ru.max_latency = max(a["lat"]) if a["lat"] else None
                ru.avg_loss = round(statistics.fmean(a["loss"]), 2) if a["loss"] else None
                ru.avg_jitter = round(statistics.fmean(a["jit"]), 2) if a["jit"] else None
                db.session.add(ru)
            db.session.merge(Setting(key="last_rollup", value=hour.isoformat()))
            db.session.commit()
        cutoff = min(utcnow() - timedelta(days=cfg["RAW_RETENTION_DAYS"]), hour)
        Check.query.filter(Check.timestamp < cutoff).delete(synchronize_session=False)
        Rollup.query.filter(Rollup.bucket < utcnow() - timedelta(days=cfg["ROLLUP_RETENTION_DAYS"])).delete(synchronize_session=False)
        db.session.commit()
