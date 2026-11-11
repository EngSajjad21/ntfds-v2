"""Read-side queries: time series, uptime/SLA, percentiles."""
import statistics
from datetime import timedelta

from sqlalchemy import case, func

from .extensions import db
from .models import Check, Device, Incident, Rollup, iso, utcnow

RANGES = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400}
DOWN = ("Offline", "Unreachable")


def _percentile(sorted_vals, p):
    if not sorted_vals:
        return None
    k = (len(sorted_vals) - 1) * p
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    return round(sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f), 2)


def uptime(device_id, seconds, raw_days=7):
    """Uptime % over a window, using raw rows when they cover it, hourly rollups otherwise."""
    since = utcnow() - timedelta(seconds=seconds)
    if seconds <= raw_days * 86400:
        total, down = db.session.query(
            func.count(Check.id), func.coalesce(func.sum(case((Check.status.in_(DOWN), 1), else_=0)), 0)
        ).filter(Check.device_id == device_id, Check.timestamp >= since).one()
    else:
        total, down = db.session.query(
            func.coalesce(func.sum(Rollup.samples), 0), func.coalesce(func.sum(Rollup.down_samples), 0)
        ).filter(Rollup.device_id == device_id, Rollup.bucket >= since).one()
        # add the not-yet-rolled-up tail from raw rows
        last = db.session.query(func.max(Rollup.bucket)).filter(Rollup.device_id == device_id).scalar()
        q = db.session.query(func.count(Check.id), func.coalesce(func.sum(case((Check.status.in_(DOWN), 1), else_=0)), 0)) \
            .filter(Check.device_id == device_id)
        if last:
            q = q.filter(Check.timestamp >= last + timedelta(hours=1))
        t2, d2 = q.one()
        total, down = total + t2, down + d2
    if not total:
        return None
    return round(100.0 * (total - down) / total, 3)


def series(device_id, rng="1h", max_points=240):
    seconds = RANGES.get(rng, 3600)
    since = utcnow() - timedelta(seconds=seconds)
    pts = []
    if seconds <= 7 * 86400:
        rows = db.session.query(Check.timestamp, Check.status, Check.latency, Check.packet_loss, Check.jitter) \
            .filter(Check.device_id == device_id, Check.timestamp >= since).order_by(Check.timestamp).all()
        bucket = max(seconds / max_points, 1)
        groups = {}
        for ts, st, lat, loss, jit in rows:
            k = int((ts - since).total_seconds() // bucket)
            g = groups.setdefault(k, {"ts": ts, "lat": [], "loss": [], "jit": [], "down": 0, "n": 0})
            g["n"] += 1
            g["down"] += st in DOWN
            if lat is not None: g["lat"].append(lat)
            if loss is not None: g["loss"].append(loss)
            if jit is not None: g["jit"].append(jit)
        for k in sorted(groups):
            g = groups[k]
            pts.append({"t": iso(g["ts"]), "latency": round(statistics.fmean(g["lat"]), 2) if g["lat"] else None,
                        "max": max(g["lat"]) if g["lat"] else None,
                        "loss": round(statistics.fmean(g["loss"]), 1) if g["loss"] else 0,
                        "jitter": round(statistics.fmean(g["jit"]), 2) if g["jit"] else None,
                        "down": g["down"] > 0})
    else:
        for ru in Rollup.query.filter(Rollup.device_id == device_id, Rollup.bucket >= since).order_by(Rollup.bucket):
            pts.append({"t": iso(ru.bucket), "latency": ru.avg_latency, "max": ru.max_latency,
                        "loss": ru.avg_loss or 0, "jitter": ru.avg_jitter, "down": ru.down_samples > 0})
    return pts


def device_stats(device_id, rng="24h"):
    seconds = RANGES.get(rng, 86400)
    since = utcnow() - timedelta(seconds=seconds)
    out = {"range": rng, "uptime": uptime(device_id, seconds)}
    if seconds <= 7 * 86400:
        lats = sorted(v for (v,) in db.session.query(Check.latency).filter(
            Check.device_id == device_id, Check.timestamp >= since, Check.latency.isnot(None)))
        out.update(samples=len(lats), min=lats[0] if lats else None, max=lats[-1] if lats else None,
                   avg=round(statistics.fmean(lats), 2) if lats else None,
                   p50=_percentile(lats, .5), p95=_percentile(lats, .95), p99=_percentile(lats, .99))
        avg_loss, avg_jit = db.session.query(func.avg(Check.packet_loss), func.avg(Check.jitter)).filter(
            Check.device_id == device_id, Check.timestamp >= since).one()
    else:
        mn, avg, mx, avg_loss, avg_jit = db.session.query(
            func.min(Rollup.avg_latency), func.avg(Rollup.avg_latency), func.max(Rollup.max_latency),
            func.avg(Rollup.avg_loss), func.avg(Rollup.avg_jitter)).filter(
            Rollup.device_id == device_id, Rollup.bucket >= since).one()
        if avg is None:   # rollups not built yet (fresh install / first hour) → fall back to raw rows
            mn, avg, mx = db.session.query(func.min(Check.latency), func.avg(Check.latency), func.max(Check.latency)).filter(
                Check.device_id == device_id, Check.timestamp >= since).one()
            avg_loss, avg_jit = db.session.query(func.avg(Check.packet_loss), func.avg(Check.jitter)).filter(
                Check.device_id == device_id, Check.timestamp >= since).one()
        out.update(min=mn, avg=round(avg, 2) if avg else None, max=mx, p50=None, p95=None, p99=None)
    out["avg_loss"] = round(avg_loss, 2) if avg_loss is not None else None
    out["avg_jitter"] = round(avg_jit, 2) if avg_jit is not None else None
    return out


def incident_stats(device_id, seconds):
    since = utcnow() - timedelta(seconds=seconds)
    rows = Incident.query.filter(Incident.device_id == device_id, Incident.started_at >= since,
                                 Incident.kind == "down", Incident.suppressed.is_(False)).all()
    done = [(i.ended_at - i.started_at).total_seconds() for i in rows if i.ended_at]
    return {"count": len(rows), "mttr": round(statistics.fmean(done)) if done else None,
            "downtime": int(sum(done) + sum((utcnow() - i.started_at).total_seconds() for i in rows if not i.ended_at))}


def sla_report(days=30):
    seconds = days * 86400
    rows = []
    for d in Device.query.order_by(Device.name).all():
        up = uptime(d.id, seconds)
        inc = incident_stats(d.id, seconds)
        st = device_stats(d.id, "30d" if days > 7 else ("7d" if days > 1 else "24h"))
        rows.append({"id": d.id, "name": d.name, "host": d.host, "group": d.group, "uptime": up,
                     "incidents": inc["count"], "mttr": inc["mttr"], "downtime": inc["downtime"],
                     "avg_latency": st.get("avg"), "p95": st.get("p95"), "avg_loss": st.get("avg_loss")})
    return rows
