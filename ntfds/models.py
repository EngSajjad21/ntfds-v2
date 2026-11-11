import json
from datetime import datetime

from sqlalchemy import event, inspect, text
from sqlalchemy.engine import Engine

from .extensions import db


def utcnow():
    return datetime.utcnow()


def iso(dt):
    return dt.isoformat() + "Z" if dt else None


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_conn, _):
    # WAL gives concurrent readers while the engine thread writes.
    if dbapi_conn.__class__.__module__.startswith("sqlite3"):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


DEVICE_KINDS = ["router", "switch", "firewall", "server", "ap", "pc", "printer", "camera", "iot", "other"]
CHECK_TYPES = ["icmp", "tcp", "http", "dns"]
# Statuses: Online, Warning, Offline, Unreachable (parent is down), Maintenance, Unknown


class Device(db.Model):
    __tablename__ = "devices"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    host = db.Column("ip", db.String(255), nullable=False, unique=True)  # column keeps legacy name "ip"
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    kind = db.Column(db.String(20), default="other")
    group = db.Column(db.String(60))
    notes = db.Column(db.Text)
    check_type = db.Column(db.String(10), default="icmp")
    port = db.Column(db.Integer)
    check_arg = db.Column(db.String(255))      # URL for http, query name for dns
    interval = db.Column(db.Integer)           # seconds, NULL = global default
    warn_latency = db.Column(db.Float)         # NULL = global default
    warn_loss = db.Column(db.Float)
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    maintenance = db.Column(db.Boolean, default=False, nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="SET NULL"))
    created_at = db.Column(db.DateTime, default=utcnow)

    last_status = db.Column(db.String(20), default="Unknown")
    last_response_time = db.Column(db.Float)
    last_loss = db.Column(db.Float)
    last_jitter = db.Column(db.Float)
    last_detail = db.Column(db.String(255))
    last_ssl_days = db.Column(db.Float)
    last_checked = db.Column(db.DateTime)
    last_change = db.Column(db.DateTime, default=utcnow)
    consecutive_failures = db.Column(db.Integer, default=0)

    logs = db.relationship("Check", backref="device", lazy=True, cascade="all, delete-orphan")
    incidents = db.relationship("Incident", backref="device", lazy=True, cascade="all, delete-orphan",
                                foreign_keys="Incident.device_id")

    def to_dict(self):
        return {
            "id": self.id, "name": self.name, "host": self.host, "ip": self.host,
            "latitude": self.latitude, "longitude": self.longitude,
            "kind": self.kind, "group": self.group, "notes": self.notes,
            "check_type": self.check_type, "port": self.port, "check_arg": self.check_arg,
            "interval": self.interval, "warn_latency": self.warn_latency, "warn_loss": self.warn_loss,
            "enabled": self.enabled, "maintenance": self.maintenance, "parent_id": self.parent_id,
            "last_status": "Maintenance" if self.maintenance else self.last_status,
            "last_response_time": self.last_response_time, "last_loss": self.last_loss,
            "last_jitter": self.last_jitter, "last_detail": self.last_detail,
            "last_ssl_days": self.last_ssl_days,
            "last_checked": iso(self.last_checked), "last_change": iso(self.last_change),
        }

    def snapshot(self):
        """Plain-dict copy that is safe to hand to worker threads."""
        return {"id": self.id, "host": self.host, "check_type": self.check_type or "icmp",
                "port": self.port, "check_arg": self.check_arg}


class Check(db.Model):
    """One probe result (legacy table name: logs)."""
    __tablename__ = "logs"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    latency = db.Column(db.Float)
    packet_loss = db.Column(db.Float)
    jitter = db.Column(db.Float)
    detail = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=utcnow)
    __table_args__ = (db.Index("ix_logs_device_ts", "device_id", "timestamp"),)

    def to_dict(self):
        return {"id": self.id, "device_id": self.device_id, "status": self.status,
                "latency": self.latency, "packet_loss": self.packet_loss, "jitter": self.jitter,
                "detail": self.detail, "timestamp": iso(self.timestamp)}


class Rollup(db.Model):
    """Hourly aggregate kept long-term after raw checks are pruned."""
    __tablename__ = "rollups"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    bucket = db.Column(db.DateTime, nullable=False)
    samples = db.Column(db.Integer, default=0)
    down_samples = db.Column(db.Integer, default=0)
    avg_latency = db.Column(db.Float)
    max_latency = db.Column(db.Float)
    avg_loss = db.Column(db.Float)
    avg_jitter = db.Column(db.Float)
    __table_args__ = (db.UniqueConstraint("device_id", "bucket", name="uq_rollup"),)


class Incident(db.Model):
    __tablename__ = "incidents"
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = db.Column(db.String(20), nullable=False)       # down, high_latency, packet_loss, jitter, ssl_expiry, http_error, anomaly
    severity = db.Column(db.String(10), nullable=False)   # critical, warning
    message = db.Column(db.String(300))
    started_at = db.Column(db.DateTime, default=utcnow, index=True)
    ended_at = db.Column(db.DateTime)
    acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_at = db.Column(db.DateTime)
    root_cause_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="SET NULL"))
    suppressed = db.Column(db.Boolean, default=False)     # opened during maintenance/flapping

    def to_dict(self):
        end = self.ended_at or utcnow()
        return {"id": self.id, "device_id": self.device_id,
                "device_name": self.device.name if self.device else None,
                "kind": self.kind, "severity": self.severity, "message": self.message,
                "started_at": iso(self.started_at), "ended_at": iso(self.ended_at),
                "duration": int((end - self.started_at).total_seconds()) if self.started_at else 0,
                "acknowledged": bool(self.acknowledged), "root_cause_id": self.root_cause_id,
                "open": self.ended_at is None}


class Channel(db.Model):
    """Notification channel: webhook | slack | discord | telegram | email."""
    __tablename__ = "channels"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    config = db.Column(db.Text, default="{}")
    enabled = db.Column(db.Boolean, default=True)
    min_severity = db.Column(db.String(10), default="warning")  # warning | critical
    notify_resolved = db.Column(db.Boolean, default=True)

    def cfg(self):
        try:
            return json.loads(self.config or "{}")
        except ValueError:
            return {}

    def to_dict(self, reveal=False):
        cfg = self.cfg()
        if not reveal:  # never send secrets back to the browser
            cfg = {k: ("••••" if k in ("token", "password", "bot_token") and v else v) for k, v in cfg.items()}
        return {"id": self.id, "name": self.name, "type": self.type, "config": cfg,
                "enabled": self.enabled, "min_severity": self.min_severity,
                "notify_resolved": self.notify_resolved}


class Setting(db.Model):
    __tablename__ = "settings"
    key = db.Column(db.String(60), primary_key=True)
    value = db.Column(db.Text)


def ensure_schema():
    """Create tables, then add any columns/indexes missing from a database made by an older release."""
    db.create_all()
    insp = inspect(db.engine)
    with db.engine.begin() as conn:
        for table in db.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            existing = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in existing:
                    continue
                ctype = col.type.compile(db.engine.dialect)
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {ctype}'))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_logs_device_ts ON logs (device_id, timestamp)"))
        # legacy rows: give pre-upgrade devices sane defaults
        conn.execute(text("UPDATE devices SET enabled=1 WHERE enabled IS NULL"))
        conn.execute(text("UPDATE devices SET maintenance=0 WHERE maintenance IS NULL"))
        conn.execute(text("UPDATE devices SET check_type='icmp' WHERE check_type IS NULL"))
        conn.execute(text("UPDATE devices SET consecutive_failures=0 WHERE consecutive_failures IS NULL"))
        conn.execute(text("UPDATE devices SET kind='other' WHERE kind IS NULL"))
