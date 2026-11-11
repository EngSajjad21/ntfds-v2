"""Runtime configuration — every value can be overridden with an environment variable."""
import os
import secrets


def _bool(name, default=False):
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


def _int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///network_monitor.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"timeout": 30}} \
        if os.getenv("DATABASE_URL", "sqlite").startswith("sqlite") else {}

    # Map tiles. The public OSM servers require a Referer and forbid heavy use; for production point this
    # at your own tile server or a provider with an API key. Empty = no tiles (grid background only).
    TILE_URL = os.getenv("NTFDS_TILE_URL", "https://tile.openstreetmap.org/{z}/{x}/{y}.png")

    HOST = os.getenv("NTFDS_HOST", "127.0.0.1")
    PORT = _int("NTFDS_PORT", 5000)
    DEBUG = _bool("NTFDS_DEBUG", False)

    # Auth: when set, every /api call, /metrics and the websocket need this token.
    API_TOKEN = os.getenv("NTFDS_API_TOKEN", "")

    # Engine
    MONITOR_ENABLED = _bool("NTFDS_MONITOR", True)
    MAX_WORKERS = _int("NTFDS_MAX_WORKERS", 32)
    RAW_RETENTION_DAYS = _int("NTFDS_RAW_RETENTION_DAYS", 7)       # per-check rows
    ROLLUP_RETENTION_DAYS = _int("NTFDS_ROLLUP_RETENTION_DAYS", 400)  # hourly rows

    # Safety rails for active tools
    ALLOW_PUBLIC_SCAN = _bool("NTFDS_ALLOW_PUBLIC_SCAN", False)    # port scan / discovery on public IPs
    DISCOVERY_MAX_HOSTS = _int("NTFDS_DISCOVERY_MAX_HOSTS", 1024)
    TOOL_CONCURRENCY = _int("NTFDS_TOOL_CONCURRENCY", 4)
    DIAG_REFERENCE_HOSTS = [h for h in os.getenv("NTFDS_REFERENCE_HOSTS", "1.1.1.1,8.8.8.8").split(",") if h]

    # Optional SMTP for e-mail alert channels
    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = _int("SMTP_PORT", 587)
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM = os.getenv("SMTP_FROM", "ntfds@localhost")


# Global defaults, editable at runtime from the Settings page (stored in the DB).
DEFAULT_SETTINGS = {
    "interval": 10,          # seconds between checks
    "warn_latency": 150.0,   # ms
    "warn_loss": 20.0,       # % packet loss
    "warn_jitter": 50.0,     # ms
    "fail_threshold": 2,     # consecutive failures before Offline
    "ssl_warn_days": 14,
    "anomaly_detection": True,
}
