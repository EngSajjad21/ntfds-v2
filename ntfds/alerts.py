"""Notification dispatch. Runs in a small thread pool so slow webhooks never block the engine."""
import json
import logging
import smtplib
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage

from .models import Channel

log = logging.getLogger("ntfds.alerts")
_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="alert")
SEV_RANK = {"warning": 1, "critical": 2}


def format_message(event):
    inc, dev = event["incident"], event["device"]
    if event["type"] == "opened":
        icon = "🔴" if inc["severity"] == "critical" else "🟠"
        head = f"{icon} {dev['name']} ({dev['host']}) — {inc['kind'].replace('_', ' ').upper()}"
    else:
        head = f"🟢 {dev['name']} ({dev['host']}) — RESOLVED after {_dur(inc['duration'])}"
    return f"{head}\n{inc['message']}"


def _dur(s):
    h, r = divmod(int(s), 3600)
    m, s = divmod(r, 60)
    return (f"{h}h " if h else "") + (f"{m}m " if m or h else "") + f"{s}s"


def _post_json(url, payload, headers=None, timeout=8):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "NTFDS/2.0", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status


def send(channel_type, cfg, text, event=None, smtp=None):
    """Raises on failure so the Test button can show the reason."""
    if channel_type == "webhook":
        _post_json(cfg["url"], {"text": text, "event": event})
    elif channel_type == "slack":
        _post_json(cfg["url"], {"text": text})
    elif channel_type == "discord":
        _post_json(cfg["url"], {"content": text[:1900]})
    elif channel_type == "telegram":
        _post_json(f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage",
                   {"chat_id": cfg["chat_id"], "text": text})
    elif channel_type == "email":
        smtp = smtp or {}
        if not smtp.get("host"):
            raise RuntimeError("SMTP_HOST is not configured on the server")
        msg = EmailMessage()
        msg["Subject"] = text.splitlines()[0][:150]
        msg["From"], msg["To"] = smtp["from"], cfg["to"]
        msg.set_content(text)
        with smtplib.SMTP(smtp["host"], smtp["port"], timeout=10) as s:
            s.starttls()
            if smtp.get("user"):
                s.login(smtp["user"], smtp["password"])
            s.send_message(msg)
    else:
        raise ValueError(f"unknown channel type {channel_type}")


def dispatch(app, event):
    """event: {'type': 'opened'|'resolved', 'incident': dict, 'device': dict}. Call inside app context."""
    text = format_message(event)
    smtp = {"host": app.config["SMTP_HOST"], "port": app.config["SMTP_PORT"], "user": app.config["SMTP_USER"],
            "password": app.config["SMTP_PASSWORD"], "from": app.config["SMTP_FROM"]}
    for ch in Channel.query.filter_by(enabled=True).all():
        if SEV_RANK.get(event["incident"]["severity"], 1) < SEV_RANK.get(ch.min_severity, 1):
            continue
        if event["type"] == "resolved" and not ch.notify_resolved:
            continue
        _pool.submit(_safe_send, ch.type, ch.cfg(), text, event, smtp)


def _safe_send(ctype, cfg, text, event, smtp):
    try:
        send(ctype, cfg, text, event, smtp)
    except Exception as e:
        log.warning("alert delivery via %s failed: %s", ctype, e)
