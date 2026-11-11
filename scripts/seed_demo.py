"""Fill a database with a realistic demo network + 48h of history (for screenshots / trying the UI).
Usage:  python scripts/seed_demo.py [path/to/demo.db]    then   DATABASE_URL=sqlite:////abs/path/demo.db NTFDS_MONITOR=0 python app.py"""
import math
import os
import random
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ntfds import create_app  # noqa: E402
from ntfds.extensions import db  # noqa: E402
from ntfds.models import Check, Device, Incident, utcnow  # noqa: E402

path = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "demo.db")
if os.path.exists(path):
    os.remove(path)
app = create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{path}", "MONITOR_ENABLED": False})
random.seed(7)

#        name,            host,           kind,      group,    parent, base_ms, lat,     lng,     status,       check, port
NET = [
    ("Edge Router",     "10.0.0.1",     "router",   "Core",   None,  2.1,  33.3152, 44.3661, "Online",      "icmp", None),
    ("Core Switch",     "10.0.0.2",     "switch",   "Core",   "Edge Router", 0.8, 33.3160, 44.3670, "Online", "icmp", None),
    ("Firewall",        "10.0.0.3",     "firewall", "Core",   "Edge Router", 1.2, 33.3148, 44.3650, "Online", "icmp", None),
    ("Floor-2 Switch",  "10.0.2.2",     "switch",   "Floor 2", "Core Switch", 1.6, 33.3420, 44.4010, "Offline", "icmp", None),
    ("AP Floor-2 A",    "10.0.2.11",    "ap",       "Floor 2", "Floor-2 Switch", 4.5, 33.3425, 44.4015, "Unreachable", "icmp", None),
    ("AP Floor-2 B",    "10.0.2.12",    "ap",       "Floor 2", "Floor-2 Switch", 4.8, 33.3418, 44.4005, "Unreachable", "icmp", None),
    ("Floor-1 Switch",  "10.0.1.2",     "switch",   "Floor 1", "Core Switch", 1.4, 33.3300, 44.3800, "Online", "icmp", None),
    ("AP Lobby",        "10.0.1.11",    "ap",       "Floor 1", "Floor-1 Switch", 6.2, 33.3305, 44.3805, "Warning", "icmp", None),
    ("Web Server",      "10.0.10.10",   "server",   "DMZ",    "Firewall", 9.5, 33.2800, 44.3300, "Online", "http", 443),
    ("DNS Resolver",    "10.0.10.53",   "server",   "DMZ",    "Firewall", 3.2, 33.2810, 44.3310, "Online", "dns", None),
    ("File Server",     "10.0.10.20",   "server",   "DMZ",    "Core Switch", 2.4, 33.2790, 44.3290, "Online", "tcp", 445),
    ("Printer HR",      "10.0.1.50",    "printer",  "Floor 1", "Floor-1 Switch", 7.1, 33.3310, 44.3790, "Online", "icmp", None),
    ("CCTV Gateway",    "10.0.20.5",    "camera",   "Security", "Core Switch", 5.5, 33.3200, 44.3500, "Online", "icmp", None),
    ("ISP Modem",       "192.168.100.1", "other",   "WAN",    None,  14.0, None, None, "Online", "icmp", None),
]
with app.app_context():
    db.session.query(Device).delete()
    now = utcnow()
    by = {}
    for name, host, kind, grp, parent, base, lat, lng, status, ct, port in NET:
        d = Device(name=name, host=host, kind=kind, group=grp, latitude=lat, longitude=lng, check_type=ct, port=port,
                   last_status=status, last_response_time=None if status in ("Offline", "Unreachable") else base,
                   last_checked=now, last_change=now - timedelta(minutes=random.randint(3, 600)),
                   last_loss=100.0 if status in ("Offline", "Unreachable") else (28.0 if status == "Warning" else 0.0),
                   last_jitter=round(base * 0.15, 2), last_detail={"Offline": "no response", "Unreachable": "parent Floor-2 Switch is down",
                   "Warning": "Packet loss 28.0%", "Online": "4/4 replies"}[status])
        if parent:
            d.parent_id = by[parent].id
        db.session.add(d); db.session.flush(); by[name] = d
        down_from = now - timedelta(minutes=34) if status in ("Offline", "Unreachable") else None
        rows = []
        for i in range(48 * 12):                       # 48h @ 5-min resolution
            ts = now - timedelta(minutes=5 * (48 * 12 - i))
            if down_from and ts >= down_from:
                rows.append(Check(device_id=d.id, status="Offline" if status == "Offline" else "Unreachable", packet_loss=100.0, timestamp=ts, detail="no response")); continue
            wave = 1 + .25 * math.sin(i / 20) + (.35 if 8 <= ts.hour <= 17 else 0)
            lat = max(.3, random.gauss(base * wave, base * .08)) * (6 if random.random() < .004 else 1)
            loss = 25.0 if (status == "Warning" and ts > now - timedelta(minutes=50)) else 0.0
            rows.append(Check(device_id=d.id, status="Warning" if loss else "Online", latency=round(lat, 2), packet_loss=loss,
                              jitter=round(lat * .12, 2), timestamp=ts, detail="4/4 replies"))
        db.session.bulk_save_objects(rows)
    for nm, kind, sev, msg, ago_m, dur in [
        ("Floor-2 Switch", "down", "critical", "No response — no reply · 2 downstream device(s) affected", 34, None),
        ("AP Lobby", "packet_loss", "warning", "Packet loss 28.0% (threshold 20%)", 48, None),
        ("Web Server", "ssl_expiry", "warning", "TLS certificate expires in 9.0 days", 1500, 600),
        ("File Server", "down", "critical", "No response — tcp/445 closed/unreachable", 1900, 420),
        ("Edge Router", "high_latency", "warning", "Latency 212 ms exceeds 150 ms", 2300, 900),
    ]:
        st = now - timedelta(minutes=ago_m)
        db.session.add(Incident(device_id=by[nm].id, kind=kind, severity=sev, message=msg, started_at=st,
                                ended_at=None if dur is None else st + timedelta(seconds=dur)))
    db.session.commit()
    print(f"seeded {len(NET)} devices → {path}")
