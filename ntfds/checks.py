"""Probe implementations. Pure functions: no DB, no Flask — safe to run in worker threads."""
import platform
import re
import shutil
import socket
import ssl
import statistics
import struct
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

IS_WINDOWS = platform.system().lower() == "windows"
IS_MAC = platform.system().lower() == "darwin"


@dataclass
class CheckResult:
    ok: bool
    latency: float = None      # ms (mean)
    loss: float = None         # %
    jitter: float = None       # ms (mean abs delta between consecutive replies)
    detail: str = ""
    extra: dict = field(default_factory=dict)   # http_status, ssl_days, samples...


# ───────────────────────────── ICMP ─────────────────────────────

_TIME_RE = re.compile(r"time\s*[=<]\s*([\d.,]+)\s*ms", re.I)
_TTL_RE = re.compile(r"ttl\s*=", re.I)


def parse_ping_output(output, sent):
    """Parse linux/mac/windows ping output → (times_ms list, loss_pct). Locale-tolerant."""
    times = [float(t.replace(",", ".")) for t in _TIME_RE.findall(output)]
    replies = max(len(times), len(_TTL_RE.findall(output)))
    replies = min(replies, sent)
    loss = round(100.0 * (sent - replies) / sent, 1) if sent else 100.0
    return times, loss


def _jitter(times):
    if len(times) < 2:
        return 0.0
    return round(statistics.fmean(abs(b - a) for a, b in zip(times, times[1:])), 2)


def ping_command(host, count, timeout_s):
    if IS_WINDOWS:
        return ["ping", "-n", str(count), "-w", str(int(timeout_s * 1000)), host]
    if IS_MAC:
        return ["ping", "-c", str(count), "-i", "0.2", "-W", str(int(timeout_s * 1000)), host]
    return ["ping", "-c", str(count), "-i", "0.2", "-W", str(max(1, int(timeout_s))), host]


def have_ping():
    return shutil.which("ping") is not None


_FALLBACK_PORTS = (443, 80, 22, 445, 53, 135, 23, 8080)


def tcp_alive(host, ports=_FALLBACK_PORTS, timeout=0.8):
    """Host liveness without ICMP: a connect or an immediate RST both prove the host is up."""
    for p in ports:
        t0 = time.perf_counter()
        try:
            with socket.create_connection((host, p), timeout=timeout):
                return True, (time.perf_counter() - t0) * 1000
        except ConnectionRefusedError:
            return True, (time.perf_counter() - t0) * 1000
        except OSError:
            continue
    return False, None


def icmp_check(host, count=4, timeout=1.0):
    if not have_ping():
        up, ms = tcp_alive(host)
        if up:
            return CheckResult(True, round(ms, 2), 0.0, 0.0, "ping binary missing — TCP liveness fallback")
        return CheckResult(False, None, 100.0, None, "no response (TCP fallback; ping binary missing)")
    try:
        proc = subprocess.run(ping_command(host, count, timeout), capture_output=True, text=True,
                              timeout=count * (timeout + 0.5) + 3)
        out = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return CheckResult(False, None, 100.0, None, "ping timed out")
    except OSError as e:
        return CheckResult(False, None, 100.0, None, f"ping failed: {e}")
    times, loss = parse_ping_output(out, count)
    if not times:
        # Replies without parsable times (rare locales) still count as alive
        if loss < 100:
            return CheckResult(True, None, loss, None, "reply without timing")
        return CheckResult(False, None, 100.0, None, "no reply")
    return CheckResult(True, round(statistics.fmean(times), 2), loss, _jitter(times),
                       f"{len(times)}/{count} replies", {"min": min(times), "max": max(times)})


# ───────────────────────────── TCP ─────────────────────────────

def tcp_check(host, port, samples=3, timeout=2.0):
    times, err = [], ""
    for _ in range(samples):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                times.append((time.perf_counter() - t0) * 1000)
        except OSError as e:
            err = e.strerror or str(e)
        if len(times) < samples:
            time.sleep(0.05)
    loss = round(100.0 * (samples - len(times)) / samples, 1)
    if not times:
        return CheckResult(False, None, 100.0, None, f"port {port} closed/unreachable: {err}")
    return CheckResult(True, round(statistics.fmean(times), 2), loss, _jitter(times),
                       f"tcp/{port} open ({len(times)}/{samples})")


# ───────────────────────────── HTTP(S) ─────────────────────────────

def cert_days_left(host, port=443, timeout=4.0):
    """Days until the TLS certificate expires, or None if the cert can't be validated."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
        return round((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400, 1)
    except ssl.SSLCertVerificationError as e:
        if "expired" in str(e).lower():
            return -1.0
        return None
    except (OSError, KeyError, ValueError):
        return None


def http_check(url, timeout=6.0):
    from urllib.parse import urlparse
    u = urlparse(url)
    extra, ssl_note = {}, ""
    ctx = None
    req = urllib.request.Request(url, headers={"User-Agent": "NTFDS-Monitor/2.0"})

    def fetch(context):
        t0 = time.perf_counter()
        with urllib.request.urlopen(req, timeout=timeout, context=context) as r:
            r.read(2048)
            return r.status, (time.perf_counter() - t0) * 1000, r.headers.get("Server", "")

    try:
        try:
            status, ms, server = fetch(ctx)
        except urllib.error.URLError as e:
            if isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError):
                reason = str(e.reason).lower()
                if "expired" in reason:
                    return CheckResult(False, None, None, None, "TLS certificate expired", {"ssl_days": -1})
                # internal gear is often self-signed: stay up, but flag it
                ssl_note = "untrusted certificate"
                unverified = ssl._create_unverified_context()
                status, ms, server = fetch(unverified)
                extra["ssl_untrusted"] = True
            else:
                raise
    except urllib.error.HTTPError as e:   # 4xx/5xx — server answered
        status, ms, server = e.code, None, e.headers.get("Server", "") if e.headers else ""
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        why = getattr(e, "reason", e)
        return CheckResult(False, None, 100.0, None, f"http error: {why}")

    extra.update({"http_status": status, "server": server})
    if u.scheme == "https":
        days = cert_days_left(u.hostname, u.port or 443)
        if days is not None:
            extra["ssl_days"] = days
    ok = status < 500
    detail = f"HTTP {status}" + (f" · {ssl_note}" if ssl_note else "")
    return CheckResult(ok, round(ms, 2) if ms is not None else None, 0.0 if ok else 100.0, None, detail, extra)


# ───────────────────────────── DNS ─────────────────────────────

def dns_query(server, name, timeout=3.0, qtype=1):
    """Minimal UDP DNS client (A/AAAA/…) so we can test a *specific* resolver without extra deps.
    Returns (ok, ms, rcode, answers)."""
    tid = int.from_bytes(__import__("os").urandom(2), "big")
    q = b"".join(bytes([len(p)]) + p.encode("idna") for p in name.rstrip(".").split(".")) + b"\x00"
    packet = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", qtype, 1)
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        t0 = time.perf_counter()
        s.sendto(packet, (server, 53))
        data, _ = s.recvfrom(1500)
        ms = (time.perf_counter() - t0) * 1000
    if len(data) < 12 or struct.unpack(">H", data[:2])[0] != tid:
        raise OSError("malformed DNS response")
    flags, _, ancount = struct.unpack(">HHH", data[2:8])
    return (flags & 0x000F) == 0, ms, flags & 0x000F, ancount


def dns_check(server, name="example.com", samples=3):
    name = name or "example.com"
    times, last = [], ""
    for _ in range(samples):
        try:
            ok, ms, rcode, answers = dns_query(server, name)
            if ok and answers:
                times.append(ms)
            else:
                last = f"rcode={rcode} answers={answers}"
        except (OSError, UnicodeError) as e:
            last = str(e)
    loss = round(100.0 * (samples - len(times)) / samples, 1)
    if not times:
        return CheckResult(False, None, 100.0, None, f"DNS {server} failed for {name}: {last}")
    return CheckResult(True, round(statistics.fmean(times), 2), loss, _jitter(times), f"resolved {name} ({len(times)}/{samples})")


# ───────────────────────────── dispatch ─────────────────────────────

def run_check(snap):
    """snap: dict from Device.snapshot(). Never raises."""
    t, host, port, arg = snap["check_type"], snap["host"], snap.get("port"), snap.get("check_arg")
    try:
        if t == "tcp" and port:
            return tcp_check(host, port)
        if t == "http":
            url = arg or f"{'https' if port == 443 else 'http'}://{host}{':%d' % port if port and port not in (80, 443) else ''}/"
            return http_check(url)
        if t == "dns":
            return dns_check(host, arg)
        return icmp_check(host)
    except Exception as e:  # a probe bug must never kill the engine
        return CheckResult(False, None, None, None, f"check error: {e.__class__.__name__}: {e}")
