"""Active troubleshooting tools: traceroute, DNS, port scan, HTTP probe, auto-diagnosis, subnet discovery."""
import functools
import ipaddress
import re
import shutil
import socket
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from .checks import IS_MAC, IS_WINDOWS, dns_query, have_ping, http_check, icmp_check, tcp_alive, tcp_check

_IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_MS_RE = re.compile(r"(<?\s*[\d.]+)\s*ms", re.I)
_tool_slots = None


def init_limits(n):
    global _tool_slots
    _tool_slots = threading.BoundedSemaphore(n)


class Busy(Exception):
    pass


def limited(fn):
    """Heavy tools share a small concurrency budget so one user can't exhaust the host."""
    @functools.wraps(fn)
    def wrap(*a, **k):
        if _tool_slots and not _tool_slots.acquire(blocking=False):
            raise Busy("too many diagnostic tasks running — try again in a few seconds")
        try:
            return fn(*a, **k)
        finally:
            if _tool_slots:
                _tool_slots.release()
    return wrap


# ───────────────────────────── traceroute ─────────────────────────────

def parse_traceroute(text):
    hops = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d{1,2})[:\s]", line)
        if not m:
            continue
        hop = int(m.group(1))
        ip = _IP_RE.search(line[m.end():])
        ms = [float(x.replace("<", "").strip()) for x in _MS_RE.findall(line)]
        if ip or "*" in line or "Request timed out" in line:
            hops.append({"hop": hop, "ip": ip.group(1) if ip else None,
                         "rtt": round(min(ms), 2) if ms else None})
    return hops


@limited
def traceroute(host, max_hops=20):
    if IS_WINDOWS:
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "1000", host]
    elif shutil.which("traceroute"):
        cmd = ["traceroute", "-n", "-q", "1", "-w", "1", "-m", str(max_hops), host]
    elif shutil.which("tracepath"):
        cmd = ["tracepath", "-n", "-m", str(max_hops), host]
    else:
        return {"available": False, "error": "traceroute/tracepath/tracert not installed", "hops": []}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=max_hops * 2 + 10)
    except subprocess.TimeoutExpired:
        return {"available": True, "error": "timed out", "hops": []}
    hops = parse_traceroute(p.stdout)
    reached = bool(hops) and hops[-1]["ip"] is not None and (hops[-1]["ip"] == host or p.returncode == 0)
    return {"available": True, "hops": hops, "reached": reached, "raw": p.stdout[-4000:]}


# ───────────────────────────── DNS ─────────────────────────────

@limited
def dns_lookup(name, server=None):
    out = {"name": name, "server": server, "records": [], "reverse": None}
    if server:
        try:
            ok, ms, rcode, n = dns_query(server, name)
            out.update(ok=ok and n > 0, latency=round(ms, 2), rcode=rcode, answers=n)
        except OSError as e:
            out.update(ok=False, error=str(e))
        return out
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(name, None)
        out["latency"] = round((time.perf_counter() - t0) * 1000, 2)
        seen = []
        for fam, _, _, _, sa in infos:
            if sa[0] not in seen:
                seen.append(sa[0])
                out["records"].append({"type": "AAAA" if fam == socket.AF_INET6 else "A", "value": sa[0]})
        out["ok"] = True
        try:
            ipaddress.ip_address(name)
            out["reverse"] = socket.gethostbyaddr(name)[0]
        except (ValueError, OSError):
            pass
    except socket.gaierror as e:
        out.update(ok=False, error=e.strerror or str(e), latency=round((time.perf_counter() - t0) * 1000, 2))
    return out


# ───────────────────────────── port scan ─────────────────────────────

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 123, 135, 139, 143, 161, 389, 443, 445, 465, 587, 993, 995,
                1433, 1723, 3306, 3389, 5432, 5900, 8080, 8443]


def _svc(p):
    try:
        return socket.getservbyport(p)
    except OSError:
        return None


def _probe_port(host, port, timeout):
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(0.4)
            banner = ""
            try:
                banner = s.recv(120).decode("latin1", "replace").strip().splitlines()[0][:100]
            except (OSError, IndexError):
                pass
            return {"port": port, "state": "open", "service": _svc(port), "banner": banner,
                    "ms": round((time.perf_counter() - t0) * 1000, 1)}
    except ConnectionRefusedError:
        return {"port": port, "state": "closed", "service": _svc(port)}
    except OSError:
        return {"port": port, "state": "filtered", "service": _svc(port)}


@limited
def port_scan(host, ports=None, timeout=1.0):
    ports = sorted(set(ports or COMMON_PORTS))[:1024]
    res = []
    with ThreadPoolExecutor(max_workers=64) as ex:
        res = [f.result() for f in as_completed([ex.submit(_probe_port, host, p, timeout) for p in ports])]
    res.sort(key=lambda r: r["port"])
    return {"host": host, "scanned": len(ports), "open": [r for r in res if r["state"] == "open"],
            "closed": sum(r["state"] == "closed" for r in res), "filtered": sum(r["state"] == "filtered" for r in res)}


def parse_ports(spec):
    """'22,80,8000-8010' → sorted list; raises ValueError."""
    out = set()
    for part in str(spec).replace(" ", "").split(","):
        if not part:
            continue
        a, _, b = part.partition("-")
        lo, hi = int(a), int(b or a)
        if not (1 <= lo <= hi <= 65535) or hi - lo > 1023:
            raise ValueError("bad port range")
        out.update(range(lo, hi + 1))
    if not out or len(out) > 1024:
        raise ValueError("1–1024 ports per scan")
    return sorted(out)


# ───────────────────────────── local network info ─────────────────────────────

def local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))   # UDP connect sends nothing; just picks the route
            return s.getsockname()[0]
    except OSError:
        return None


def default_gateway():
    try:
        with open("/proc/net/route") as f:
            for line in list(f)[1:]:
                p = line.split()
                if p[1] == "00000000" and int(p[3], 16) & 2:
                    return socket.inet_ntoa(bytes.fromhex(p[2])[::-1])
    except OSError:
        pass
    try:   # macOS / BSD / Windows
        cmd = ["route", "print", "0.0.0.0"] if IS_WINDOWS else ["netstat", "-rn"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"(?:default|0\.0\.0\.0\s+0\.0\.0\.0)\s+(\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def arp_table():
    table = {}
    try:
        with open("/proc/net/arp") as f:
            for line in list(f)[1:]:
                p = line.split()
                if len(p) >= 4 and p[3] != "00:00:00:00:00:00":
                    table[p[0]] = p[3]
        return table
    except OSError:
        pass
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5).stdout
        for ip, mac in re.findall(r"(\d+\.\d+\.\d+\.\d+)\D+([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", out):
            table[ip] = mac.lower().replace("-", ":")
    except (OSError, subprocess.TimeoutExpired):
        pass
    return table


# ───────────────────────────── http tool ─────────────────────────────

@limited
def http_probe(url):
    r = http_check(url)
    return {"ok": r.ok, "latency": r.latency, "detail": r.detail, **(r.extra or {})}


# ───────────────────────────── auto diagnosis ─────────────────────────────

def _finding(sev, code, text, fix=None):
    return {"severity": sev, "code": code, "text": text, "fix": fix}


@limited
def diagnose(host, check_type="icmp", port=None, url=None, reference_hosts=()):
    """Walk the network stack bottom-up and explain where it breaks.
    Steps: DNS → local gateway → reference Internet hosts → target ICMP → target service → path (traceroute)."""
    steps, findings = [], []

    def step(name, ok, detail, data=None):
        steps.append({"name": name, "ok": ok, "detail": detail, "data": data})
        return ok

    is_ip = True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        is_ip = False
    target_ip = host
    if not is_ip:
        d = _resolve(host)
        if step("dns", d.get("ok", False), (d.get("records") and d["records"][0]["value"]) or d.get("error", "failed"), d):
            target_ip = d["records"][0]["value"]
        else:
            findings.append(_finding("critical", "dns_fail", f"Name '{host}' does not resolve.",
                                     "Check the DNS server settings, the spelling of the name, or use the IP address directly."))
            return {"host": host, "steps": steps, "findings": findings, "verdict": "dns_fail"}

    gw = default_gateway()
    gw_ok = None
    if gw:
        r = icmp_check(gw, count=3, timeout=1)
        gw_ok = step("gateway", r.ok, f"{gw}: {r.detail}" if r.ok else f"{gw} not answering", {"ip": gw, "latency": r.latency, "loss": r.loss})
        if not gw_ok:
            findings.append(_finding("critical", "gateway_down", f"Default gateway {gw} is not answering.",
                                     "Check this machine's cable/Wi-Fi, switch port, and the gateway device itself."))

    refs = []
    for ref in reference_hosts:
        r = icmp_check(ref, count=2, timeout=1)
        refs.append(r.ok)
        step(f"internet:{ref}", r.ok, r.detail if r.ok else "no reply", {"latency": r.latency})
    internet_ok = any(refs) if refs else None

    rt = icmp_check(target_ip, count=8, timeout=1.0)
    step("icmp", rt.ok, rt.detail, {"latency": rt.latency, "loss": rt.loss, "jitter": rt.jitter})
    svc_ok = None
    if check_type == "tcp" and port:
        s = tcp_check(target_ip, port, samples=3)
        svc_ok = step(f"tcp/{port}", s.ok, s.detail, {"latency": s.latency})
    elif check_type == "http":
        h = http_check(url or f"http://{host}/")
        svc_ok = step("http", h.ok, h.detail, {"latency": h.latency, **(h.extra or {})})
        code = (h.extra or {}).get("http_status", 0)
        if code >= 400:
            findings.append(_finding("critical" if code >= 500 else "warning", "http_error", f"The web service answers with HTTP {code}.",
                                     "Check the application/web-server logs and the URL/credentials used by the monitor."))
            svc_ok = svc_ok and code < 500
        d = (h.extra or {}).get("ssl_days")
        if d is not None and d < 14:
            findings.append(_finding("warning" if d > 0 else "critical", "ssl_expiring",
                                     f"TLS certificate {'expires in %.0f days' % d if d > 0 else 'has expired'}.", "Renew the certificate."))
    elif check_type == "dns":
        try:
            ok, ms, rc, n = dns_query(target_ip, "example.com")
            svc_ok = step("dns-server", ok and n > 0, f"rcode={rc} answers={n} in {ms:.0f} ms")
        except OSError as e:
            svc_ok = step("dns-server", False, str(e))

    tr = traceroute.__wrapped__(target_ip) if not rt.ok else None
    if tr and tr.get("hops"):
        answered = [h for h in tr["hops"] if h["ip"]]
        last = answered[-1] if answered else None
        step("traceroute", bool(tr.get("reached")), f"last responding hop: {last['hop']} ({last['ip']})" if last else "no hops answered", tr)
    elif tr and not tr.get("available"):
        step("traceroute", False, tr["error"], tr)

    # ── conclusions
    verdict = "healthy"
    if not rt.ok and svc_ok:
        findings.append(_finding("info", "icmp_blocked", "ICMP is filtered but the service answers — the device is up.",
                                 "Allow ICMP echo or monitor this device with a TCP/HTTP check instead."))
        verdict = "icmp_blocked"
    elif not rt.ok:
        if gw_ok is False:
            verdict = "local_network"
            findings.append(_finding("critical", "local_network", "The fault is on the local side: even the default gateway is unreachable.",
                                     "Check this host's NIC, cable, VLAN and switch uplink first."))
        elif internet_ok is False and gw_ok:
            verdict = "wan_down"
            findings.append(_finding("critical", "wan_down", "Local network is fine but reference Internet hosts do not answer — likely a WAN/ISP outage.",
                                     "Check the router's WAN link and contact the ISP."))
        else:
            verdict = "target_down"
            hint = ""
            if tr and tr.get("hops"):
                answered = [h for h in tr["hops"] if h["ip"]]
                if answered:
                    hint = f" The path stops after {answered[-1]['ip']} (hop {answered[-1]['hop']}) — inspect the next device/link beyond it."
            findings.append(_finding("critical", "target_down", f"{host} does not respond and the rest of the network is healthy.{hint}",
                                     "Check power, the port/cable on its switch, its firewall rules and its IP configuration."))
    else:
        if rt.loss and rt.loss >= 10:
            findings.append(_finding("warning", "packet_loss", f"{rt.loss}% packet loss to the target.",
                                     "Suspect a bad cable/SFP, duplex mismatch, Wi-Fi interference or link saturation."))
            verdict = "degraded"
        if rt.jitter and rt.jitter > 30:
            findings.append(_finding("warning", "jitter", f"High jitter ({rt.jitter} ms).",
                                     "Look for congestion/bufferbloat; apply QoS for real-time traffic."))
            verdict = "degraded"
        if rt.latency and rt.latency > 150:
            findings.append(_finding("warning", "high_latency", f"High latency ({rt.latency} ms).",
                                     "Compare with traceroute to find the slow hop; check link utilisation."))
            verdict = "degraded"
        if svc_ok is False:
            findings.append(_finding("critical", "service_down", "Host answers ping but the monitored service does not.",
                                     "Restart the service, check the listening port and any host firewall."))
            verdict = "service_down"
    if not findings:
        findings.append(_finding("ok", "healthy", "All checks passed.", None))
    elif verdict == "healthy" and any(f["severity"] in ("warning", "critical") for f in findings):
        verdict = "degraded"
    return {"host": host, "target_ip": target_ip, "steps": steps, "findings": findings, "verdict": verdict}


def _resolve(host):
    try:
        infos = socket.getaddrinfo(host, None)
        return {"ok": True, "records": [{"type": "A", "value": infos[0][4][0]}]}
    except socket.gaierror as e:
        return {"ok": False, "error": e.strerror or str(e)}


# ───────────────────────────── discovery ─────────────────────────────

_jobs = {}
_jobs_lock = threading.Lock()


def parse_cidr(cidr, max_hosts, allow_public=False):
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 4:
        raise ValueError("IPv4 only")
    if net.num_addresses > max_hosts:
        raise ValueError(f"range too large (max {max_hosts} addresses)")
    if not allow_public and not (net.is_private or net.is_loopback or net.is_link_local):
        raise ValueError("public ranges are disabled (set NTFDS_ALLOW_PUBLIC_SCAN=1 to allow)")
    return net


def _sweep_host(ip):
    if have_ping():
        r = icmp_check(ip, count=1, timeout=1)
        if r.ok:
            return r.latency
    up, ms = tcp_alive(ip, timeout=0.5)
    return round(ms, 2) if up else None


def _rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def start_discovery(cidr, max_hosts, allow_public=False):
    net = parse_cidr(cidr, max_hosts, allow_public)
    hosts = [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]
    job = {"id": uuid.uuid4().hex[:12], "cidr": str(net), "total": len(hosts), "done": 0,
           "state": "running", "found": [], "started": time.time()}
    with _jobs_lock:
        for k in [k for k, v in _jobs.items() if time.time() - v["started"] > 3600]:
            _jobs.pop(k)
        _jobs[job["id"]] = job

    def run():
        with ThreadPoolExecutor(max_workers=64) as ex:
            futs = {ex.submit(_sweep_host, h): h for h in hosts}
            for f in as_completed(futs):
                job["done"] += 1
                ms = f.result()
                if ms is not None:
                    job["found"].append({"ip": futs[f], "latency": ms})
            arp = arp_table()
            names = {x["ip"]: ex.submit(_rdns, x["ip"]) for x in job["found"]}
            for x in job["found"]:
                x["mac"] = arp.get(x["ip"])
                x["hostname"] = names[x["ip"]].result()
            job["found"].sort(key=lambda x: ipaddress.ip_address(x["ip"]))
        job["state"] = "done"

    threading.Thread(target=run, daemon=True, name="discovery").start()
    return job


def get_job(job_id):
    return _jobs.get(job_id)
