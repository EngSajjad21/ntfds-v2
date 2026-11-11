import http.server
import socket
import struct
import threading

from ntfds import checks, diagnostics
from ntfds.security import valid_host, valid_port, valid_url

LINUX = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=10.2 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=12.4 ms
64 bytes from 1.1.1.1: icmp_seq=4 ttl=57 time=11.0 ms
--- 1.1.1.1 ping statistics ---
4 packets transmitted, 3 received, 25% packet loss, time 603ms"""

WINDOWS = """Reply from 192.168.1.1: bytes=32 time<1ms TTL=64
Reply from 192.168.1.1: bytes=32 time=2ms TTL=64
Request timed out.
Reply from 192.168.1.1: bytes=32 time=3ms TTL=64"""

TRACE = """traceroute to 8.8.8.8, 20 hops max
 1  192.168.1.1  0.512 ms
 2  * 
 3  10.0.0.1  8.1 ms
 4  8.8.8.8  12.0 ms"""


def test_parse_ping_linux():
    times, loss = checks.parse_ping_output(LINUX, 4)
    assert times == [10.2, 12.4, 11.0] and loss == 25.0
    assert checks._jitter(times) == round((2.2 + 1.4) / 2, 2)


def test_parse_ping_windows():
    times, loss = checks.parse_ping_output(WINDOWS, 4)
    assert len(times) == 3 and loss == 25.0


def test_parse_traceroute():
    hops = diagnostics.parse_traceroute(TRACE)
    assert [h["ip"] for h in hops] == ["192.168.1.1", None, "10.0.0.1", "8.8.8.8"]
    assert hops[0]["rtt"] == 0.51


def test_validators_block_injection():
    for bad in ["-c1", "a b", "1.1.1.1; rm -rf /", "$(id)", "host`x`", "", "a" * 300, "x|y"]:
        assert not valid_host(bad), bad
    for ok in ["192.168.1.1", "router.local", "fe80::1", "my-host_1"]:
        assert valid_host(ok), ok
    assert valid_port(443) and not valid_port(0) and not valid_port(70000) and not valid_port(True)
    assert valid_url("https://a.b/x") and not valid_url("ftp://a") and not valid_url("javascript:alert(1)")


def test_parse_ports():
    assert diagnostics.parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]
    for bad in ["0", "70000", "1-5000", "abc"]:
        try:
            diagnostics.parse_ports(bad)
            assert False, bad
        except ValueError:
            pass


def test_parse_cidr_limits():
    assert diagnostics.parse_cidr("192.168.1.0/24", 1024).num_addresses == 256
    for bad in ["10.0.0.0/8", "8.8.8.0/24", "::1/128"]:
        try:
            diagnostics.parse_cidr(bad, 1024)
            assert False, bad
        except ValueError:
            pass


def test_tcp_check_open_and_closed():
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5)
    port = srv.getsockname()[1]
    r = checks.tcp_check("127.0.0.1", port, samples=2)
    assert r.ok and r.loss == 0
    srv.close()
    assert not checks.tcp_check("127.0.0.1", port, samples=1, timeout=0.5).ok


def test_http_check_local():
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(404 if self.path == "/missing" else 200); self.end_headers(); self.wfile.write(b"hi")
        def log_message(self, *a): pass
    s = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{s.server_port}"
    r = checks.http_check(base + "/")
    assert r.ok and r.extra["http_status"] == 200
    assert checks.http_check(base + "/missing").extra["http_status"] == 404
    s.shutdown()
    assert not checks.http_check(base + "/").ok


def test_dns_query_against_fake_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); srv.bind(("127.0.0.1", 0))
    orig = socket.socket.sendto

    def serve():
        data, addr = srv.recvfrom(512)
        # echo header with QR bit + 1 answer count, rcode 0
        orig(srv, data[:2] + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0) + data[12:], addr)
    threading.Thread(target=serve, daemon=True).start()
    # point the client at our port by monkeypatching sendto target port 53 → fake port
    port = srv.getsockname()[1]
    def patched(self, data, addr):
        return orig(self, data, (addr[0], port))
    socket.socket.sendto = patched
    try:
        ok, ms, rcode, n = checks.dns_query("127.0.0.1", "example.com", timeout=2)
    finally:
        socket.socket.sendto = orig
    assert ok and rcode == 0 and n == 1


def test_icmp_fallback_without_ping(monkeypatch):
    monkeypatch.setattr(checks, "have_ping", lambda: False)
    monkeypatch.setattr(checks, "tcp_alive", lambda h, **k: (True, 1.5))
    r = checks.icmp_check("10.0.0.1")
    assert r.ok and "fallback" in r.detail
