"""Input validation and authentication helpers. Nothing user-supplied ever reaches a shell."""
import hmac
import ipaddress
import re

from flask import current_app, jsonify, request

_HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$")


def valid_host(value):
    """True for an IPv4/IPv6 literal or an RFC-ish hostname. Rejects leading '-', spaces, shell chars."""
    if not isinstance(value, str) or not value or value.startswith("-"):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(_HOST_RE.match(value))


def valid_port(p):
    return isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535


def valid_url(u):
    return isinstance(u, str) and re.match(r"^https?://[^\s/$.?#][^\s]*$", u) is not None and len(u) <= 255


def is_private_target(host):
    """Resolve-free check: True if host is an IP literal in a private/loopback/link-local range."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def check_token(token):
    expected = current_app.config.get("API_TOKEN") or ""
    return bool(expected) and bool(token) and hmac.compare_digest(str(token), expected)


def extract_token():
    h = request.headers.get("Authorization", "")
    if h.lower().startswith("bearer "):
        return h[7:].strip()
    return request.headers.get("X-API-Key") or ""


def auth_required_response():
    """Returns a 401 response when auth is enabled and the request has no valid token, else None."""
    if not current_app.config.get("API_TOKEN"):
        return None
    if check_token(extract_token()):
        return None
    return jsonify({"error": "unauthorized"}), 401
