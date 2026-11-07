"""Checks shared by every loopback listener (broker, admin API).

Binding to 127.0.0.1 keeps remote hosts out, but not web pages: a page in the
operator's browser can send "simple" cross-origin requests to loopback without a
CORS preflight, and a DNS-rebinding page can make its own origin resolve to
127.0.0.1 and read responses as same-origin. These helpers close both doors.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from urllib.parse import urlsplit

# Sec-Fetch-Site values that mean "another site asked for this".
_CROSS_SITE_FETCH_VALUES = {"cross-site", "same-site"}


def is_loopback_host(hostname: str) -> bool:
    hostname = hostname.strip().strip("[]").lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def is_loopback_authority(authority: str) -> bool:
    try:
        hostname = urlsplit(f"//{authority}").hostname
    except ValueError:
        return False
    return bool(hostname) and is_loopback_host(hostname)


def browser_request_rejection(headers: Mapping[str, str]) -> str | None:
    """Return why a request looks browser-originated, or ``None`` if it does not.

    Programmatic HTTP clients and SDKs do not send ``Origin``; browsers send it on
    every cross-origin request and on all non-GET requests.
    """
    lowered = {key.lower(): value for key, value in headers.items()}
    if "origin" in lowered:
        return "requests carrying an Origin header are not accepted"
    if lowered.get("sec-fetch-site", "").lower() in _CROSS_SITE_FETCH_VALUES:
        return "cross-site browser requests are not accepted"
    return None


def require_loopback_bind(host: str) -> None:
    if not is_loopback_host(host):
        raise ValueError(f"refusing to listen on non-loopback address {host!r}")
