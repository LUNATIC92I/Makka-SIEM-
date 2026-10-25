"""Outbound destination validation (SSRF protection).

Every outbound request performed by a connector goes through
``validate_outbound_url``. Rules:

* only ``https`` (``http`` is allowed only for hosts explicitly allow-listed);
* no credentials embedded in the URL;
* the host must resolve exclusively to *global* unicast addresses, unless the
  host name is in ``MAKKADI_OUTBOUND_ALLOWED_HOSTS`` or the resolved address is
  inside ``MAKKADI_OUTBOUND_ALLOWED_CIDRS`` (on-premise SIEM for example);
* redirects are not followed automatically: each hop is re-validated.

Residual risk (documented): DNS rebinding between validation and connection
is mitigated by re-validating on each hop but not fully eliminated.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

from app.core.config import get_settings
from app.core.errors import OutboundBlocked

Resolver = Callable[[str], list[str]]


def system_resolver(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise OutboundBlocked(f"Résolution DNS impossible pour {host}") from exc
    return sorted({info[4][0] for info in infos})


_resolver: Resolver = system_resolver


def set_resolver(resolver: Resolver | None) -> None:
    """Override DNS resolution (tests)."""
    global _resolver
    _resolver = resolver or system_resolver


def _ip_allowed_by_policy(ip: ipaddress._BaseAddress) -> bool:
    for cidr in get_settings().outbound_allowed_cidrs:
        if ip in ipaddress.ip_network(cidr, strict=False):
            return True
    return False


def validate_outbound_url(url: str) -> str:
    settings = get_settings()
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise OutboundBlocked("URL sans hôte")
    if parts.username or parts.password:
        raise OutboundBlocked("Identifiants intégrés à l'URL interdits")
    host_allowed = host in {h.lower() for h in settings.outbound_allowed_hosts}
    if scheme not in ("https", "http"):
        raise OutboundBlocked(f"Schéma interdit: {scheme}")
    if scheme == "http" and not host_allowed:
        raise OutboundBlocked("HTTP non chiffré interdit (seul HTTPS est autorisé)")
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
        addresses = [str(literal)]
    except ValueError:
        addresses = _resolver(host)
    if not addresses:
        raise OutboundBlocked(f"Aucune adresse pour {host}")
    for addr in addresses:
        ip = ipaddress.ip_address(addr)
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        if ip.is_global and not ip.is_multicast:
            continue
        if host_allowed or _ip_allowed_by_policy(ip):
            continue
        raise OutboundBlocked(
            f"Destination interne ou réservée refusée ({host} -> {ip}). "
            "Ajoutez-la explicitement à MAKKADI_OUTBOUND_ALLOWED_HOSTS si elle est autorisée."
        )
    return url
