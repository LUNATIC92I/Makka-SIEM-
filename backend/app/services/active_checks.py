"""Authorised active checks (DISABLED by default).

Only a TCP connect test on a short list of ports, only towards addresses inside
``MAKKADI_ACTIVE_CHECKS_ALLOWED_CIDRS`` (assets owned by the organisation or
explicitly in scope). No range scanning: one address per request, rate limited,
and every check is audited. There is deliberately no way to target arbitrary
public addresses.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

from app.core.config import get_settings
from app.core.errors import ValidationFailed


def authorize_target(address: str, ports: list[int]) -> tuple[ipaddress._BaseAddress, list[int]]:
    s = get_settings()
    if not s.active_checks_enabled:
        raise ValidationFailed("Mode actif désactivé (MAKKADI_ACTIVE_CHECKS_ENABLED=false).")
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ValidationFailed("Une seule adresse IP est acceptée (pas de plage, pas de nom).") from exc
    if not any(ip in ipaddress.ip_network(c, strict=False) for c in s.active_checks_allowed_cidrs):
        raise ValidationFailed("Adresse hors du périmètre autorisé pour les contrôles actifs.")
    allowed = set(s.active_checks_allowed_ports)
    bad = [p for p in ports if p not in allowed]
    if bad or not ports:
        raise ValidationFailed(f"Ports non autorisés : {bad or 'aucun'}")
    if len(ports) > 10:
        raise ValidationFailed("10 ports maximum par contrôle.")
    return ip, ports


async def tcp_check(address: str, ports: list[int], timeout: float = 3.0) -> list[dict[str, Any]]:
    ip, ports = authorize_target(address, ports)
    out = []
    for port in ports:
        try:
            _r, w = await asyncio.wait_for(asyncio.open_connection(str(ip), port), timeout=timeout)
            w.close()
            out.append({"port": port, "state": "open"})
        except (TimeoutError, OSError):
            out.append({"port": port, "state": "closed_or_filtered"})
    return out
