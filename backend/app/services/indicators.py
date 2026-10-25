"""Indicator (IOC) extraction, normalisation and validation.

Supported types: ipv4, ipv6, domain, url, md5, sha1, sha256.

IP scope classification is essential to avoid misinterpretation: private,
loopback, link-local, CGNAT, documentation (TEST-NET), multicast, reserved and
unspecified addresses are never sent to external OSINT sources.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

IP_TYPES = {"ipv4", "ipv6"}
HASH_TYPES = {"md5", "sha1", "sha256"}
ALL_TYPES = IP_TYPES | HASH_TYPES | {"domain", "url"}

_DOC_V4 = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
_BENCH_V4 = ipaddress.ip_network("198.18.0.0/15")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_DOC_V6 = ipaddress.ip_network("2001:db8::/32")

# Reserved / special-use TLDs (RFC 2606, RFC 6761, RFC 6762, RFC 9476)
SPECIAL_TLDS = {"test", "example", "invalid", "localhost", "local", "onion", "alt", "internal", "lan", "home", "corp"}
SPECIAL_DOMAINS = {"example.com", "example.net", "example.org"}

_IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])")
_IPV6_RE = re.compile(r"(?<![:\w])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![:\w])")
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>()\[\]{}]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?=.{4,253}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b", re.IGNORECASE)
_HASH_RES = {
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
}
# Common file extensions that look like TLDs in logs; avoids false domain hits.
_FILE_EXT_TLDS = {"exe", "dll", "log", "txt", "json", "xml", "php", "js", "py", "sh", "bat", "ps1", "tmp", "dat", "zip", "conf", "ini", "yml", "yaml", "csv", "html", "htm", "png", "jpg", "gif", "pdf", "docx", "xlsx", "sys", "msi", "cfg", "bin", "db"}


@dataclass
class ExtractedIndicator:
    type: str
    value: str
    role: str = "observed"
    extracted_from: str = ""
    scope: str = "public"
    classification: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str]:
        return (self.type, self.value)

    @property
    def enrichable(self) -> bool:
        """Only public, routable indicators are sent to external OSINT sources."""
        return self.scope == "public"


def refang(text: str) -> str:
    return (
        text.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".").replace("{.}", ".")
        .replace("hxxp", "http").replace("hXXp", "http").replace("[:]", ":").replace("[://]", "://")
    )


def classify_ip(value: str) -> tuple[str, dict[str, Any]]:
    """Return (scope, details) for an IP address string. Raises ValueError if invalid."""
    ip = ipaddress.ip_address(value.strip())
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return classify_ip(str(ip.ipv4_mapped))
    info: dict[str, Any] = {"version": ip.version, "normalized": ip.compressed}
    checks: list[tuple[str, bool]] = [
        ("unspecified", ip.is_unspecified),
        ("loopback", ip.is_loopback),
        ("multicast", ip.is_multicast),
        ("link_local", ip.is_link_local),
        ("documentation", any(ip in n for n in _DOC_V4) if ip.version == 4 else ip in _DOC_V6),
        ("benchmarking", ip.version == 4 and ip in _BENCH_V4),
        ("cgnat", ip.version == 4 and ip in _CGNAT),
        ("reserved", ip.is_reserved),
        ("private", ip.is_private),
        ("reserved", not ip.is_global),
    ]
    for scope, hit in checks:
        if hit:
            info["note"] = SCOPE_NOTES[scope]
            return scope, info
    info["note"] = SCOPE_NOTES["public"]
    return "public", info


SCOPE_NOTES = {
    "public": "Adresse publique routable : éligible à l'enrichissement OSINT.",
    "private": "Adresse privée (RFC 1918 / ULA) : interne, aucune recherche OSINT externe.",
    "loopback": "Adresse de bouclage : locale à l'hôte.",
    "link_local": "Adresse lien-local : non routable.",
    "multicast": "Adresse multicast : ne désigne pas un hôte unique.",
    "documentation": "Plage réservée à la documentation (TEST-NET / 2001:db8::/32) : jamais routée sur Internet.",
    "benchmarking": "Plage réservée aux tests de performance (RFC 2544).",
    "cgnat": "Espace partagé CGNAT (RFC 6598) : adresse d'opérateur, non attribuable à un client.",
    "reserved": "Adresse réservée ou à usage spécial : non routable publiquement.",
    "unspecified": "Adresse non spécifiée (0.0.0.0 / ::).",
    "special_domain": "Domaine réservé (RFC 2606/6761) : non résolu publiquement.",
}


def normalize_domain(value: str) -> str:
    value = refang(value).strip().strip(".").lower()
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Domaine invalide: {value}") from exc


def classify_domain(value: str) -> tuple[str, dict[str, Any]]:
    domain = normalize_domain(value)
    labels = domain.split(".")
    if len(labels) < 2 or len(domain) > 253 or any(not 0 < len(lbl) <= 63 for lbl in labels):
        raise ValueError(f"Domaine invalide: {value}")
    if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", domain) or labels[-1].isdigit():
        raise ValueError(f"Domaine invalide: {value}")
    if labels[-1] in SPECIAL_TLDS or ".".join(labels[-2:]) in SPECIAL_DOMAINS:
        return "special_domain", {"normalized": domain, "note": SCOPE_NOTES["special_domain"]}
    return "public", {"normalized": domain}


def validate_indicator(type_: str, value: str) -> ExtractedIndicator:
    """Validate and normalise a single indicator. Raises ValueError on invalid input."""
    if type_ not in ALL_TYPES:
        raise ValueError(f"Type d'indicateur non supporté: {type_}")
    value = refang(value.strip())
    if not value or len(value) > 2048:
        raise ValueError("Valeur vide ou trop longue")
    if type_ in IP_TYPES:
        scope, info = classify_ip(value)
        detected = "ipv4" if info["version"] == 4 else "ipv6"
        return ExtractedIndicator(detected, info["normalized"], scope=scope, classification=info)
    if type_ in HASH_TYPES:
        if not _HASH_RES[type_].fullmatch(value):
            raise ValueError(f"Empreinte {type_} invalide")
        return ExtractedIndicator(type_, value.lower(), classification={"algorithm": type_})
    if type_ == "domain":
        scope, info = classify_domain(value)
        return ExtractedIndicator("domain", info["normalized"], scope=scope, classification=info)
    # url
    parts = urlsplit(value)
    if parts.scheme.lower() not in ("http", "https", "ftp") or not parts.hostname:
        raise ValueError("URL invalide")
    host = parts.hostname
    try:
        scope, info = classify_ip(host)
    except ValueError:
        scope, info = classify_domain(host)
    normalized = parts._replace(scheme=parts.scheme.lower(), netloc=parts.netloc.lower()).geturl()
    return ExtractedIndicator("url", normalized, scope=scope, classification={"host": host, **info})


def guess_type(value: str) -> str | None:
    v = refang(value.strip())
    try:
        ip = ipaddress.ip_address(v)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass
    for t, rx in _HASH_RES.items():
        if rx.fullmatch(v):
            return t
    if _URL_RE.fullmatch(v):
        return "url"
    if _DOMAIN_RE.fullmatch(v):
        return "domain"
    return None


def extract_from_text(text: str, source_field: str = "text") -> list[ExtractedIndicator]:
    """Extract indicators from free text (log messages, descriptions)."""
    text = refang(text)
    found: dict[tuple[str, str], ExtractedIndicator] = {}

    def add(type_: str, raw: str) -> None:
        try:
            ind = validate_indicator(type_, raw)
        except ValueError:
            return
        ind.extracted_from = source_field
        found.setdefault(ind.key, ind)

    url_hosts: set[str] = set()
    for m in _URL_RE.finditer(text):
        add("url", m.group(0).rstrip(".,;"))
        host = urlsplit(m.group(0)).hostname
        if host:
            url_hosts.add(host.lower())
    for m in _IPV4_RE.finditer(text):
        add("ipv4", m.group(0))
    for m in _IPV6_RE.finditer(text):
        if m.group(0).count(":") >= 2 and any(c.isalnum() for c in m.group(0)):
            add("ipv6", m.group(0))
    for t in ("sha256", "sha1", "md5"):
        for m in _HASH_RES[t].finditer(text):
            if not any(k[1].find(m.group(0).lower()) >= 0 for k in found if k[0] in HASH_TYPES):
                add(t, m.group(0))
    for m in _DOMAIN_RE.finditer(text):
        candidate = m.group(0).lower()
        if candidate.rsplit(".", 1)[-1] in _FILE_EXT_TLDS:
            continue
        add("domain", candidate)
    for host in url_hosts:
        if guess_type(host) == "domain":
            add("domain", host)
    return list(found.values())
