"""Handling of untrusted text (SIEM logs, OSINT payloads, domain names...).

All such data is treated as *data*, never as instructions. This module:
* strips control characters and bounds sizes;
* flags typical prompt-injection patterns so they can be shown to the analyst
  and neutralised before any AI processing.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

_CONTROL = re.compile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f\\u200b-\\u200f\\u202a-\\u202e\\u2066-\\u2069]")

INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ignore_instructions", re.compile(r"(?i)\b(ignore|disregard|forget|oublie[zr]?|ignore[zr]?)\b.{0,40}\b(previous|prior|above|all|précédentes?|toutes?)\b.{0,30}\b(instructions?|rules?|consignes?|règles?)")),
    ("role_override", re.compile(r"(?i)\b(you are now|act as|tu es maintenant|agis comme|new instructions|nouvelles instructions)\b")),
    ("system_prompt", re.compile(r"(?i)(system\s*prompt|<\s*/?\s*(system|assistant|user|instructions?)\s*>|\[/?INST\]|<\|im_(start|end)\|>)")),
    ("exfiltration", re.compile(r"(?i)\b(reveal|print|show|send|exfiltrate|révèle|affiche|envoie)\b.{0,40}\b(api[ _-]?key|secret|password|token|mot de passe|prompt)\b")),
    ("tool_call", re.compile(r"(?i)\b(execute|run|call|exécute|lance)\b.{0,30}\b(command|tool|function|shell|commande|outil)\b")),
    ("verdict_manipulation", re.compile(r"(?i)\b(mark|classify|report|consider|marque|classe|considère)\b.{0,40}\b(as\s+)?(benign|safe|clean|harmless|bénin|sûr|légitime|false positive|faux positif)\b")),
]


def clean_text(value: str, max_len: int = 4000) -> str:
    value = unicodedata.normalize("NFKC", value)
    value = _CONTROL.sub("", value)
    if len(value) > max_len:
        value = value[:max_len] + " [tronqué]"
    return value


def detect_injection(value: str) -> list[str]:
    return [name for name, pattern in INJECTION_PATTERNS if pattern.search(value)]


def scan_structure(data: Any, path: str = "$", max_items: int = 5000) -> list[dict[str, str]]:
    """Walk a JSON-like structure and report fields containing injection patterns."""
    flags: list[dict[str, str]] = []
    stack: list[tuple[str, Any]] = [(path, data)]
    seen = 0
    while stack and seen < max_items:
        p, item = stack.pop()
        seen += 1
        if isinstance(item, dict):
            stack.extend((f"{p}.{k}", v) for k, v in item.items())
        elif isinstance(item, list):
            stack.extend((f"{p}[{i}]", v) for i, v in enumerate(item))
        elif isinstance(item, str):
            for name in detect_injection(item):
                flags.append({"path": p, "pattern": name, "excerpt": clean_text(item, 160)})
    return flags


def sanitize_structure(data: Any, max_str: int = 2000, depth: int = 0) -> Any:
    """Return a copy with cleaned strings and bounded depth/size."""
    if depth > 12:
        return "[profondeur max]"
    if isinstance(data, dict):
        return {clean_text(str(k), 200): sanitize_structure(v, max_str, depth + 1) for k, v in list(data.items())[:500]}
    if isinstance(data, list):
        return [sanitize_structure(v, max_str, depth + 1) for v in data[:500]]
    if isinstance(data, str):
        return clean_text(data, max_str)
    return data
