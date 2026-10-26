"""AI provider abstraction.

* ``deterministic``, local rule-based analyst (no LLM, no data leaves the machine);
* ``anthropic``, Claude via the official Anthropic SDK (structured JSON output);
* ``openai_compatible``, any OpenAI-compatible chat endpoint (local Ollama, vLLM,
  LM Studio, or a hosted service).

No provider receives tools: the model can only return a JSON document, which is
then validated (``app.ai.validation``). It cannot trigger any action.
"""

from __future__ import annotations

import ipaddress
import json
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.ai.prompts import SYSTEM_PROMPT, user_message
from app.ai.schemas import strict_json_schema
from app.core.errors import ConnectorError
from app.security.ssrf import validate_outbound_url


@dataclass
class AIConfig:
    provider: str
    model: str | None = None
    base_url: str | None = None
    api_key: str | None = None
    external_processing_allowed: bool = False
    pseudonymize: bool = True
    timeout: float = 120.0


def safe_json(package: dict[str, Any]) -> str:
    """Serialise untrusted data so it cannot close the data delimiter."""
    return json.dumps(package, ensure_ascii=False, default=str).replace("<", "\\u003c").replace(">", "\\u003e")


def is_local_endpoint(url: str | None) -> bool:
    if not url:
        return False
    host = (urlsplit(url).hostname or "").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class AIProvider(ABC):
    name: str
    external: bool = True

    def __init__(self, cfg: AIConfig):
        self.cfg = cfg

    @property
    def model(self) -> str | None:
        return self.cfg.model

    @abstractmethod
    async def analyze(self, package: dict[str, Any]) -> dict[str, Any]: ...


class AnthropicProvider(AIProvider):
    name = "anthropic"
    DEFAULT_MODEL = "claude-opus-5-5"

    @property
    def model(self) -> str:
        return self.cfg.model or self.DEFAULT_MODEL

    async def analyze(self, package: dict[str, Any]) -> dict[str, Any]:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ConnectorError("Le paquet 'anthropic' n'est pas installé") from exc
        if not self.cfg.api_key:
            raise ConnectorError("Clé API Anthropic non configurée")
        client = anthropic.AsyncAnthropic(api_key=self.cfg.api_key, timeout=self.cfg.timeout, max_retries=2)
        nonce = secrets.token_hex(8)
        try:
            response = await client.beta.messages.create(
                model=self.model,
                max_tokens=16000,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message(safe_json(package), nonce)}],
                thinking={"type": "adaptive"},
                output_config={"effort": "high", "format": {"type": "json_schema", "schema": strict_json_schema()}},
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except anthropic.RateLimitError as exc:
            raise ConnectorError("Limite de requêtes du fournisseur IA atteinte", retryable=True, status_code=429) from exc
        except anthropic.APIStatusError as exc:
            raise ConnectorError(f"Erreur du fournisseur IA (HTTP {exc.status_code})", status_code=exc.status_code) from exc
        except anthropic.APIConnectionError as exc:
            raise ConnectorError("Fournisseur IA injoignable", retryable=True) from exc
        if response.stop_reason == "refusal":
            raise ConnectorError("Le modèle a refusé la requête (stop_reason=refusal)")
        if response.stop_reason == "max_tokens":
            raise ConnectorError("Réponse IA tronquée (max_tokens)")
        text = next((b.text for b in response.content if getattr(b, "type", "") == "text"), "")
        try:
            return json.loads(text)
        except ValueError as exc:
            raise ConnectorError("Réponse IA non JSON") from exc


class OpenAICompatibleProvider(AIProvider):
    name = "openai_compatible"

    @property
    def external(self) -> bool:  # type: ignore[override]
        return not is_local_endpoint(self.cfg.base_url)

    async def analyze(self, package: dict[str, Any]) -> dict[str, Any]:
        base = (self.cfg.base_url or "").rstrip("/")
        if not base or not self.cfg.model:
            raise ConnectorError("URL de base et modèle requis pour le fournisseur compatible OpenAI")
        if not is_local_endpoint(base):
            validate_outbound_url(base)
        nonce = secrets.token_hex(8)
        schema_hint = json.dumps(strict_json_schema(), ensure_ascii=False)
        body = {
            "model": self.cfg.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT + "\n\nSchéma JSON attendu :\n" + schema_hint},
                {"role": "user", "content": user_message(safe_json(package), nonce)},
            ],
            "response_format": {"type": "json_object"},
        }
        headers = {"Authorization": f"Bearer {self.cfg.api_key}"} if self.cfg.api_key else {}
        try:
            async with httpx.AsyncClient(timeout=self.cfg.timeout, follow_redirects=False) as client:
                resp = await client.post(f"{base}/chat/completions", json=body, headers=headers)
        except httpx.HTTPError as exc:
            raise ConnectorError(f"Fournisseur IA injoignable ({type(exc).__name__})", retryable=True) from exc
        if resp.status_code >= 400:
            raise ConnectorError(f"Erreur du fournisseur IA (HTTP {resp.status_code})", status_code=resp.status_code)
        try:
            content = resp.json()["choices"][0]["message"]["content"]
            return json.loads(content)
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ConnectorError("Réponse IA non conforme") from exc


def build_provider(cfg: AIConfig) -> AIProvider:
    from app.ai.deterministic import DeterministicProvider

    if cfg.provider == "deterministic":
        return DeterministicProvider(cfg)
    if cfg.provider == "anthropic":
        return AnthropicProvider(cfg)
    if cfg.provider == "openai_compatible":
        return OpenAICompatibleProvider(cfg)
    raise ConnectorError(f"Fournisseur IA inconnu ou désactivé : {cfg.provider}")
