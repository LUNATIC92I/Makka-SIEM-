"""Outbound HTTP client shared by every connector.

* SSRF validation of every URL (and every redirect hop);
* bounded response size;
* retries with exponential backoff on network errors / 5xx / 429 (``Retry-After`` honoured);
* errors converted to ``ConnectorError`` without leaking secrets.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any
from urllib.parse import urljoin

import httpx

from app.core.config import get_settings
from app.core.errors import AuthExpired, ConnectorError, OutboundBlocked, RateLimited
from app.security.ssrf import validate_outbound_url

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
USER_AGENT = "MAKKADi-OSINT/0.1 (+SOC investigation tool)"

_transport_override: httpx.AsyncBaseTransport | None = None


def set_transport(transport: httpx.AsyncBaseTransport | None) -> None:
    """Inject a transport (``httpx.MockTransport`` in tests)."""
    global _transport_override
    _transport_override = transport


class SafeHttpClient:
    def __init__(self, *, timeout: float | None = None, max_retries: int = 2, backoff_base: float = 0.5):
        self.timeout = timeout or get_settings().http_timeout_seconds
        self.max_retries = max_retries
        self.backoff_base = backoff_base

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            transport=_transport_override,
            headers={"User-Agent": USER_AGENT},
            trust_env=True,
        )

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        attempt = 0
        while True:
            try:
                return await self._request_once(method, url, **kwargs)
            except RateLimited as exc:
                if attempt >= self.max_retries:
                    raise
                delay = exc.retry_after if exc.retry_after is not None else self._backoff(attempt)
                if delay > 30:
                    raise
            except ConnectorError as exc:
                if not exc.retryable or isinstance(exc, AuthExpired) or attempt >= self.max_retries:
                    raise
                delay = self._backoff(attempt)
            attempt += 1
            await asyncio.sleep(delay)

    def _backoff(self, attempt: int) -> float:
        return self.backoff_base * (2**attempt) + random.uniform(0, self.backoff_base)  # noqa: S311

    async def _request_once(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        current = url
        async with self._client() as client:
            for _hop in range(4):
                validate_outbound_url(current)
                try:
                    async with client.stream(method, current, **kwargs) as resp:
                        body = bytearray()
                        async for chunk in resp.aiter_bytes():
                            body.extend(chunk)
                            if len(body) > MAX_RESPONSE_BYTES:
                                raise ConnectorError("Réponse trop volumineuse")
                        # aiter_bytes() already decoded the body: drop encoding headers before rebuilding.
                        headers = [(k, v) for k, v in resp.headers.multi_items()
                                   if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")]
                        response = httpx.Response(
                            resp.status_code, headers=headers, content=bytes(body), request=resp.request
                        )
                except httpx.TimeoutException as exc:
                    raise ConnectorError("Délai d'attente dépassé", retryable=True) from exc
                except httpx.TransportError as exc:
                    raise ConnectorError(f"Erreur réseau: {type(exc).__name__}", retryable=True) from exc
                if response.is_redirect and "location" in response.headers:
                    current = urljoin(current, response.headers["location"])
                    method = "GET" if response.status_code in (301, 302, 303) else method
                    if method == "GET":
                        kwargs.pop("json", None)
                        kwargs.pop("data", None)
                    continue
                return self._check(response)
        raise ConnectorError("Trop de redirections")

    @staticmethod
    def _check(response: httpx.Response) -> httpx.Response:
        code = response.status_code
        if code == 429:
            retry_after = response.headers.get("retry-after")
            try:
                ra = float(retry_after) if retry_after else None
            except ValueError:
                ra = None
            raise RateLimited(retry_after=ra)
        if code == 401:
            raise AuthExpired("Authentification refusée par la source (HTTP 401)")
        if code == 403:
            raise ConnectorError("Accès refusé par la source (HTTP 403)", status_code=code)
        if code >= 500:
            raise ConnectorError(f"Erreur serveur de la source (HTTP {code})", retryable=True, status_code=code)
        return response

    async def get_json(self, url: str, **kwargs: Any) -> tuple[Any, httpx.Response]:
        resp = await self.request("GET", url, **kwargs)
        return _json(resp), resp

    async def post_json(self, url: str, **kwargs: Any) -> tuple[Any, httpx.Response]:
        resp = await self.request("POST", url, **kwargs)
        return _json(resp), resp


def _json(resp: httpx.Response) -> Any:
    if resp.status_code == 404:
        return None
    if resp.status_code >= 400:
        raise ConnectorError(f"Requête refusée (HTTP {resp.status_code})", status_code=resp.status_code)
    try:
        return resp.json()
    except ValueError as exc:
        raise ConnectorError("Réponse JSON invalide") from exc


__all__ = ["SafeHttpClient", "set_transport", "OutboundBlocked"]
