"""OAuth2 client-credentials token cache (Microsoft Entra ID)."""

from __future__ import annotations

import time

from app.connectors.http import SafeHttpClient
from app.core.errors import ConnectorError


class ClientCredentialsToken:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, scope: str,
                 authority: str = "https://login.microsoftonline.com"):
        self.url = f"{authority.rstrip('/')}/{tenant_id}/oauth2/v2.0/token"
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self._token: str | None = None
        self._expires_at = 0.0

    def invalidate(self) -> None:
        self._token = None
        self._expires_at = 0.0

    async def get(self, http: SafeHttpClient) -> str:
        if self._token and time.time() < self._expires_at - 60:
            return self._token
        data, _ = await http.post_json(
            self.url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": self.scope,
            },
        )
        if not isinstance(data, dict) or "access_token" not in data:
            raise ConnectorError("Échec d'obtention du jeton OAuth (réponse inattendue)")
        self._token = data["access_token"]
        self._expires_at = time.time() + float(data.get("expires_in", 3600))
        return self._token
