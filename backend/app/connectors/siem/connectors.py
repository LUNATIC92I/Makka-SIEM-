"""Concrete SIEM connectors.

Maturity (honest status): every connector below is implemented against the
vendor's documented REST API and covered by tests using mocked HTTP responses.
None of them has been validated against a live tenant in this repository; the
UI therefore shows them as "implémenté, non validé sur instance réelle" until
a successful ``test_connection`` is recorded by the operator.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from app.connectors.http import SafeHttpClient
from app.connectors.siem.base import FetchResult, NormalizedEvent, SiemConnector, get_path, normalize_with_mapping
from app.connectors.siem.common import initial_cursor, max_timestamp
from app.connectors.siem.oauth import ClientCredentialsToken
from app.core.errors import AuthExpired, ConnectorError
from app.services.indicators import extract_from_text

# --------------------------------------------------------------------------- JSON folder


class JsonFolderConnector(SiemConnector):
    """Watches a local folder for ``*.json`` files (list of events, or ``{"events": [...]}``).

    Used for test environments and air-gapped imports. Cursor = processed file digests.
    """

    provider = "json_folder"
    display_name = "Import JSON (dossier surveillé)"
    description = "Lit les fichiers JSON déposés dans un dossier local. Idéal pour les tests."
    settings_schema = {"directory": "Chemin du dossier à surveiller", "source_system": "Nom de la source"}
    maturity = "implemented-tested"

    async def fetch(self, cursor: str | None, limit: int = 200) -> FetchResult:
        directory = Path(self.require("directory")).expanduser()
        if not directory.is_dir():
            raise ConnectorError("Dossier introuvable")
        seen: dict[str, str] = json.loads(cursor) if cursor else {}
        events: list[NormalizedEvent] = []
        warnings: list[str] = []
        for path in sorted(directory.glob("*.json")):
            if path.stat().st_size > 50 * 1024 * 1024:
                warnings.append(f"{path.name}: fichier trop volumineux, ignoré")
                continue
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if seen.get(path.name) == digest:
                continue
            try:
                events.extend(parse_event_document(json.loads(data), self.source_system))
            except (ValueError, ConnectorError) as exc:
                warnings.append(f"{path.name}: {exc}")
            seen[path.name] = digest
        return FetchResult(events=events, next_cursor=json.dumps(seen), warnings=warnings)


def parse_event_document(doc: Any, source_system: str, *, is_synthetic: bool = False,
                         mapping: dict | None = None) -> list[NormalizedEvent]:
    if isinstance(doc, dict) and isinstance(doc.get("events"), list):
        is_synthetic = is_synthetic or bool(doc.get("synthetic"))
        source_system = doc.get("source_system") or source_system
        items = doc["events"]
    elif isinstance(doc, list):
        items = doc
    elif isinstance(doc, dict):
        items = [doc]
    else:
        raise ConnectorError("Format JSON non reconnu (attendu: objet, liste ou {\"events\": [...]})")
    if len(items) > 10_000:
        raise ConnectorError("Trop d'événements dans un seul document (max 10 000)")
    return [
        normalize_with_mapping(item, item.get("source_system") or source_system, mapping, is_synthetic=is_synthetic)
        for item in items if isinstance(item, dict)
    ]


# --------------------------------------------------------------------------- Generic REST


class GenericRestConnector(SiemConnector):
    provider = "generic_rest"
    display_name = "API REST générique"
    description = "Interroge une API REST documentée renvoyant des événements JSON."
    settings_schema = {
        "url": "URL de l'API (HTTPS)",
        "items_path": "Chemin JSON de la liste d'événements (ex: data.items)",
        "since_param": "Nom du paramètre de requête 'depuis' (ex: since)",
        "time_field": "Champ horodatage des événements (curseur)",
        "auth_type": "bearer | header | basic | none",
        "auth_header": "Nom de l'en-tête si auth_type=header",
        "field_mapping": "Correspondance des champs (JSON)",
    }
    secret_fields = ["token", "username", "password"]

    def _auth(self) -> tuple[dict[str, str], Any]:
        kind = self.setting("auth_type", "bearer")
        if kind == "bearer":
            return {"Authorization": f"Bearer {self.require('token', secret=True)}"}, None
        if kind == "header":
            return {self.setting("auth_header", "X-API-Key"): self.require("token", secret=True)}, None
        if kind == "basic":
            return {}, (self.require("username", secret=True), self.require("password", secret=True))
        return {}, None

    async def fetch(self, cursor: str | None, limit: int = 200) -> FetchResult:
        cursor = cursor or initial_cursor(self.ctx.settings)
        headers, auth = self._auth()
        params = {self.setting("since_param", "since"): cursor, self.setting("limit_param", "limit"): limit}
        kwargs: dict[str, Any] = {"headers": {**headers, "Accept": "application/json"}, "params": params}
        if auth:
            kwargs["auth"] = auth
        data, _ = await SafeHttpClient().get_json(self.require("url"), **kwargs)
        items = get_path(data, self.setting("items_path", "")) if self.setting("items_path") else data
        if not isinstance(items, list):
            raise ConnectorError("La réponse ne contient pas de liste d'événements au chemin configuré")
        events = [self.normalize(i) for i in items[:limit] if isinstance(i, dict)]
        time_field = self.setting("time_field", "timestamp")
        nxt = max_timestamp(cursor, [get_path(i, time_field) for i in items if isinstance(i, dict)])
        return FetchResult(events=events, next_cursor=nxt, has_more=len(items) >= limit)


# --------------------------------------------------------------------------- Microsoft Sentinel


class SentinelConnector(SiemConnector):
    """Microsoft Sentinel via the Log Analytics query API (``SecurityAlert`` / ``SecurityIncident``)."""

    provider = "sentinel"
    display_name = "Microsoft Sentinel"
    description = "Requête KQL sur l'espace Log Analytics (API Azure Monitor) via une application Entra ID."
    settings_schema = {
        "tenant_id": "ID du locataire Entra ID",
        "client_id": "ID d'application (client)",
        "workspace_id": "ID de l'espace de travail Log Analytics",
        "table": "SecurityAlert (défaut) ou SecurityIncident",
        "kql_filter": "Filtre KQL additionnel (optionnel)",
    }
    secret_fields = ["client_secret"]
    API = "https://api.loganalytics.io"

    def __init__(self, ctx):  # noqa: ANN001
        super().__init__(ctx)
        self._token: ClientCredentialsToken | None = None

    def _token_provider(self) -> ClientCredentialsToken:
        if self._token is None:
            self._token = ClientCredentialsToken(
                self.require("tenant_id"), self.require("client_id"),
                self.require("client_secret", secret=True), f"{self.API}/.default",
            )
        return self._token

    def build_query(self, cursor: str, limit: int) -> str:
        table = self.setting("table", "SecurityAlert")
        if table not in ("SecurityAlert", "SecurityIncident"):
            raise ConnectorError("Table Sentinel non supportée")
        extra = self.setting("kql_filter", "")
        if any(tok in extra for tok in ("|", ";", "\n")):
            raise ConnectorError("Le filtre KQL ne doit contenir qu'une condition 'where' (sans | ni ;)")
        where_extra = f" and ({extra})" if extra else ""
        # cursor is an ISO timestamp produced by MAKKADi itself (validated by parse in max_timestamp)
        return (
            f"{table} | where TimeGenerated >= datetime({cursor}){where_extra} "
            f"| order by TimeGenerated asc | take {int(limit)}"
        )

    async def fetch(self, cursor: str | None, limit: int = 200) -> FetchResult:
        cursor = cursor or initial_cursor(self.ctx.settings)
        http = SafeHttpClient()
        url = f"{self.API}/v1/workspaces/{self.require('workspace_id')}/query"
        body = {"query": self.build_query(cursor, limit)}
        for attempt in range(2):
            token = await self._token_provider().get(http)
            try:
                data, _ = await http.post_json(url, json=body, headers={"Authorization": f"Bearer {token}"})
                break
            except AuthExpired:
                self._token_provider().invalidate()
                if attempt:
                    raise
        rows = _log_analytics_rows(data)
        events = [self._normalize_alert(r) for r in rows]
        nxt = max_timestamp(cursor, [r.get("TimeGenerated") for r in rows])
        return FetchResult(events=events, next_cursor=nxt, has_more=len(rows) >= limit)

    def _normalize_alert(self, row: dict[str, Any]) -> NormalizedEvent:
        mapping = {
            "original_id": ["SystemAlertId", "IncidentName", "AlertLink"],
            "event_time": ["TimeGenerated", "StartTime"],
            "title": ["AlertName", "Title", "DisplayName"],
            "event_type": ["AlertType", "Tactics", "ProductName"],
            "severity": ["AlertSeverity", "Severity"],
            "hostname": ["CompromisedEntity"],
            **(self.ctx.settings.get("field_mapping") or {}),
        }
        event = normalize_with_mapping(row, self.source_system, mapping)
        if not event.src_ip:
            entities = row.get("Entities")
            text = entities if isinstance(entities, str) else json.dumps(entities or "")
            ips = [i for i in extract_from_text(text, "Entities") if i.type in ("ipv4", "ipv6")]
            if ips:
                event.src_ip = ips[0].value
                event.context["entity_ips"] = [i.value for i in ips]
        return event


def _log_analytics_rows(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not data.get("tables"):
        return []
    table = data["tables"][0]
    cols = [c["name"] for c in table.get("columns", [])]
    return [dict(zip(cols, row, strict=False)) for row in table.get("rows", [])]


# --------------------------------------------------------------------------- Splunk ES


class SplunkConnector(SiemConnector):
    """Splunk Enterprise Security: notable events via ``/services/search/jobs/export``."""

    provider = "splunk"
    display_name = "Splunk Enterprise Security"
    description = "Recherche SPL exportée (événements 'notable') via l'API REST de Splunk."
    settings_schema = {
        "base_url": "URL de l'API de gestion (https://splunk:8089)",
        "search": "Recherche SPL (défaut: search `notable`)",
    }
    secret_fields = ["token"]

    async def fetch(self, cursor: str | None, limit: int = 200) -> FetchResult:
        from app.core.timeutil import parse_timestamp

        cursor = cursor or initial_cursor(self.ctx.settings)
        ts = parse_timestamp(cursor)
        earliest = int(ts.timestamp()) if ts else 0
        search = self.setting("search", "search `notable`")
        if not search.lstrip().startswith(("search", "|")):
            search = "search " + search
        spl = f"{search} earliest={earliest} | sort 0 _time | head {int(limit)}"
        url = self.require("base_url").rstrip("/") + "/services/search/jobs/export"
        resp = await SafeHttpClient().request(
            "POST", url,
            data={"search": spl, "output_mode": "json"},
            headers={"Authorization": f"Bearer {self.require('token', secret=True)}"},
        )
        if resp.status_code >= 400:
            raise ConnectorError(f"Splunk a refusé la recherche (HTTP {resp.status_code})")
        results: list[dict[str, Any]] = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj.get("result"), dict):
                results.append(obj["result"])
        mapping = {
            "original_id": ["event_id", "_cd", "orig_sid"],
            "event_time": ["_time"],
            "title": ["rule_name", "search_name", "rule_title"],
            "severity": ["urgency", "severity"],
            "src_ip": ["src", "src_ip"],
            "dst_ip": ["dest", "dest_ip"],
            "hostname": ["dest_host", "dest", "host"],
            "attempt_count": ["count"],
            **(self.ctx.settings.get("field_mapping") or {}),
        }
        events = [normalize_with_mapping(r, self.source_system, mapping) for r in results]
        nxt = max_timestamp(cursor, [r.get("_time") for r in results])
        return FetchResult(events=events, next_cursor=nxt, has_more=len(results) >= limit)


# --------------------------------------------------------------------------- Elastic / Wazuh


class ElasticConnector(SiemConnector):
    """Elastic Security alerts index (``.alerts-security.alerts-default``) via ``_search``."""

    provider = "elastic"
    display_name = "Elastic Security"
    description = "Lecture de l'index d'alertes Elastic Security via l'API _search (clé API)."
    settings_schema = {"base_url": "URL Elasticsearch", "index": "Index des alertes"}
    secret_fields = ["api_key", "username", "password"]
    default_index = ".alerts-security.alerts-default"
    time_field = "@timestamp"
    default_mapping: dict[str, list[str]] = {
        "original_id": ["kibana.alert.uuid", "_id"],
        "event_time": ["@timestamp"],
        "title": ["kibana.alert.rule.name", "message"],
        "event_type": ["kibana.alert.rule.category", "event.category", "event.action"],
        "severity": ["kibana.alert.severity", "event.severity"],
        "src_ip": ["source.ip"],
        "dst_ip": ["destination.ip"],
        "hostname": ["host.name"],
    }

    def _auth_kwargs(self) -> dict[str, Any]:
        api_key = self.ctx.secrets.get("api_key")
        if api_key:
            return {"headers": {"Authorization": f"ApiKey {api_key}"}}
        return {"auth": (self.require("username", secret=True), self.require("password", secret=True))}

    async def fetch(self, cursor: str | None, limit: int = 200) -> FetchResult:
        cursor = cursor or initial_cursor(self.ctx.settings)
        index = self.setting("index", self.default_index)
        if any(c in index for c in "/?#") or ".." in index:
            raise ConnectorError("Nom d'index invalide")
        url = f"{self.require('base_url').rstrip('/')}/{index}/_search"
        query = {
            "size": int(limit),
            "sort": [{self.time_field: "asc"}],
            "query": {"range": {self.time_field: {"gte": cursor}}},
        }
        kwargs = self._auth_kwargs()
        kwargs.setdefault("headers", {})["Content-Type"] = "application/json"
        data, _ = await SafeHttpClient().post_json(url, json=query, **kwargs)
        hits = (data or {}).get("hits", {}).get("hits", []) if isinstance(data, dict) else []
        mapping = {**self.default_mapping, **(self.ctx.settings.get("field_mapping") or {})}
        events = []
        stamps = []
        for h in hits:
            src = dict(h.get("_source") or {})
            src.setdefault("_id", h.get("_id"))
            events.append(normalize_with_mapping(src, self.source_system, mapping))
            stamps.append(get_path(src, self.time_field))
        return FetchResult(events=events, next_cursor=max_timestamp(cursor, stamps), has_more=len(hits) >= limit)


class WazuhConnector(ElasticConnector):
    """Wazuh alerts through the Wazuh indexer (OpenSearch API, ``wazuh-alerts-*``)."""

    provider = "wazuh"
    display_name = "Wazuh"
    description = "Lecture des alertes 'wazuh-alerts-*' via l'API de l'indexeur Wazuh (OpenSearch)."
    settings_schema = {"base_url": "URL de l'indexeur Wazuh (https://wazuh-indexer:9200)", "index": "wazuh-alerts-*"}
    default_index = "wazuh-alerts-*"
    time_field = "timestamp"
    default_mapping = {
        "original_id": ["id", "_id"],
        "event_time": ["timestamp"],
        "title": ["rule.description"],
        "event_type": ["rule.groups"],
        "severity": ["rule.level"],
        "src_ip": ["data.srcip", "data.src_ip"],
        "dst_ip": ["data.dstip", "agent.ip"],
        "src_port": ["data.srcport"],
        "dst_port": ["data.dstport"],
        "hostname": ["agent.name"],
        "attempt_count": ["rule.firedtimes"],
    }


# --------------------------------------------------------------------------- Defender XDR


class DefenderConnector(SiemConnector):
    """Microsoft Defender XDR alerts via Microsoft Graph ``/security/alerts_v2``.

    Requires an Entra ID application with the ``SecurityAlert.Read.All`` application permission.
    """

    provider = "defender"
    display_name = "Microsoft Defender XDR"
    description = "Alertes Defender XDR via Microsoft Graph (security/alerts_v2)."
    settings_schema = {"tenant_id": "ID du locataire", "client_id": "ID d'application (client)"}
    secret_fields = ["client_secret"]
    GRAPH = "https://graph.microsoft.com"

    def __init__(self, ctx):  # noqa: ANN001
        super().__init__(ctx)
        self._token: ClientCredentialsToken | None = None

    async def fetch(self, cursor: str | None, limit: int = 200) -> FetchResult:
        cursor = cursor or initial_cursor(self.ctx.settings)
        if self._token is None:
            self._token = ClientCredentialsToken(
                self.require("tenant_id"), self.require("client_id"),
                self.require("client_secret", secret=True), f"{self.GRAPH}/.default",
            )
        http = SafeHttpClient()
        params = {
            "$filter": f"createdDateTime ge {cursor}",
            "$orderby": "createdDateTime asc",
            "$top": str(min(int(limit), 2000)),
        }
        url = f"{self.GRAPH}/v1.0/security/alerts_v2"
        for attempt in range(2):
            token = await self._token.get(http)
            try:
                data, _ = await http.get_json(url, params=params, headers={"Authorization": f"Bearer {token}"})
                break
            except AuthExpired:
                self._token.invalidate()
                if attempt:
                    raise
        alerts = (data or {}).get("value", []) if isinstance(data, dict) else []
        events = [self._normalize(a) for a in alerts]
        nxt = max_timestamp(cursor, [a.get("createdDateTime") for a in alerts])
        return FetchResult(events=events, next_cursor=nxt, has_more=bool((data or {}).get("@odata.nextLink")))

    def _normalize(self, alert: dict[str, Any]) -> NormalizedEvent:
        mapping = {
            "original_id": ["id"],
            "event_time": ["createdDateTime"],
            "title": ["title"],
            "event_type": ["category"],
            "severity": ["severity"],
            **(self.ctx.settings.get("field_mapping") or {}),
        }
        event = normalize_with_mapping(alert, self.source_system, mapping)
        ips, hosts = [], []
        for ev in alert.get("evidence") or []:
            kind = str(ev.get("@odata.type", ""))
            if kind.endswith("ipEvidence") and ev.get("ipAddress"):
                ips.append(ev["ipAddress"])
            if kind.endswith("deviceEvidence") and ev.get("deviceDnsName"):
                hosts.append(ev["deviceDnsName"])
        if ips and not event.src_ip:
            event.src_ip = ips[0]
            event.context["evidence_ips"] = ips
        if hosts and not event.hostname:
            event.hostname = hosts[0]
        return event


SIEM_CONNECTORS: dict[str, type[SiemConnector]] = {
    c.provider: c
    for c in (JsonFolderConnector, GenericRestConnector, SentinelConnector, SplunkConnector,
              ElasticConnector, WazuhConnector, DefenderConnector)
}
