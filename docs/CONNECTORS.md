# Connecteurs

Statuts de maturité (affichés tels quels dans l'interface) :

* **Implémenté et testé** — testé de bout en bout dans ce dépôt.
* **Implémenté — testé sur réponses simulées, non validé sur instance réelle** — code conforme à l'API documentée par
  l'éditeur, tests automatisés avec des réponses HTTP simulées ; aucun accès à une instance réelle n'était disponible.
* **Validé en direct** (dans [TEST_RESULTS.md](TEST_RESULTS.md)) — la source a effectivement été interrogée.

Un connecteur n'apparaît **« opérationnel »** que si son dernier test ou sa dernière collecte a réussi.

## SIEM

| Connecteur | API utilisée | Authentification | Curseur | Maturité |
|---|---|---|---|---|
| Import JSON (dossier surveillé) | fichiers `*.json` locaux | — | empreintes des fichiers traités | implémenté et testé |
| Import JSON (téléversement) | `POST /api/v1/ingest/file` | session analyste | — | implémenté et testé |
| Webhook | `POST /api/v1/ingest/webhook/{nom}` | HMAC-SHA256 + horodatage (anti-rejeu 300 s) | — | implémenté et testé |
| API REST générique | `GET <url>?since=…&limit=…` | bearer / en-tête / basic / aucune | champ horodatage configurable | simulé |
| Microsoft Sentinel | Log Analytics `POST /v1/workspaces/{id}/query` (KQL sur `SecurityAlert` ou `SecurityIncident`) | Entra ID client credentials (`https://api.loganalytics.io/.default`), rafraîchissement sur 401 | `TimeGenerated` | simulé |
| Splunk Enterprise Security | `POST /services/search/jobs/export` (`output_mode=json`, recherche `notable`) | jeton bearer | `_time` | simulé |
| Elastic Security | `POST /{index}/_search` (`.alerts-security.alerts-default`) | clé API (`ApiKey`) ou basic | `@timestamp` | simulé |
| Wazuh | indexeur OpenSearch `POST /wazuh-alerts-*/_search` | basic ou clé | `timestamp` | simulé |
| Microsoft Defender XDR | Graph `GET /v1.0/security/alerts_v2` (permission `SecurityAlert.Read.All`) | Entra ID client credentials, rafraîchissement sur 401 | `createdDateTime` | simulé |

### Comportement commun

* Collecte planifiée selon `poll_interval_seconds` (≥ 30 s) ; « Collecter maintenant » depuis l'interface.
* **Déduplication** : contrainte unique `(source_system, original_id)` ; identifiant d'origine conservé. Sans
  identifiant fourni, un identifiant déterministe `sha256:` est dérivé du contenu brut.
* **Reprise** : le curseur n'est avancé qu'après persistance des événements dans la même transaction ; les curseurs
  sont inclusifs (`>=`) et la déduplication absorbe les doublons. En cas d'erreur, le curseur reste inchangé et
  l'erreur est visible (statut du connecteur + file de tâches, nouvelle tentative avec temporisation).
* Erreurs : 401 → rafraîchissement du jeton puis échec explicite ; 429 → `Retry-After` ; 5xx/réseau → retries
  exponentiels ; 403 → échec non relancé.
* **Correspondance des champs** : `field_mapping` (JSON) surcharge les chemins par défaut (notation pointée,
  clés ECS aplaties acceptées), `severity_scale` = `level15` | `percent` | `ten`, `context_fields` = champs à
  conserver dans le contexte.
* Requêtes sortantes soumises au **garde SSRF** : un SIEM sur réseau interne doit être explicitement autorisé via
  `MAKKADI_OUTBOUND_ALLOWED_HOSTS` / `MAKKADI_OUTBOUND_ALLOWED_CIDRS`.
* Le filtre KQL additionnel de Sentinel n'accepte qu'une condition (`|`, `;` et retours à la ligne refusés).

### Format d'événement JSON accepté

```json
{
  "source_system": "mon-siem",
  "events": [{
    "id": "ALERT-1", "timestamp": "2026-10-25T22:14:35Z", "title": "Connexions suspectes répétées",
    "event_type": "authentication_failure_burst", "severity": "high",
    "src_ip": "154.73.112.25", "dst_ip": "10.20.30.40", "dst_port": 22, "protocol": "tcp",
    "hostname": "srv-web-01", "attempt_count": 48
  }]
}
```

Une liste d'événements ou un objet seul sont aussi acceptés. Les adresses, domaines, URL et empreintes présents
dans le titre, le contexte ou le contenu brut sont extraits automatiquement (formes « défangées » comprises).

### Signature des webhooks

```
X-Makkadi-Timestamp: <epoch secondes>
X-Makkadi-Signature: sha256=HMAC_SHA256(secret, "<timestamp>.<corps brut>")
```

Le secret partagé est le secret `webhook_secret` du connecteur SIEM (activé).

## OSINT / Threat Intelligence

Chaque source est un module indépendant (`backend/app/connectors/osint/`). Toutes sont **désactivées par défaut** :
activer une source revient à lui transmettre les indicateurs publics investigués. Les adresses privées, réservées,
de documentation, CGNAT, etc. ne sont **jamais** envoyées à l'extérieur.

| Source | Catégorie | Types | Clé | Groupe d'amont | Fiabilité | Maturité |
|---|---|---|---|---|---|---|
| RDAP (rdap.org → RIR/registre) | réseau | IP, domaine | non | rir-registry | 0,85 | **validé en direct** |
| RIPEstat | réseau / BGP | IP | non | bgp-routing | 0,85 | **validé en direct** |
| Shodan InternetDB | services (passif) | IPv4 | non | shodan-scans | 0,70 | **validé en direct** |
| GreyNoise Community | réputation | IPv4 | optionnelle | greynoise-sensors | 0,75 | interrogé en direct (réponse « non observé » pour l'IP de test) |
| DNS (résolveur) | infrastructure | domaine, IP (PTR) | non | dns-live | 0,90 | interrogé en direct (pas de PTR pour l'IP de test) |
| crt.sh | infrastructure (CT) | domaine | non | ct-logs | 0,80 | simulé |
| ipinfo.io | géolocalisation | IP | jeton optionnel | geo-ipinfo | 0,60 | simulé |
| MaxMind GeoLite2 | géolocalisation (hors ligne) | IP | base `.mmdb` | geo-maxmind | 0,60 | non testé (base sous licence absente) |
| VirusTotal v3 | réputation | IP, domaine, URL, empreintes | oui | virustotal-aggregate | 0,75 | simulé |
| AbuseIPDB v2 | réputation | IP | oui | abuseipdb | 0,65 | simulé |
| AlienVault OTX | renseignement | tous | oui | otx-community | 0,45 | simulé |
| URLhaus (abuse.ch) | réputation | IPv4, domaine, URL, md5, sha256 | oui (Auth-Key) | abusech | 0,80 | simulé |
| MISP | renseignement | tous | oui | misp | 0,70 | simulé |
| STIX/TAXII 2.1 | renseignement | tous | selon serveur | taxii | 0,70 | simulé |
| Listes internes | réputation | tous | — | internal | 0,85 | implémenté et testé |

Pour chaque requête sont conservés : source, indicateur, statut (`ok`, `no_data`, `error`, `not_configured`,
`rate_limited`, `unsupported`), heure de consultation, date de la donnée si fournie, confiance déclarée par la
source, résultat brut assaini + SHA-256, URL de consultation, durée, erreurs. L'interface affiche
**« Donnée indisponible »** et la raison pour tout statut autre que `ok`.

Règles d'interprétation intégrées :

* VirusTotal sans détection → verdict `inconnu` (pas « bénin ») ;
* RDAP : seules les entités de type **organisation** sont conservées (les contacts individuels sont ignorés) ;
* relations DNS/certificats qualifiées **actuelles** ou **historiques** et jamais présentées comme preuve d'attaque ;
* TAXII 2.1 ne permettant pas de filtrer par valeur, la collection est mise en cache (bornée) et filtrée localement.

## Sources de démonstration

`demo_network`, `demo_geo_a`, `demo_geo_b`, `demo_reputation_a`, `demo_reputation_mirror`, `demo_reputation_b`,
`demo_infrastructure` — actives uniquement en mode démonstration, aucune requête réseau, valeurs dérivées d'un
hachage et volontairement non réalistes (ASN de documentation RFC 5398, codes pays XA/XB/ZZ, coordonnées en plein
océan, domaines `.example`). `demo_reputation_mirror` partage l'amont de `demo_reputation_a` pour démontrer que la
confiance ne compte pas deux fois la même donnée ; `demo_geo_a`/`demo_geo_b` se contredisent volontairement.

## Ajouter une source

1. Créer `backend/app/connectors/osint/<source>.py` avec une classe héritant d'`OsintProvider` (attributs `name`,
   `category`, `supported_types`, `upstream_group`, `reliability`, `requires_api_key`, méthode `_lookup`).
2. Utiliser `SafeHttpClient` (SSRF, retries, quotas) et retourner des `Findings` normalisés ; ne jamais lever
   d'exception non gérée (la méthode `lookup` encapsule les erreurs).
3. L'ajouter à `REAL_PROVIDERS` dans `registry.py`, écrire un test avec `httpx.MockTransport`.
