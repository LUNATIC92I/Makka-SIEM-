# Guide de configuration des API

Toutes les clés se saisissent dans *Connecteurs* (champs « secret »), sont chiffrées avec la clé maîtresse et ne
sont plus jamais réaffichées (valeur masquée ; laisser le masque pour conserver, vider pour supprimer). Après
configuration : **Tester la connexion** (un test réussi marque le connecteur « opérationnel »).

> Respectez les conditions d'utilisation de chaque fournisseur (usage commercial, quotas, redistribution). Les liens
> sont accessibles depuis la fiche du connecteur.

## Sources OSINT

| Source | Obtenir l'accès | Champ(s) | Quota indicatif (à vérifier) |
|---|---|---|---|
| RDAP | aucun | — | raisonnable (registres RIR) |
| RIPEstat | aucun | — | usage raisonnable, `sourceapp=makkadi` envoyé |
| Shodan InternetDB | aucun | — | usage non commercial |
| GreyNoise Community | compte gratuit (facultatif) | `api_key` | limité par jour |
| crt.sh | aucun | — | service communautaire, lent sous charge |
| DNS | aucun | `nameservers` (optionnel) | — |
| ipinfo.io | compte (facultatif) | `token` | offre gratuite limitée |
| MaxMind GeoLite2 | compte MaxMind + licence, télécharger `GeoLite2-City.mmdb` / `GeoLite2-ASN.mmdb` | `city_db_path`, `asn_db_path` | hors ligne |
| VirusTotal | compte VirusTotal → API key | `api_key`, `malicious_threshold` (défaut 3) | API publique : 4 req/min, 500/jour |
| AbuseIPDB | compte → API | `api_key`, `max_age_days` (défaut 90) | offre gratuite : 1 000 vérifications/jour |
| AlienVault OTX | compte OTX → API key | `api_key` | — |
| URLhaus | compte abuse.ch (Auth-Key) | `api_key` | — |
| MISP | clé d'API utilisateur MISP (instance autorisée) | `base_url`, `api_key` | selon instance |
| TAXII 2.1 | accès au serveur (API root + collection) | `api_root`, `collection_id`, `cache_minutes`, `token` ou `username`/`password` | selon fournisseur |
| Listes internes | fichier CSV/JSON (`type,value,verdict,comment`) | `file_path` ou `entries` | — |

## SIEM

### Microsoft Sentinel

1. Entra ID → *Inscriptions d'applications* → nouvelle application ; créer un secret client.
2. Sur l'espace Log Analytics : rôle **Log Analytics Reader** pour l'application.
3. Connecteur : `tenant_id`, `client_id`, `workspace_id`, `table` (`SecurityAlert` ou `SecurityIncident`),
   `kql_filter` optionnel (une condition), secret `client_secret`.

### Microsoft Defender XDR

Application Entra ID avec la permission d'application Microsoft Graph **SecurityAlert.Read.All** (consentement
administrateur). Connecteur : `tenant_id`, `client_id`, secret `client_secret`.

### Splunk Enterprise Security

Jeton d'authentification Splunk (*Settings → Tokens*) avec un rôle autorisé à rechercher les événements notables.
Connecteur : `base_url` (`https://splunk:8089`), `search` (défaut ``search `notable` ``), secret `token`.

### Elastic Security

Clé d'API avec lecture sur `.alerts-security.alerts-*`. Connecteur : `base_url`, `index`, secret `api_key`
(ou `username`/`password`).

### Wazuh

Compte de l'indexeur Wazuh en lecture sur `wazuh-alerts-*`. Connecteur : `base_url` (`https://indexer:9200`),
secrets `username`/`password`.

### API REST générique

`url`, `items_path` (chemin de la liste), `since_param`, `limit_param`, `time_field`, `auth_type`
(`bearer|header|basic|none`), `auth_header`, `field_mapping` (JSON), secrets `token` / `username` / `password`.

Paramètres communs : `source_system` (nom affiché), `initial_lookback_minutes` (défaut 60), `field_mapping`,
`severity_scale`, `context_fields`, fréquence de collecte. Pour un SIEM sur réseau interne, autoriser l'hôte dans
`MAKKADI_OUTBOUND_ALLOWED_HOSTS`.

## Fournisseur d'IA

| Fournisseur | Configuration |
|---|---|
| Moteur déterministe (défaut) | aucune ; local, sans LLM |
| Anthropic Claude | clé API Anthropic ; modèle par défaut `claude-opus-5-5` ; requête via le SDK officiel avec sortie JSON contrainte par schéma, réflexion adaptative et repli serveur en cas de refus (`fallbacks`) ; cocher la validation de la politique de traitement |
| Compatible OpenAI | `base_url` (ex. `http://127.0.0.1:11434/v1` pour Ollama) et `model` ; une URL locale (boucle) ne nécessite pas de validation d'envoi externe |

L'envoi vers un fournisseur non local est bloqué tant que la case « politique de traitement validée » n'est pas
cochée (ou `MAKKADI_AI_EXTERNAL_PROCESSING_ALLOWED=true`). La pseudonymisation des hôtes et IP internes est activée
par défaut.
