# Architecture et cahier des charges technique

## 1. Analyse de l'existant et de l'environnement

* Dépôt initial : vide (un `README.md`). Aucun code à conserver.
* Environnement de développement utilisé : conteneur Linux, Python 3.13, Node 22, Chromium/Playwright, accès réseau
  sortant via proxy. **Pas de Windows ni de Wine** : le `.exe` final se compile sous Windows (script PowerShell ou
  GitHub Actions `windows-latest`). Le spec PyInstaller et la configuration Electron ont été validés en construisant
  et en exécutant la variante Linux (voir [TEST_RESULTS.md](TEST_RESULTS.md)).
* Cible Python : ≥ 3.12 (CI en 3.12, développement vérifié en 3.13).

## 2. Vue d'ensemble

```
            ┌──────────────┐   poll (fréquence)   ┌──────────────────────────────────────────────┐
 SIEM ─────▶│ Connecteurs  │──────────────────────▶│ Ingestion : normalisation, déduplication,     │
 (Sentinel, │ SIEM         │   webhook HMAC        │ extraction/validation IOC, regroupement       │
 Splunk…)   └──────────────┘──────────────────────▶└──────────────┬───────────────────────────────┘
 Fichier JSON / démo ─────────────────────────────────────────────▶│ tâche run_investigation
                                                                   ▼
 ┌──────────────────── File de tâches persistante (DB, reprise, backoff) ─────────────────────────┐
 │  1. Enrichissement OSINT concurrent (sources activées, quotas, SSRF guard, « Donnée indisponible »)│
 │  2. Corrélation : relations qualifiées, faits attribués, concordances, contradictions, manques   │
 │  3. Scoring explicable : risque ≠ confiance, dépendance des sources                              │
 │  4. Analyse IA : paquet de preuves minimisé → fournisseur → validation stricte                   │
 └──────────────────────────────────────────────────────────────────────────────────────────────────┘
            │                                    │
            ▼                                    ▼
   API FastAPI (127.0.0.1, JWT, RBAC)     Rapports PDF/JSON (SHA-256) · Audit chaîné
            │
            ▼
   Console React (Electron ou navigateur)
```

### Choix techniques justifiés

| Besoin | Choix | Justification |
|---|---|---|
| API interne | FastAPI + Pydantic v2 | validation stricte des entrées, OpenAPI généré |
| Persistance | SQLAlchemy 2 + Alembic, SQLite WAL / PostgreSQL | monoposte sans serveur ; migration vers PostgreSQL par simple URL |
| Tâches asynchrones | **File persistante en base** (pas de Redis/Celery) | application de bureau mono-utilisateur : persistance, visibilité UI et reprise après crash sans infrastructure supplémentaire. Interface remplaçable pour un déploiement distribué |
| HTTP sortant | httpx + client « SafeHttpClient » | SSRF guard sur chaque saut, taille de réponse bornée, retries/backoff, `Retry-After` |
| Graphe | Cytoscape.js | navigation, styles par type, liens qualifiés |
| Carte | Leaflet + fond Natural Earth embarqué (world-atlas) | fonctionne hors ligne ; tuiles OSM optionnelles (fuite d'information évitée par défaut) |
| Graphiques | Recharts | maintenu, adapté aux tableaux de bord |
| Bureau | Electron + backend PyInstaller | un simple `.exe` Python ne fournit pas une application complète ; Electron apporte la fenêtre, l'installateur NSIS et le cycle de vie du serveur local |
| IA | abstraction de fournisseurs | moteur déterministe local par défaut ; Claude via SDK officiel ; endpoint compatible OpenAI pour modèle local |

## 3. Organisation du code

```
backend/
  app/
    api/            deps (auth, RBAC, contrôle d'accès) + routes/ (auth, users, investigations, events, intel, reports, connectors, operations)
    core/           config (MAKKADI_*), logging JSON UTC + rédaction des secrets, erreurs, temps UTC
    database/       base (UTCDateTime), session, migrations programmatiques
    models/         modèle SQLAlchemy
    schemas/        sérialisation API (aucun secret)
    security/       mots de passe, JWT, clés, coffre Fernet, SSRF, webhook HMAC, rate limiting, assainissement/injection
    connectors/
      http.py       client HTTP sortant sécurisé
      siem/         base (normalisation, mapping), connectors (JSON, REST, Sentinel, Splunk, Elastic, Wazuh, Defender), OAuth
      osint/        un module par source + demo.py (synthétique) + registry
    services/       indicateurs, ingestion, tâches, audit, paramètres, rétention, démo, contrôles actifs, bootstrap
    investigation/  pipeline (enrichissement → corrélation → scoring → IA), correlation
    scoring/        moteur de scoring explicable
    ai/             schémas de sortie, paquet de preuves, prompts, fournisseurs, validation, moteur déterministe, service
    reporting/      builder (provenance), PDF, service (SHA-256, vérification)
    main.py, run.py
  migrations/       Alembic (0001_initial_schema)
  tests/            pytest (unitaires, sécurité, migrations, bout en bout, live optionnels)
  makkadi-backend.spec   PyInstaller
frontend/src/       components, pages, services, hooks, types, maps, lib
desktop/            Electron (src/main.js, preload.js), build/ (icônes), configuration electron-builder
scripts/            build_windows.ps1, dev.sh, run_checks.sh
sample_data/        scénario de démonstration synthétique
docs/
```

## 4. Modèle de données

| Table | Clé | Rôle / contraintes principales |
|---|---|---|
| `roles` | id | nom unique, permissions (JSON) |
| `users` | id | username unique, hash bcrypt, rôle (FK RESTRICT), verrouillage, `token_version` (révocation) |
| `connector_configs` | id | `kind ∈ {siem, osint, ai}` (CHECK), nom unique, paramètres non secrets (JSON), **secrets chiffrés** (Fernet), état |
| `ingestion_checkpoints` | connector_id (FK CASCADE) | curseur de collecte, avancé seulement après persistance |
| `siem_events` | id | **UNIQUE (source_system, original_id)**, empreinte de contenu, brut assaini + SHA-256, index temps/IP |
| `investigations` | uuid | référence unique `INV-AAAA-NNNNNN`, statut, risque/confiance, scoring et corrélation (JSON), `restricted` |
| `investigation_events` | (investigation, event) | association N-N |
| `investigation_assignees` | (investigation, user) | accès aux investigations restreintes |
| `indicators` | id | **UNIQUE (type, value)**, portée (public/privé/réservé…), classification |
| `investigation_indicators` | (investigation, indicator, role) | rôle source/destination/observé, champ d'extraction, événement |
| `osint_sources` | name | registre : catégorie, groupe d'amont (dépendance), fiabilité, clé requise, conditions |
| `enrichment_results` | id | source, statut, `queried_at`, `data_updated_at`, résultats normalisés, brut + SHA-256, URL, erreurs, `is_synthetic` |
| `indicator_relations` | id | lien qualifié (type, source, date, temporalité, confiance, preuve FK) |
| `ai_analyses` | id | fournisseur, modèle, statut, sortie validée, problèmes de validation, injections détectées, SHA-256 de l'entrée, envoi externe |
| `reports` | id | type, format, fichier, SHA-256, taille |
| `investigation_notes` | id | notes, décisions, changements de statut de l'analyste |
| `tasks` | id | type, charge, statut, tentatives, prochaine exécution, `dedup_key`, erreurs |
| `audit_logs` | id | chaîne `prev_hash` → `entry_hash` (UNIQUE) |
| `app_settings` | key | pondérations, seuils, règles d'ingestion, actifs, rétention |

Toutes les dates sont stockées en UTC (`UTCDateTime`). Les clés étrangères sont actives sous SQLite (`PRAGMA
foreign_keys=ON`). Migrations : `alembic upgrade head` (appliquées automatiquement au démarrage) ; un test vérifie
que la migration correspond exactement au modèle et que `downgrade base` fonctionne.

## 5. Dépendances externes

* Sources sans clé : RDAP (rdap.org → RIR), RIPEstat, Shodan InternetDB, GreyNoise Community, crt.sh, DNS, ipinfo.io (jeton optionnel).
* Sources avec clé : VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus (Auth-Key abuse.ch), MISP, TAXII 2.1.
* Base locale : MaxMind GeoLite2 (`.mmdb`, licence MaxMind).
* SIEM : Microsoft Sentinel (Log Analytics API + Entra ID), Splunk ES (REST export), Elastic Security, Wazuh indexer, Microsoft Defender XDR (Graph `alerts_v2`), REST générique, dossier JSON.
* IA : SDK `anthropic` (optionnel), tout endpoint `/chat/completions` compatible OpenAI.

## 6. Risques techniques identifiés

| Risque | Mesure |
|---|---|
| Connecteurs SIEM non validés sur instance réelle | statut affiché honnêtement ; tests sur réponses simulées conformes aux API documentées ; bouton « Tester la connexion » |
| Quotas et conditions d'utilisation des sources | sources désactivées par défaut, `Retry-After`, statut `rate_limited`, liens vers les conditions |
| DNS rebinding entre validation SSRF et connexion | revalidation à chaque redirection ; risque résiduel documenté (SECURITY.md) |
| Hallucinations / injection de prompt IA | données non fiables délimitées, sortie JSON stricte, validation des preuves, pas d'outils, action humaine obligatoire |
| Compilation Windows impossible dans ce conteneur | script PowerShell + workflow GitHub Actions ; validation du spec sur Linux |
| SQLite et concurrence | WAL + `busy_timeout` ; PostgreSQL pour les déploiements multi-utilisateurs |
| Fichier de clé maîtresse perdu | les secrets des connecteurs deviennent illisibles (affichés « non configuré ») ; sauvegarde à prévoir |
