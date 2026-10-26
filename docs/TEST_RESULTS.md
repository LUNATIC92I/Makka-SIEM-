# Résultats des tests exécutés

Date d'exécution : 2026-10-25 (UTC). Environnement : Linux x86-64, Python 3.13.17, Node 22.22.0, Chromium (Playwright).
Seuls les résultats réellement obtenus sont reportés ici.

## 1. Tests automatisés backend (pytest)

Commande : `cd backend && python -m pytest -q` → **138 réussis, 3 ignorés** (tests réseau « live », exécutés
séparément ci-dessous), durée ≈ 29 s.

| Fichier | Tests | Couverture fonctionnelle |
|---|---|---|
| `test_indicators.py` | 30 | validation IPv4/IPv6, 21 cas de portée (privée, loopback, link-local/métadonnées, CGNAT, documentation, benchmark, multicast, réservée, IPv4 mappée…), domaines spéciaux et IDN, extraction texte, refang, empreintes |
| `test_siem.py` | 23 | normalisation des sévérités, mapping (clés ECS aplaties), id déterministe, import JSON, dossier surveillé avec reprise, Sentinel (KQL + rafraîchissement de jeton sur 401, refus d'injection KQL), Splunk, Elastic, Wazuh, Defender, REST générique (429 + `Retry-After`, 401, 503 → retries), paramètres manquants |
| `test_osint.py` | 17 | RDAP (organisations seules, aucune donnée personnelle), redirection vers 169.254.169.254 bloquée, réponses gzip, RIPEstat, VirusTotal (absence de détection ≠ bénin, non configuré, 404), AbuseIPDB (Tor, quota, 500 sans fuite de clé), OTX, URLhaus (hors périmètre IPv6), GreyNoise, InternetDB, crt.sh (actuel/historique), MISP, TAXII, listes internes, erreur interne confinée, 7 sources de démo marquées synthétiques |
| `test_scoring.py` | 7 | risque/confiance séparés et expliqués, **source miroir non comptée deux fois**, recouvrement pondéré, pénalités (contradictions, obsolescence, erreurs), absence de signal ≠ bénin, pondérations configurables, criticité des actifs |
| `test_ai.py` | 18 | sortie déterministe valide et ancrée, preuves/URL inventées retirées, attribution sans renseignement retirée et confiance plafonnée, schéma strict, actions toujours soumises à validation humaine, 5 motifs d'injection, neutralisation du résumé, délimiteur non refermable, schéma JSON strict, fournisseur compatible OpenAI local (simulé), **fournisseur Claude (client SDK simulé)** : forme de la requête, `refusal`, clé absente, blocage sans politique de traitement |
| `test_security.py` | 29 | 10 cas SSRF, DNS vers IP privée + liste blanche, authentification requise, bootstrap unique et local uniquement, RBAC, isolation des investigations restreintes, verrouillage et limitation de débit de connexion, révocation à la déconnexion, entrées d'injection SQL inertes, secrets jamais exposés ni stockés en clair (vérification sur le dump SQLite), URL de connecteur SSRF refusée, erreurs de validation sans écho de secret, webhook HMAC (mauvaise signature, rejeu, connecteur inconnu, doublon), en-têtes de sécurité, garde d'écoute réseau, chaîne d'audit altérée détectée, mode actif désactivé et périmètre, `.env` du dossier de données |
| `test_tasks.py` | 6 | retries avec temporisation puis succès, `dead` après maximum, échec non relançable, déduplication, **reprise des tâches interrompues**, curseur de collecte non avancé en cas d'échec + dédup à la relecture, planification sans doublon, purge de rétention |
| `test_reports.py` | 4 | PDF technique et synthèse (`%PDF`, en-tête SHA-256), JSON valide et complet (provenance, ID d'origine, horodatages), détection de falsification du fichier, échappement du balisage hostile |
| `test_migrations.py` | 2 | `upgrade head` identique au modèle (aucun écart Alembic), `downgrade base`, re-upgrade, contrainte d'unicité des événements |
| `test_e2e_scenario.py` | 2 | **scénario complet** (section 8) en mode démo — étapes 1 à 7 + traçabilité + injection — et en mode réel avec collecte SIEM automatique (dossier JSON planifié) et connecteurs RDAP/RIPEstat/AbuseIPDB (HTTP simulé), VirusTotal activé sans clé (« non configuré » visible) |

## 2. Tests « live » (sources réelles, sans clé)

Commande : `MAKKADI_LIVE_TESTS=1 python -m pytest -m live` → **3 réussis** (RDAP, RIPEstat, InternetDB).

Interrogation directe des sources pour l'indicateur de démonstration `154.73.112.25` :

| Source | Résultat obtenu |
|---|---|
| RDAP | 1ʳᵉ requête : réponse AfriNIC (bloc `154.73.112.0/23`, pays d'enregistrement `TD`, enregistré le 2019-05-07 ; seule entité publiée : un contact individuel, **volontairement ignoré**). Requêtes suivantes : AfriNIC a répondu **404 « Resource not found »** (vérifié aussi avec `curl`) → affiché comme « Donnée indisponible » avec la réponse du registre |
| RIPEstat | `ok` : préfixe annoncé `154.73.112.0/24`, AS327756 (« AIRTEL TCHAD ») |
| Shodan InternetDB | `ok` : port 2000 observé, nom d'hôte PTR fourni par Shodan |
| GreyNoise Community | `no_data` : « non observé par les capteurs » |
| DNS (PTR) | `no_data` |

Ces valeurs proviennent des sources au moment du test et peuvent évoluer ; elles ne sont pas préremplies dans
l'application.

Ces tests en conditions réelles ont révélé **deux défauts corrigés** : réponses compressées (gzip) mal reconstruites
par le client HTTP, et URL de référence RDAP contenant des espaces.

## 3. Frontend

* `npm test` (Vitest) : **4 réussis**.
* `npm run build` (`tsc --noEmit` + Vite) : réussi.
* Vérification visuelle dans Chromium (Playwright) sur l'application servie par le backend : connexion, vue
  d'ensemble, centre d'investigation, fiche (synthèse, OSINT, chronologie, graphe, carte, analyse IA, rapports),
  cartographie, Threat Intelligence, connecteurs, paramètres, file de tâches — **aucune erreur JavaScript**.
  Captures : `docs/screenshots/`.

## 4. Application de bout en bout

* Serveur réel (`python -m app.run`) en mode démo : scénario chargé, 4 investigations traitées par le worker,
  rapports générés.
* Serveur réel en mode **non démo**, sources sans clé activées, import du scénario `154.73.112.25` : investigation
  `completed`, données réelles RIPEstat/InternetDB, manques affichés, risque *élevé* (75/100) avec confiance
  *faible* (21/100) — conforme au principe « peu de preuves ⇒ confiance faible ». Capture :
  `docs/screenshots/real-investigation.png`.

## 5. Packaging

| Vérification | Résultat |
|---|---|
| PyInstaller (`makkadi-backend.spec`, variante Linux) | compilé (96 Mo) ; exécution : santé OK, interface servie, migrations, démo, PDF généré |
| electron-builder `--linux dir` avec ce backend, lancement sous Xvfb | backend embarqué démarré sur port libre, interface « premier démarrage » affichée (capture `electron-first-run.png`) |
| **`.exe` Windows** | **non produit ici** (conteneur Linux sans Wine) — à générer via `scripts/build_windows.ps1` ou le workflow GitHub Actions |

## 6. Contrôles de sécurité

| Outil | Résultat |
|---|---|
| `bandit -r app` | 0 haute, 0 moyenne, 10 basses revues (faux positifs / assertions / gigue non cryptographique) — un caractère bidirectionnel littéral a été remplacé par des échappements |
| `pip-audit -r requirements.txt` | aucune vulnérabilité connue |
| `npm audit` (frontend, production) | 0 après mise à jour de `react-router-dom` 6 → 7.18.4 (GHSA-wrjc-x8rr-h8h6, GHSA-337j-9hxr-rhxg) |
| `npm audit` (desktop) | 0 après mise à jour d'Electron 44.7.0 → 44.9.3 (GHSA-jr5w-w6x2-84p9) |

## 7. Compléments (2026-10-26)

* **CI GitHub Actions** (Ubuntu, Python 3.12) : jobs backend et frontend **réussis** sur la branche.
* **Premier build sur runner Windows** (`windows-latest`) : 137/138 tests réussis ; l'échec a révélé un vrai défaut
  Windows — un fichier de liste interne enregistré en cp1252 (Excel / Bloc-notes) n'était pas lu. Corrigé (UTF-8,
  UTF-8 BOM puis cp1252) et couvert par un test.
* Nouveaux tests : historisation des enrichissements, notifications (signature, envoi unique par niveau, format
  Teams, données de démo exclues, SSRF sur l'URL, échec relancé et visible), migration 0002 appliquée sur une base
  0001 contenant des données. Total backend : **143 réussis, 3 ignorés (live)**.
* **Test E2E de l'interface** (`frontend/e2e/ui-smoke.mjs`, Playwright, application réelle en mode démo) :
  **22/22 contrôles réussis** (connexion/premier démarrage, ingestion, pipeline, 6 onglets, avertissement de
  géolocalisation, validation humaine, PDF + vérification d'intégrité, 6 pages, aucune erreur JavaScript). Ajouté
  à la CI (job `ui-e2e`).

* **PostgreSQL 16** (serveur local) : `MAKKADI_TEST_DATABASE_URL=… pytest` → **145 réussis** après correction d'un
  défaut réel (`SELECT DISTINCT` sur colonnes JSON refusé par PostgreSQL dans l'historique d'un indicateur).
* Protection DPAPI des clés : test Windows ajouté (exécuté sur le runner Windows).

## 8. Restant à tester

* Connecteurs SIEM et OSINT à clé contre des **instances réelles** (Sentinel, Splunk, Elastic, Wazuh, Defender,
  VirusTotal, AbuseIPDB, OTX, URLhaus, MISP, TAXII) — aucun accès disponible.
* Fournisseur Claude contre l'API réelle (testé avec un client simulé uniquement) ; fournisseur compatible OpenAI
  contre un vrai modèle local.
* MaxMind (base sous licence absente).
* Compilation, installation et lancement du `.exe` sur Windows 10/11 ; signature Authenticode.
* Tests de charge et tests d'interface automatisés au-delà des captures.
