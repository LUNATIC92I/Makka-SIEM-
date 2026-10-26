# État fonctionnel

## Opérationnel (implémenté et testé)

* Ingestion : import JSON (téléversement et dossier surveillé), webhook HMAC, mode démonstration, collecte planifiée,
  déduplication, conservation de l'identifiant d'origine, reprise par curseur, regroupement par source.
* Extraction et validation des indicateurs (IP, domaines, URL, md5/sha1/sha256), classification des adresses
  spéciales, formes défangées.
* Moteur OSINT concurrent avec quotas, erreurs visibles, « Donnée indisponible », références, horodatages, SHA-256.
* Sources réelles interrogées avec succès : RDAP, RIPEstat, Shodan InternetDB (GreyNoise et DNS interrogés, sans
  donnée pour l'IP de test). Listes de réputation internes.
* Corrélation : relations qualifiées (actuelles/historiques), faits attribués, concordances, contradictions,
  données obsolètes, informations manquantes.
* Scoring explicable risque/confiance, dépendance des sources, pondérations configurables.
* Analyse IA : moteur déterministe local ; abstraction de fournisseurs ; validation stricte ; protections contre
  l'injection ; politique d'envoi externe ; pseudonymisation.
* Graphe d'investigation navigable, cartographie hors ligne avec avertissements, chronologie avec provenance.
* Rapports PDF (technique, synthèse) et JSON, SHA-256 et vérification.
* Authentification, RBAC, investigations restreintes, verrouillage, limitation de débit, coffre de secrets, SSRF,
  en-têtes de sécurité, audit chaîné et vérifiable, rétention.
* File de tâches persistante (retries, temporisation, reprise après interruption) consultable.
* Historique des enrichissements : chaque relance crée une nouvelle passe, les résultats antérieurs sont conservés
  (marqués « remplacés ») et visibles dans l'historique Threat Intelligence et la chronologie.
* Notifications (webhook JSON signé HMAC, Microsoft Teams, Slack) au franchissement d'un seuil de risque, une fois
  par niveau, réémises en cas d'escalade ; URL chiffrée et contrôlée anti-SSRF ; données de démo exclues par défaut.
* Sous Windows, clé maîtresse et clé JWT chiffrées par DPAPI (liées au compte Windows) ; migration automatique des
  fichiers en clair existants.
* Mode actif (TCP) désactivé par défaut, restreint au périmètre autorisé.
* Console SOC (8 pages + fiche d'investigation à 9 onglets).
* Migrations Alembic, `.env.example`, spec PyInstaller, application Electron, script de build Windows, CI.

## Implémenté, non validé sur instance réelle

Connecteurs SIEM Sentinel, Splunk ES, Elastic Security, Wazuh, Defender XDR, REST générique ; sources VirusTotal,
AbuseIPDB, OTX, URLhaus, MISP, TAXII 2.1, crt.sh, ipinfo, MaxMind ; fournisseurs IA Claude et compatible OpenAI.
Ils sont couverts par des tests sur réponses simulées conformes aux API documentées et sont affichés comme tels.

## Partiel / limites connues

* **Exécutable Windows** : chaîne de build complète fournie et validée sous Linux ; le `.exe` doit être compilé sous
  Windows (non réalisé dans ce conteneur). Binaires non signés.
* PostgreSQL : supporté par l'ORM, non testé.
* Pas d'enrichissement récursif (les indicateurs associés sont relevés mais pas enrichis à leur tour).
* Limitation de débit en mémoire (mono-processus).
* Pas de mise à jour automatique (choix de sécurité tant que les binaires ne sont pas signés).
* Le moteur déterministe n'est pas un LLM : il restitue les preuves avec des règles prudentes.

## À développer

1. Validation des connecteurs sur des instances SIEM/TI réelles (Sentinel, Splunk, Elastic, Wazuh, Defender).
2. Signature Authenticode et mise à jour automatique signée (`electron-updater`).
4. Notifications par e-mail (SMTP) ; webhooks Teams/Slack non validés sur des espaces réels.
5. Enrichissement de second niveau contrôlé (profondeur, budget de requêtes).
6. Comparaison visuelle entre passes d'enrichissement (les données sont déjà historisées).
7. DNS passif (sources sous licence), Censys, sources sectorielles (CERT, ISAC).
8. Authentification SSO (OIDC/SAML) et MFA pour un déploiement multi-utilisateurs.
9. Horodatage qualifié (RFC 3161) des rapports et export externe de l'empreinte d'audit.
10. Tests de charge.
