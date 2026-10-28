# Guide de sécurité

## Modèle de menace (résumé)

| Menace | Mesures |
|---|---|
| Exposition réseau involontaire | écoute sur `127.0.0.1` par défaut ; refus de démarrer sur une autre interface sans `MAKKADI_ALLOW_REMOTE_BIND=true` ; Electron choisit un port libre local |
| Accès non autorisé | authentification obligatoire (JWT HS256, durée 60 min, révocation par `token_version` à la déconnexion / changement de mot de passe / de rôle) ; création du premier administrateur uniquement depuis le poste local et une seule fois |
| Mot de passe oublié | aucun envoi par e-mail ni question secrète. Réinitialisation par un administrateur (journalisée, sans le mot de passe) ou, pour le dernier administrateur, outil local `--reset-password` : il exige l'accès au dossier de données, comme l'initialisation. Toute réinitialisation déverrouille le compte et révoque ses sessions |
| Force brute | bcrypt (coût 12), verrouillage après 5 échecs (15 min), limitation de débit dédiée à la connexion (10/min/IP), comparaison factice pour les utilisateurs inconnus |
| Élévation de privilèges | RBAC (admin, analyst, viewer) vérifié côté serveur sur chaque route ; investigations **restreintes** visibles seulement du propriétaire, des assignés et des administrateurs, avec un 404 identique à « inexistant » |
| Injection SQL | ORM paramétré exclusivement ; filtres validés (types, longueurs, motifs) ; tests d'injection |
| SSRF | tout appel sortant passe par `validate_outbound_url` : HTTPS uniquement, pas d'identifiants dans l'URL, résolution DNS et refus des adresses non globales (privées, loopback, link-local/métadonnées cloud, CGNAT, réservées, IPv4 mappées), revalidation à chaque redirection, liste blanche explicite pour un SIEM interne |
| Fuite de secrets | secrets des connecteurs chiffrés (Fernet, clé maîtresse hors base, fichier 0600 ou variable d'environnement) ; jamais renvoyés par l'API (masqués) ni journalisés ; erreurs de validation sans écho des valeurs ; logs JSON avec rédaction des motifs de secrets |
| Données hostiles (journaux, OSINT) | assainissement (caractères de contrôle et bidirectionnels, tailles bornées), échappement XML dans les PDF, React échappe le HTML, popups de carte échappés |
| Injection de prompt IA | voir ci-dessous |
| Altération de preuves | SHA-256 des contenus bruts (événements, résultats OSINT), des entrées IA et des rapports ; vérification à la demande ; journal d'audit chaîné |
| Webhooks falsifiés / rejoués | HMAC-SHA256 avec horodatage (fenêtre 300 s), comparaison à temps constant, rejet journalisé |
| Abus des API internes | limitation de débit globale (240 req/min/IP), en-têtes de sécurité (CSP stricte, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `Cache-Control: no-store` pour l'API), OpenAPI désactivé en production |
| Shell de bureau | Electron : `contextIsolation`, `sandbox`, pas de `nodeIntegration`, navigation limitée à l'origine locale, liens externes HTTPS ouverts dans le navigateur système, permissions refusées, DevTools désactivés en production, instance unique |
| Balayage indiscriminé | **aucune** fonction de scan d'IP publiques. Le mode actif (connexion TCP sur une liste de ports) est désactivé par défaut, limité à une adresse unique dans `MAKKADI_ACTIVE_CHECKS_ALLOWED_CIDRS`, ports autorisés, justification obligatoire, journalisé |

## IA : protections

1. **Séparation** : les instructions sont dans le prompt système ; les données d'investigation sont transmises
   dans un bloc délimité `<investigation_data id="nonce">` déclaré non fiable. Les caractères `<`/`>` des données
   sont échappés (`<`) afin qu'elles ne puissent pas fermer le délimiteur.
2. **Détection** : les motifs d'injection (« ignore previous instructions », changement de rôle, balises système,
   demande de secrets, manipulation de verdict…) sont repérés dans les données et affichés à l'analyste.
3. **Aucun outil** n'est fourni au modèle ; il ne peut que retourner un document JSON.
4. **Sortie structurée validée** (`app/ai/validation.py`) : schéma strict (champs inconnus refusés), identifiants de
   preuve existants obligatoires, faits sans preuve retirés, URL non présentes dans les preuves supprimées,
   identifiants MITRE vérifiés, attribution d'acteur retirée sans preuve de renseignement (une IP ou une
   géolocalisation ne suffit jamais), confiance d'attribution plafonnée, toutes les actions marquées
   `requires_human_validation = true`, résumé neutralisé s'il reprend une injection.
5. **Minimisation** : seul un paquet de preuves est envoyé (pas les charges brutes) ; pseudonymisation des noms
   d'hôtes et adresses internes pour un fournisseur externe.
6. **Politique de traitement** : aucun envoi à un fournisseur non local sans
   `external_processing_acknowledged` (interface) ou `MAKKADI_AI_EXTERNAL_PROCESSING_ALLOWED=true`. Chaque analyse
   enregistre si des données ont quitté le poste et l'empreinte de l'entrée.
7. Le score de risque reste calculé par le moteur déterministe ; l'IA l'explique mais ne le fixe pas.

## Traçabilité

* `audit_logs` : connexion (réussite/échec/verrouillage), création d'administrateur, utilisateurs, ingestion,
  création/enrichissement d'investigation, changements de statut, décisions, analyses IA, rapports, téléchargements,
  connecteurs (création, modification, test, collecte), paramètres (avant/après), purges, contrôles actifs.
* Chaque entrée contient `prev_hash` et `entry_hash = SHA-256(prev_hash || entrée canonique)`. `GET
  /api/v1/audit/verify` détecte toute modification, insertion ou suppression.
* **Limite assumée** : la chaîne est *infalsifiable au sens « détectable »* et non immuable — un attaquant disposant
  d'un accès en écriture à la base peut recalculer toute la chaîne. Pour une garantie plus forte, exporter
  régulièrement le dernier `last_hash` vers un système externe (SIEM, stockage WORM) ou un service d'horodatage.
* Les rapports portent une empreinte SHA-256 vérifiable, **pas** une signature électronique qualifiée.

## Exploitation sûre

* Sauvegarder le dossier de données (`makkadi.db`, clés, `reports/`). Sans la clé maîtresse, les secrets des
  connecteurs sont illisibles.
* Sous Windows, la clé maîtresse et la clé JWT sont chiffrées par **DPAPI** (`master.key.dpapi`, `jwt.key.dpapi`),
  donc liées au compte Windows : une sauvegarde restaurée sur un autre compte ou poste ne pourra pas les déchiffrer.
  Pour une migration de poste, fournir la clé via `MAKKADI_MASTER_KEY` (coffre d'entreprise). Ailleurs, fichiers
  en permissions 0600.
* Pour un déploiement multi-utilisateurs : PostgreSQL, reverse proxy TLS devant le serveur, `MAKKADI_ALLOW_REMOTE_BIND`
  explicite, et revue des limites de débit.
* Signer le code des exécutables Windows (Authenticode) avant diffusion.

## Contrôles effectués avant distribution

Voir [TEST_RESULTS.md](TEST_RESULTS.md) : tests de sécurité automatisés, `bandit`, `pip-audit`, `npm audit`.
Résidus `bandit` (sévérité basse, revus) : `B105` faux positifs (`"bearer"`, masque `••••`), `B311` (`random` pour la
gigue de temporisation, non cryptographique), `B101` (assertions d'invariants internes), `B406`
(`xml.sax.saxutils.escape`, utilisé pour échapper et non pour analyser du XML).
Risque résiduel connu : rebinding DNS entre la validation SSRF et la connexion (atténué, non éliminé).
