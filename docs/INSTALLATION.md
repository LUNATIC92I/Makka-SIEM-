# Installation et configuration

## Utilisateur final (Windows)

1. Exécuter `MAKKADi-<version>-x64-nsis.exe` (ou lancer directement la version portable).
2. Au premier démarrage, créer le compte administrateur (12 caractères minimum, majuscules, minuscules, chiffres).
3. Le mode démonstration est actif par défaut : *Vue d'ensemble → Charger le scénario de démonstration*.
4. Pour un usage réel : *Connecteurs* → activer les sources OSINT et configurer le SIEM, puis définir
   `MAKKADI_DEMO_MODE=false` dans `%APPDATA%\MAKKADi\data\.env` (ou variable d'environnement) pour masquer les
   sources synthétiques.

Données : `%APPDATA%\MAKKADi\data` (base `makkadi.db`, `master.key`, `jwt.key`, `reports\`).

## Développeur / serveur

```bash
git clone <dépôt> && cd Makka-SIEM-
cd backend && python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
cp ../.env.example .env            # ajuster si besoin
python -m app.run                  # 127.0.0.1:8765, migrations appliquées automatiquement
cd ../frontend && npm ci && npm run build   # l'interface est ensuite servie par le backend
```

Options de `python -m app.run` : `--host`, `--port`, `--data-dir`, `--static-dir`, `--open-browser`,
`--migrate-only`.

## Configuration

Toutes les variables (`MAKKADI_*`) sont décrites dans [`.env.example`](../.env.example). Les clés d'API se saisissent
dans l'interface (*Connecteurs*) et sont chiffrées ; elles ne doivent pas être placées dans `.env`.

Paramètres modifiables à chaud (*Paramètres*, journalisés) : pondérations et seuils de scoring, règles d'ingestion
(seuil de sévérité, regroupement), criticité des actifs, rétention, utilisateurs et rôles.

## PostgreSQL

```bash
pip install -r requirements-postgres.txt
export MAKKADI_DATABASE_URL="postgresql+psycopg://makkadi:***@db:5432/makkadi"
python -m app.run --migrate-only && python -m app.run
```

> La suite de tests complète passe sur PostgreSQL 16 :
> `MAKKADI_TEST_DATABASE_URL=postgresql+psycopg://… python -m pytest` (job CI `backend-postgres`).

## Exposition réseau

Par défaut le serveur refuse d'écouter ailleurs que sur la boucle locale. Pour un serveur partagé : placer un reverse
proxy TLS (nginx, IIS) devant le service, définir `MAKKADI_HOST=0.0.0.0` **et** `MAKKADI_ALLOW_REMOTE_BIND=true`.
La création du premier administrateur reste limitée au poste local.

## Connecteurs SIEM sur réseau interne

Le garde anti-SSRF refuse les destinations privées. Autoriser explicitement l'hôte :

```
MAKKADI_OUTBOUND_ALLOWED_HOSTS=["splunk.corp.local"]
MAKKADI_OUTBOUND_ALLOWED_CIDRS=["10.10.0.0/24"]
```
