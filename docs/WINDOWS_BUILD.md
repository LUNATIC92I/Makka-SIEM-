# Compilation de l'exécutable Windows

## Ce qui est produit

| Fichier | Description |
|---|---|
| `desktop\dist\MAKKADi-Setup-0.1.0-x64.exe` | installateur (choix du dossier, raccourcis, désinstallation ; installation par utilisateur, sans droits administrateur) |
| `desktop\dist\MAKKADi-Portable-0.1.0-x64.exe` | exécutable portable (aucune installation) |
| `backend\dist\makkadi-backend\makkadi-backend.exe` | serveur seul (interface dans le navigateur : `makkadi-backend.exe --open-browser`) |

Architecture : Electron lance `resources\backend\makkadi-backend.exe --host 127.0.0.1 --port <libre> --data-dir
%APPDATA%\MAKKADi\data`, attend `/api/v1/health`, puis affiche l'interface. Le serveur est arrêté à la fermeture.
Les données restent dans `%APPDATA%\MAKKADi` (non supprimées à la désinstallation).

## Prérequis (poste de build Windows 10/11 x64)

* Python **3.12** (python.org, cocher « Add python.exe to PATH »)
* Node.js **22 LTS**
* Git
* Connexion Internet (dépendances pip/npm, binaire Electron, NSIS téléchargé par electron-builder)

## Procédure

```powershell
git clone <dépôt> makkadi; cd makkadi
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\build_windows.ps1            # ajoute -SkipTests pour un build rapide
```

Le script : crée `backend\.venv`, installe les dépendances, exécute `pytest` et `pip-audit`, construit le frontend
(`npm ci`, tests, `npm run build`), compile le backend avec PyInstaller (`makkadi-backend.spec`), **lance un test de
fumée** du backend compilé (`/api/v1/health`), copie le backend dans `desktop\resources\backend`, puis exécute
`electron-builder --win nsis portable --x64` et affiche les SHA-256 des `.exe`.

### Étapes manuelles équivalentes

```powershell
cd backend; python -m venv .venv; .\.venv\Scripts\pip install -r requirements-dev.txt
.\.venv\Scripts\python -m pytest -q
cd ..\frontend; npm ci; npm run build
cd ..\backend; .\.venv\Scripts\pyinstaller --noconfirm makkadi-backend.spec
cd ..\desktop; mkdir resources\backend; xcopy /E /I ..\backend\dist\makkadi-backend resources\backend\makkadi-backend
npm ci; npm run dist:win
```

## Via GitHub Actions

Workflow `.github/workflows/windows-build.yml` : *Actions → Windows build (.exe) → Run workflow* (ou pousser un tag
`v*`). Les `.exe` sont publiés comme artefact `makkadi-windows`.

## Signature de code et mises à jour

* Les exécutables produits **ne sont pas signés** : Windows SmartScreen affichera un avertissement. Pour la
  diffusion, signer avec un certificat Authenticode (`CSC_LINK` / `CSC_KEY_PASSWORD` pour electron-builder, ou
  `signtool sign /fd sha256 /tr <horodatage> ...`).
* **Mise à jour automatique : non incluse** (hors périmètre de cette version). Une mise à jour sécurisée exigerait
  des binaires signés et un canal HTTPS de confiance (ex. `electron-updater` avec vérification de signature). Les
  mises à jour se font en réinstallant la nouvelle version ; la base est migrée automatiquement au démarrage.

## Ce qui a été vérifié

**Le `.exe` a été compilé et testé sur un runner GitHub Actions `windows-latest`** (exécution
[40252937566](https://github.com/LUNATIC92I/Makka-SIEM-/actions/runs/40252937566), 2026-10-26) :

| Étape | Résultat |
|---|---|
| Tests backend sous Windows | 147 réussis, 3 ignorés (tests réseau) — dont le test DPAPI |
| `pip-audit`, tests et build frontend | réussis |
| Backend PyInstaller `makkadi-backend.exe` | compilé ; test de fumée `/api/v1/health` : « Backend compilé OK : MAKKADi 0.1.0 » |
| `MAKKADi-Setup-0.1.0-x64.exe` (NSIS) | produit — SHA-256 `0F0FF23CA13BCA61F13985CA0612B2B832FA9CE67D514121AA39346070C72188` |
| `MAKKADi-Portable-0.1.0-x64.exe` | produit — SHA-256 `581F8D21D9AD7F24CC35E0F1FC625A3C53D1586B31E7055E9D06F587370AFF0C` |
| Lancement de `MAKKADi.exe` | backend embarqué démarré sur un port local libre, fenêtre « MAKKADi » chargée (`http://127.0.0.1:54423/`), santé OK |
| Données utilisateur | `%APPDATA%\MAKKADi\data` contient `master.key.dpapi` et `jwt.key.dpapi`, aucune clé en clair |

Build le plus récent vérifié (exécution 40253530668, commit `d11819a`, même test de fumée réussi) :

```
ec1caef50020b65f8ad190dde2fda169648cf58d64c9c3a5364a807dd6ee8e8d  MAKKADi-Setup-0.1.0-x64.exe
51c38f7635744fe287a854f2bff3587ca12ecaef96ed979fc1045ca58d354ab2  MAKKADi-Portable-0.1.0-x64.exe
```

(Les builds ne sont pas reproductibles octet pour octet : chaque exécution produit des empreintes différentes, à
comparer avec celles affichées dans le journal de l'exécution concernée.)

Les exécutables sont téléchargeables dans l'artefact **`makkadi-windows`** de cette exécution (≈ 340 Mo, conservé
jusqu'au 2027-01-24 selon la politique de rétention GitHub). Chaque push sur `main` ou un tag `v*` en produit un
nouveau. Ils ne sont **pas signés** (voir ci-dessus).

Non vérifié automatiquement : l'installation interactive via l'assistant NSIS et la navigation dans l'interface sous
Windows (l'interface est testée de bout en bout sous Linux par le job `ui-e2e`).

## Dépannage

| Symptôme | Cause probable |
|---|---|
| `cannot expand pattern … macro target is not defined` | ancienne configuration : utiliser `artifactName` par cible (`nsis`, `portable`), déjà corrigé |
| « frontend/dist manquant » | exécuter `npm run build` dans `frontend` avant PyInstaller |
| Fenêtre « Le serveur local s'est arrêté » | consulter le message (dernières lignes du journal) ; port bloqué par un antivirus, dossier de données non inscriptible |
| Antivirus bloquant `makkadi-backend.exe` | faux positif fréquent pour PyInstaller non signé : signer le binaire |
| PDF sans caractères spéciaux | police Arial absente : les caractères hors Latin-1 sont translittérés |
