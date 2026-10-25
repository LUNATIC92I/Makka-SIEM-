# Compilation de l'exécutable Windows

## Ce qui est produit

| Fichier | Description |
|---|---|
| `desktop\dist\MAKKADi-0.1.0-x64-nsis.exe` | installateur (choix du dossier, raccourcis, désinstallation ; installation par utilisateur, sans droits administrateur) |
| `desktop\dist\MAKKADi-0.1.0-x64-portable.exe` | exécutable portable (aucune installation) |
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

## Ce qui a été vérifié dans ce dépôt

Le conteneur de développement est Linux sans Wine : **aucun `.exe` n'a été produit ici**. Ont été effectivement
vérifiés (voir [TEST_RESULTS.md](TEST_RESULTS.md)) :

* compilation PyInstaller du backend avec le même `makkadi-backend.spec` (variante Linux) puis exécution :
  migrations, interface servie, scénario de démonstration, génération d'un PDF ;
* construction Electron `electron-builder --linux dir` avec ce backend et lancement sous Xvfb : démarrage du
  serveur embarqué sur un port libre et affichage de l'écran de premier démarrage.

La compilation Windows elle-même reste **à exécuter** (script ou workflow ci-dessus).

## Dépannage

| Symptôme | Cause probable |
|---|---|
| « frontend/dist manquant » | exécuter `npm run build` dans `frontend` avant PyInstaller |
| Fenêtre « Le serveur local s'est arrêté » | consulter le message (dernières lignes du journal) ; port bloqué par un antivirus, dossier de données non inscriptible |
| Antivirus bloquant `makkadi-backend.exe` | faux positif fréquent pour PyInstaller non signé : signer le binaire |
| PDF sans caractères spéciaux | police Arial absente : les caractères hors Latin-1 sont translittérés |
