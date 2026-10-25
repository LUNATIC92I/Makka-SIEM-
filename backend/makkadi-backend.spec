# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the MAKKADi backend (onedir build).
#   pyinstaller --noconfirm makkadi-backend.spec
# Produces dist/makkadi-backend/makkadi-backend(.exe) with migrations, demo data and the built frontend.
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).resolve()
REPO = ROOT.parent
frontend_dist = REPO / "frontend" / "dist"
if not (frontend_dist / "index.html").is_file():
    raise SystemExit("frontend/dist manquant : exécutez d'abord 'npm run build' dans frontend/")

datas = [
    (str(ROOT / "migrations"), "migrations"),
    (str(REPO / "sample_data"), "sample_data"),
    (str(frontend_dist), "frontend_dist"),
]
datas += collect_data_files("reportlab")
hiddenimports = (
    collect_submodules("app")
    + collect_submodules("uvicorn")
    + collect_submodules("dns")
    + ["sqlalchemy.dialects.sqlite", "alembic.runtime.migration", "alembic.ddl.sqlite", "multipart", "maxminddb"]
)

a = Analysis(
    [str(ROOT / "app" / "run.py")],
    pathex=[str(ROOT)],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest", "IPython", "matplotlib", "numpy"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [], exclude_binaries=True, name="makkadi-backend", console=True,
    upx=False, icon=str(REPO / "desktop" / "build" / "icon.ico") if (REPO / "desktop" / "build" / "icon.ico").exists() else None,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="makkadi-backend")
