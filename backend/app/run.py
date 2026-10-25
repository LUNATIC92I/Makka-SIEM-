"""Entry point: ``python -m app.run`` (also the PyInstaller executable entry)."""

from __future__ import annotations

import argparse
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="makkadi-backend", description="MAKKADi OSINT investigation server")
    parser.add_argument("--host", help="Interface d'écoute (défaut 127.0.0.1)")
    parser.add_argument("--port", type=int, help="Port (défaut 8765)")
    parser.add_argument("--data-dir", help="Dossier de données")
    parser.add_argument("--static-dir", help="Dossier du frontend compilé")
    parser.add_argument("--migrate-only", action="store_true", help="Appliquer les migrations puis quitter")
    parser.add_argument("--open-browser", action="store_true", help="Ouvrir l'interface dans le navigateur par défaut")
    args = parser.parse_args(argv)
    for key, value in (("HOST", args.host), ("PORT", args.port), ("DATA_DIR", args.data_dir), ("STATIC_DIR", args.static_dir)):
        if value is not None:
            os.environ[f"MAKKADI_{key}"] = str(value)

    from app.core.config import get_settings

    settings = get_settings()
    try:
        settings.check_bind_address()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    settings.ensure_dirs()
    if args.migrate_only:
        from app.database.migrate import upgrade_to_head

        upgrade_to_head(settings.resolved_database_url)
        print("migrations applied")
        return 0

    import uvicorn

    from app.main import app

    if args.open_browser:
        import threading
        import time
        import urllib.request
        import webbrowser

        url = f"http://{settings.host}:{settings.port}/"

        def _open() -> None:
            for _ in range(60):
                try:
                    urllib.request.urlopen(url + "api/v1/health", timeout=1)  # noqa: S310  # nosec B310 - fixed local http URL
                    webbrowser.open(url)
                    return
                except OSError:
                    time.sleep(0.5)

        threading.Thread(target=_open, daemon=True).start()

    uvicorn.run(app, host=settings.host, port=settings.port, log_config=None, access_log=False, proxy_headers=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
