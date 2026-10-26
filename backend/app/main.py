"""FastAPI application factory."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

# Importing handlers registers them in the task registry.
import app.investigation.pipeline  # noqa: F401
import app.services.notifications  # noqa: F401
import app.services.retention  # noqa: F401
from app.api.routes import auth, connectors, events, intel, investigations, operations, reports, users
from app.core.config import APP_VERSION, get_settings
from app.core.logging import configure_logging, get_logger
from app.database.migrate import upgrade_to_head
from app.database.session import SessionLocal, init_engine
from app.investigation.pipeline import scheduler_loop
from app.security.keys import jwt_secret, master_key
from app.security.ratelimit import limiter
from app.services.bootstrap import bootstrap
from app.services.tasks import recover_interrupted, worker_loop

log = get_logger("makkadi")
API_PREFIX = "/api/v1"


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ANN201
    s = get_settings()
    s.ensure_dirs()
    master_key(s)  # create/unlock key material at startup (DPAPI on Windows): fail early, not on first use
    jwt_secret(s)
    init_engine()
    upgrade_to_head(s.resolved_database_url)
    with SessionLocal() as db:
        bootstrap(db)
        recovered = recover_interrupted(db)
    log.info("startup", extra={"ctx": {"app": s.app_name, "version": APP_VERSION, "demo_mode": s.demo_mode,
                                        "recovered_tasks": recovered}})
    stop = asyncio.Event()
    background: list[asyncio.Task] = []
    if s.worker_enabled:
        background.append(asyncio.create_task(worker_loop(SessionLocal, s.worker_poll_seconds, stop)))
        background.append(asyncio.create_task(scheduler_loop(SessionLocal, stop)))
    yield
    stop.set()
    for t in background:
        try:
            await asyncio.wait_for(t, timeout=10)
        except (TimeoutError, asyncio.CancelledError):
            t.cancel()


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data: https://*.tile.openstreetmap.org; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
}


def create_app() -> FastAPI:
    s = get_settings()
    configure_logging(s.log_level)
    app = FastAPI(title=f"{s.app_name} API", version=APP_VERSION, lifespan=lifespan,
                  docs_url="/api/docs" if s.environment != "production" else None, redoc_url=None,
                  openapi_url="/api/openapi.json" if s.environment != "production" else None)
    if s.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=s.cors_origins, allow_methods=["*"],
                           allow_headers=["Authorization", "Content-Type"], allow_credentials=False)

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):  # noqa: ANN001, ANN202
        path = request.url.path
        if path.startswith(API_PREFIX):
            ip = request.client.host if request.client else "unknown"
            limit = s.login_rate_limit_per_minute if path.endswith("/auth/login") or path.endswith("/auth/bootstrap") else s.rate_limit_per_minute
            key = f"{ip}:{'login' if limit == s.login_rate_limit_per_minute else 'api'}"
            allowed, retry = limiter.allow(key, limit)
            if not allowed:
                return JSONResponse({"detail": "Trop de requêtes, réessayez plus tard"}, status_code=429,
                                    headers={"Retry-After": str(int(retry) + 1)})
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if path.startswith(API_PREFIX):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Do not echo submitted values (could contain secrets).
        return JSONResponse({"detail": "Requête invalide",
                             "errors": [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()[:20]]}, status_code=422)

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error")
        return JSONResponse({"detail": "Erreur interne"}, status_code=500)

    for module in (auth, users, investigations, events, intel, reports, connectors, operations):
        app.include_router(module.router, prefix=API_PREFIX)

    static_dir = s.static_dir or _default_static_dir()
    if static_dir and (static_dir / "index.html").is_file():
        root = static_dir.resolve()

        @app.get("/{full_path:path}", include_in_schema=False)
        async def spa(full_path: str):  # noqa: ANN202
            if full_path.startswith("api/"):
                raise StarletteHTTPException(status_code=404)
            candidate = (root / full_path).resolve()
            if full_path and candidate.is_file() and root in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(root / "index.html")

    return app


def _default_static_dir() -> Path | None:
    import sys

    if getattr(sys, "_MEIPASS", None):
        return Path(sys._MEIPASS) / "frontend_dist"  # type: ignore[attr-defined]
    candidate = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    return candidate if candidate.is_dir() else None


app = create_app()
