"""Password change, administrator reset and local recovery of a forgotten password."""

from __future__ import annotations

import io

from sqlalchemy import select

from app.models import AuditLog
from app.run import main as run_main
from app.services.account_recovery import LOCAL_ACTOR, run_cli
from tests.conftest import ADMIN, auth_headers, create_user

API = "/api/v1"
NEW = "Nouveau-Secret-2026"


def _login(client, username, password):  # noqa: ANN001, ANN202
    return client.post(API + "/auth/login", json={"username": username, "password": password})


def _user_id(client, admin, username):  # noqa: ANN001, ANN202
    return next(u["id"] for u in client.get(API + "/users", headers=admin).json() if u["username"] == username)


def test_change_own_password(client, admin):
    bad = client.post(API + "/auth/change-password", headers=admin, json={"current_password": "faux", "new_password": NEW})
    assert bad.status_code == 400
    weak = client.post(API + "/auth/change-password", headers=admin, json={"current_password": ADMIN[1], "new_password": "court"})
    assert weak.status_code == 422
    ok = client.post(API + "/auth/change-password", headers=admin, json={"current_password": ADMIN[1], "new_password": NEW})
    assert ok.status_code == 200
    assert client.get(API + "/auth/me", headers=admin).status_code == 401  # sessions revoked
    assert _login(client, "admin", ADMIN[1]).status_code == 401
    assert _login(client, "admin", NEW).status_code == 200


def test_admin_resets_locked_user(client, admin, db):
    analyst = create_user(client, admin, "analyste1", "analyst")
    for _ in range(5):
        _login(client, "analyste1", "mauvais-mot-de-passe")
    assert _login(client, "analyste1", "Utilisateur-Test-42").status_code == 423
    uid = _user_id(client, admin, "analyste1")
    assert next(u for u in client.get(API + "/users", headers=admin).json() if u["id"] == uid)["locked"]

    r = client.patch(API + f"/users/{uid}", headers=admin, json={"password": NEW})
    assert r.status_code == 200 and r.json()["locked"] is False
    assert client.get(API + "/auth/me", headers=analyst).status_code == 401
    assert _login(client, "analyste1", NEW).status_code == 200
    entry = db.scalars(select(AuditLog).where(AuditLog.action == "user.updated").order_by(AuditLog.id.desc())).first()
    assert entry.details == {"password": "reset"}
    assert NEW not in str(entry.details)


def test_admin_unlock_without_reset(client, admin):
    create_user(client, admin, "analyste2", "analyst")
    for _ in range(5):
        _login(client, "analyste2", "mauvais-mot-de-passe")
    uid = _user_id(client, admin, "analyste2")
    assert client.patch(API + f"/users/{uid}", headers=admin, json={"unlock": True}).json()["locked"] is False
    assert _login(client, "analyste2", "Utilisateur-Test-42").status_code == 200


def test_only_admin_can_reset_others(client, admin):
    analyst = create_user(client, admin, "analyste3", "analyst")
    uid = _user_id(client, admin, "admin")
    assert client.patch(API + f"/users/{uid}", headers=analyst, json={"password": NEW}).status_code == 403
    assert _login(client, *ADMIN).status_code == 200


def test_local_recovery_cli(client, admin, db):
    out = io.StringIO()
    answers = iter([NEW, "different", "court", "court", NEW, NEW])
    code = run_cli(db, None, out, ask=lambda _p: "admin", ask_secret=lambda _p: next(answers))
    text = out.getvalue()
    assert code == 0, text
    assert "admin  [admin]" in text and "différentes" in text and "trop faible" in text
    assert client.get(API + "/auth/me", headers=admin).status_code == 401
    assert _login(client, "admin", NEW).status_code == 200
    entry = db.scalars(select(AuditLog).where(AuditLog.action == "auth.password_reset_local")).one()
    assert entry.actor == LOCAL_ACTOR and NEW not in str(entry.details)


def test_local_recovery_cli_failures(client, admin, db):
    out = io.StringIO()
    assert run_cli(db, "inconnu", out, ask_secret=lambda _p: NEW) == 1
    assert "introuvable" in out.getvalue()
    assert run_cli(db, "admin", out, ask_secret=lambda _p: "court") == 1
    assert "trop d'essais" in out.getvalue()
    assert _login(client, *ADMIN).status_code == 200


def test_reset_password_command(client, admin, env, monkeypatch, capsys):
    for _ in range(5):
        _login(client, "admin", "mauvais-mot-de-passe")
    monkeypatch.setattr("getpass.getpass", lambda _p="": NEW)
    assert run_main(["--data-dir", str(env), "--reset-password", "admin"]) == 0
    assert "réinitialisé" in capsys.readouterr().out
    auth_headers(client, "admin", NEW)  # unlocked and new password accepted
