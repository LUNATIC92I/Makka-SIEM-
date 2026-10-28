"""Local account recovery: reset a forgotten password from the machine that holds the data.

Used by ``makkadi-backend --reset-password``. Access to the data directory is the proof of
authority, exactly like the first-administrator bootstrap which is only allowed locally.
"""

from __future__ import annotations

import getpass
from collections.abc import Callable
from typing import TextIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import User
from app.security.passwords import hash_password, validate_password_strength
from app.services import audit

LOCAL_ACTOR = "console-locale"


class RecoveryError(Exception):
    pass


def reset_password(db: Session, username: str, new_password: str) -> User:
    """Set a new password, unlock the account and revoke every open session."""
    user = db.scalars(select(User).where(User.username == username)).first()
    if user is None:
        raise RecoveryError(f"Utilisateur introuvable : {username}")
    problems = validate_password_strength(new_password)
    if problems:
        raise RecoveryError("Mot de passe trop faible : " + ", ".join(problems))
    user.password_hash = hash_password(new_password)
    user.failed_logins, user.locked_until = 0, None
    user.token_version += 1
    audit.record(db, "auth.password_reset_local", actor=LOCAL_ACTOR, target_type="user", target_id=user.id,
                 details={"username": user.username})
    db.commit()
    return user


def run_cli(db: Session, username: str | None, out: TextIO, *, ask: Callable[[str], str] | None = None,
            ask_secret: Callable[[str], str] | None = None, attempts: int = 3) -> int:
    """Interactive flow. Returns a process exit code."""
    ask = ask or input
    ask_secret = ask_secret or getpass.getpass
    users = list(db.scalars(select(User).order_by(User.id)))
    if not users:
        print("Aucun compte : lancez MAKKADi pour créer le premier administrateur.", file=out)
        return 1
    if not username:
        print("Comptes existants :", file=out)
        for u in users:
            state = "" if u.is_active else " (désactivé)"
            print(f"  {u.username}  [{u.role.name}]{state}", file=out)
        username = ask("Identifiant à réinitialiser : ").strip()
    if not username:
        print("Aucun identifiant saisi.", file=out)
        return 1
    target = next((u for u in users if u.username == username), None)
    if target is None:
        print(f"Utilisateur introuvable : {username}", file=out)
        return 1
    for _ in range(attempts):
        first = ask_secret("Nouveau mot de passe : ")
        if first != ask_secret("Confirmez le mot de passe : "):
            print("Les deux saisies sont différentes.", file=out)
            continue
        try:
            reset_password(db, username, first)
        except RecoveryError as exc:
            print(str(exc), file=out)
            continue
        print(f"Mot de passe de « {username} » réinitialisé. Le compte est déverrouillé et les sessions ouvertes "
              "sont fermées.", file=out)
        if not target.is_active:
            print("Attention : ce compte est désactivé ; un administrateur doit le réactiver.", file=out)
        return 0
    print("Abandon après trop d'essais.", file=out)
    return 1
