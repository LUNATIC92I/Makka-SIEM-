from __future__ import annotations

from collections.abc import Callable

import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import Investigation, InvestigationAssignee, User
from app.security.tokens import decode_access_token

DbDep = Depends(get_db)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def get_current_user(request: Request, db: Session = DbDep) -> User:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentification requise", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = decode_access_token(header[7:].strip())
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Jeton invalide ou expiré") from exc
    user = db.get(User, int(claims["sub"]))
    if user is None or not user.is_active or user.token_version != claims.get("ver"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session révoquée")
    return user


def has_perm(user: User, perm: str) -> bool:
    return perm in (user.role.permissions or [])


def require(perm: str) -> Callable[..., User]:
    def dep(user: User = Depends(get_current_user)) -> User:
        if not has_perm(user, perm):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Permission insuffisante")
        return user

    return dep


def can_access_investigation(db: Session, user: User, inv: Investigation) -> bool:
    if not has_perm(user, "investigations:read"):
        return False
    if not inv.restricted or has_perm(user, "investigations:restricted") or inv.owner_id == user.id:
        return True
    return db.scalars(select(InvestigationAssignee).where(
        InvestigationAssignee.investigation_id == inv.id, InvestigationAssignee.user_id == user.id)).first() is not None


def load_investigation(db: Session, user: User, investigation_id: str) -> Investigation:
    inv = db.get(Investigation, investigation_id)
    # Same 404 for "missing" and "forbidden": no existence oracle on restricted cases.
    if inv is None or not can_access_investigation(db, user, inv):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation introuvable")
    return inv
