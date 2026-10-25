from __future__ import annotations

import ipaddress
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import DbDep, client_ip, get_current_user
from app.core.config import get_settings
from app.core.timeutil import utc_now
from app.models import Role, User
from app.schemas.serializers import user_out
from app.security.passwords import dummy_verify, hash_password, validate_password_strength, verify_password
from app.security.tokens import create_access_token
from app.services import audit

router = APIRouter(prefix="/auth", tags=["auth"])
USERNAME_PATTERN = r"^[a-zA-Z0-9._-]{3,64}$"


class Credentials(BaseModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    password: str = Field(min_length=1, max_length=256)


class BootstrapIn(Credentials):
    display_name: str = Field(default="", max_length=128)


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


@router.get("/setup-status")
def setup_status(db: Session = DbDep) -> dict:
    return {"needs_setup": (db.scalar(select(func.count()).select_from(User)) or 0) == 0}


@router.post("/bootstrap", status_code=201)
def bootstrap_admin(body: BootstrapIn, request: Request, db: Session = DbDep) -> dict:
    """Create the first administrator. Only possible when no user exists, from the local machine."""
    if db.scalar(select(func.count()).select_from(User)):
        raise HTTPException(status.HTTP_409_CONFLICT, "L'application est déjà initialisée")
    ip = client_ip(request)
    try:
        local = ipaddress.ip_address(ip).is_loopback
    except ValueError:
        local = ip in ("testclient", "localhost")
    if not local:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Initialisation autorisée uniquement depuis le poste local")
    problems = validate_password_strength(body.password)
    if problems:
        raise HTTPException(422, "Mot de passe trop faible : " + ", ".join(problems))
    role = db.scalars(select(Role).where(Role.name == "admin")).one()
    user = User(username=body.username, display_name=body.display_name or body.username,
                password_hash=hash_password(body.password), role_id=role.id)
    db.add(user)
    db.flush()
    audit.record(db, "auth.bootstrap", actor=user.username, actor_user_id=user.id, client_ip=ip)
    db.commit()
    return user_out(user)


@router.post("/login")
def login(body: Credentials, request: Request, db: Session = DbDep) -> dict:
    s = get_settings()
    ip = client_ip(request)
    user = db.scalars(select(User).where(User.username == body.username)).first()
    now = utc_now()
    if user is None:
        dummy_verify()
        audit.record(db, "auth.login_failed", actor=body.username, client_ip=ip, details={"reason": "unknown_user"})
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Identifiants invalides")
    if user.locked_until and user.locked_until > now:
        audit.record(db, "auth.login_locked", actor=user.username, actor_user_id=user.id, client_ip=ip)
        db.commit()
        raise HTTPException(status.HTTP_423_LOCKED, "Compte temporairement verrouillé")
    if not user.is_active or not verify_password(body.password, user.password_hash):
        user.failed_logins += 1
        if user.failed_logins >= s.max_failed_logins:
            user.locked_until = now + timedelta(minutes=s.lockout_minutes)
            user.failed_logins = 0
        audit.record(db, "auth.login_failed", actor=user.username, actor_user_id=user.id, client_ip=ip)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Identifiants invalides")
    user.failed_logins, user.locked_until, user.last_login_at = 0, None, now
    token, ttl = create_access_token(user.id, user.token_version)
    audit.record(db, "auth.login", actor=user.username, actor_user_id=user.id, client_ip=ip)
    db.commit()
    return {"access_token": token, "token_type": "bearer", "expires_in": ttl, "user": user_out(user)}


@router.get("/me")
def me(user: User = Depends(get_current_user)) -> dict:
    return user_out(user)


@router.post("/logout")
def logout(request: Request, user: User = Depends(get_current_user), db: Session = DbDep) -> dict:
    user = db.get(User, user.id)
    user.token_version += 1  # revokes every token issued so far
    audit.record(db, "auth.logout", actor=user.username, actor_user_id=user.id, client_ip=client_ip(request))
    db.commit()
    return {"ok": True}


@router.post("/change-password")
def change_password(body: PasswordChange, request: Request, user: User = Depends(get_current_user), db: Session = DbDep) -> dict:
    user = db.get(User, user.id)
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Mot de passe actuel incorrect")
    problems = validate_password_strength(body.new_password)
    if problems:
        raise HTTPException(422, "Mot de passe trop faible : " + ", ".join(problems))
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1
    audit.record(db, "auth.password_changed", actor=user.username, actor_user_id=user.id, client_ip=client_ip(request))
    db.commit()
    return {"ok": True}
