from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import DbDep, client_ip, require
from app.api.routes.auth import USERNAME_PATTERN
from app.models import Role, User
from app.schemas.serializers import user_out
from app.security.passwords import hash_password, validate_password_strength
from app.services import audit

router = APIRouter(prefix="/users", tags=["users"])


class UserIn(BaseModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    display_name: str = Field(default="", max_length=128)
    password: str = Field(max_length=256)
    role: str = Field(pattern=r"^(admin|analyst|viewer)$")


class UserPatch(BaseModel):
    display_name: str | None = Field(default=None, max_length=128)
    role: str | None = Field(default=None, pattern=r"^(admin|analyst|viewer)$")
    is_active: bool | None = None
    password: str | None = Field(default=None, max_length=256)


@router.get("")
def list_users(db: Session = DbDep, _: User = Depends(require("users:manage"))) -> list[dict]:
    return [user_out(u) for u in db.scalars(select(User).order_by(User.id))]


@router.get("/roles")
def list_roles(db: Session = DbDep, _: User = Depends(require("users:manage"))) -> list[dict]:
    return [{"name": r.name, "description": r.description, "permissions": r.permissions} for r in db.scalars(select(Role))]


@router.get("/directory")
def directory(db: Session = DbDep, _: User = Depends(require("investigations:write"))) -> list[dict]:
    """Minimal user list (for assignment)."""
    return [{"id": u.id, "username": u.username, "display_name": u.display_name}
            for u in db.scalars(select(User).where(User.is_active.is_(True)))]


@router.post("", status_code=201)
def create_user(body: UserIn, request: Request, db: Session = DbDep, admin: User = Depends(require("users:manage"))) -> dict:
    if db.scalars(select(User).where(User.username == body.username)).first():
        raise HTTPException(409, "Nom d'utilisateur déjà utilisé")
    problems = validate_password_strength(body.password)
    if problems:
        raise HTTPException(422, "Mot de passe trop faible : " + ", ".join(problems))
    role = db.scalars(select(Role).where(Role.name == body.role)).one()
    user = User(username=body.username, display_name=body.display_name or body.username,
                password_hash=hash_password(body.password), role_id=role.id)
    db.add(user)
    db.flush()
    audit.record(db, "user.created", actor=admin.username, actor_user_id=admin.id, target_type="user", target_id=user.id,
                 details={"username": user.username, "role": body.role}, client_ip=client_ip(request))
    db.commit()
    return user_out(user)


@router.patch("/{user_id}")
def update_user(user_id: int, body: UserPatch, request: Request, db: Session = DbDep,
                admin: User = Depends(require("users:manage"))) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "Utilisateur introuvable")
    changes: dict = {}
    if body.display_name is not None:
        user.display_name = changes["display_name"] = body.display_name
    if body.role is not None:
        if user.id == admin.id and body.role != "admin":
            raise HTTPException(400, "Impossible de retirer son propre rôle administrateur")
        user.role_id = db.scalars(select(Role).where(Role.name == body.role)).one().id
        changes["role"] = body.role
        user.token_version += 1
    if body.is_active is not None:
        if user.id == admin.id and not body.is_active:
            raise HTTPException(400, "Impossible de désactiver son propre compte")
        user.is_active = changes["is_active"] = body.is_active
        user.token_version += 1
    if body.password:
        problems = validate_password_strength(body.password)
        if problems:
            raise HTTPException(422, "Mot de passe trop faible : " + ", ".join(problems))
        user.password_hash = hash_password(body.password)
        user.token_version += 1
        changes["password"] = "reset"
    audit.record(db, "user.updated", actor=admin.username, actor_user_id=admin.id, target_type="user", target_id=user.id,
                 details=changes, client_ip=client_ip(request))
    db.commit()
    db.refresh(user)
    return user_out(user)
