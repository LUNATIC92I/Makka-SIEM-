from __future__ import annotations

import bcrypt

MIN_PASSWORD_LENGTH = 12


def validate_password_strength(password: str) -> list[str]:
    problems: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"au moins {MIN_PASSWORD_LENGTH} caractères")
    if not any(c.islower() for c in password) or not any(c.isupper() for c in password):
        problems.append("majuscules et minuscules")
    if not any(c.isdigit() for c in password):
        problems.append("au moins un chiffre")
    if len(password.encode()) > 72:
        problems.append("72 octets maximum")
    return problems


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode()[:72], password_hash.encode())
    except ValueError:
        return False


# Constant-time dummy check to limit username enumeration through timing.
_DUMMY_HASH = bcrypt.hashpw(b"makkadi-dummy-password", bcrypt.gensalt(rounds=12)).decode()


def dummy_verify() -> None:
    verify_password("not-the-password", _DUMMY_HASH)
