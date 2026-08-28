"""
Autenticação e autorização JWT — cookie-based, HttpOnly.

Mudanças em relação à v1.0:
- Tokens armazenados em cookie HttpOnly/Secure/SameSite=Strict (não localStorage)
- Claims JWT completos: sub, exp, iat, nbf, iss, aud, jti, role
- Validação explícita de issuer e audience
- Rejeição de algoritmo inesperado (algorithms whitelist)
- RBAC: papéis VIEWER, ANALYST, ADMIN embutidos no token
- Revogação simples via jti (in-memory, single-process)

Referências:
- OWASP ASVS v4.0 — §3.2 Session Token Requirements
- OWASP Top 10 2021 — A07 Identification and Authentication Failures
- RFC 7519: JSON Web Token
"""

import logging
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Annotated, Optional
from dataclasses import dataclass

from fastapi import Cookie, Depends, HTTPException, Response, status
import jwt as _jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from .config import get_settings
from .security import generate_jti, is_token_revoked

log = logging.getLogger(__name__)
settings = get_settings()

COOKIE_NAME = "session"
ALGORITHM = "HS256"


# ── RBAC ─────────────────────────────────────────────────────────────────────

class Role(str, Enum):
    VIEWER  = "viewer"
    ANALYST = "analyst"
    ADMIN   = "admin"


# Hierarquia numérica para comparação de níveis
_ROLE_LEVEL: dict[Role, int] = {
    Role.VIEWER:  0,
    Role.ANALYST: 1,
    Role.ADMIN:   2,
}


@dataclass
class AuthUser:
    username: str
    role: Role
    jti: str


# ── Token creation ────────────────────────────────────────────────────────────

def create_token(username: str, role: Role = Role.ADMIN) -> str:
    """
    Cria JWT com claims completos conforme RFC 7519 e OWASP ASVS §3.5.
    """
    now = datetime.now(tz=timezone.utc)
    jti = generate_jti()
    payload = {
        "sub": username,
        "role": role.value,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=settings.jwt_expire_minutes),
        "jti": jti,
    }
    return _jwt.encode(payload, settings.resolved_jwt_secret, algorithm=ALGORITHM)


def set_auth_cookie(response: Response, token: str) -> None:
    """Define o cookie de sessão HttpOnly com todos os atributos de segurança."""
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/api",
        max_age=settings.jwt_expire_minutes * 60,
    )


def clear_auth_cookie(response: Response) -> None:
    """Remove o cookie de sessão (logout)."""
    response.delete_cookie(
        key=COOKIE_NAME,
        path="/api",
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
    )


# ── Token verification ────────────────────────────────────────────────────────

def _decode_token(token: str) -> dict:
    """
    Decodifica e valida JWT.
    Rejeita algoritmo inesperado, issuer inválido, audience inválida,
    tokens expirados e tokens revogados.
    """
    try:
        payload = _jwt.decode(
            token,
            settings.resolved_jwt_secret,
            algorithms=[ALGORITHM],          # whitelist explícita — rejeita outros algos
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["sub", "exp", "iat", "iss", "aud", "jti"]},
        )
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão expirada.",
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão inválida.",
        )

    jti = payload.get("jti", "")
    if is_token_revoked(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão encerrada.",
        )

    return payload


async def get_current_user(
    session: Optional[str] = Cookie(None, alias=COOKIE_NAME),
) -> AuthUser:
    """Dependency FastAPI: extrai e valida usuário do cookie de sessão."""
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticação necessária.",
        )

    payload = _decode_token(session)

    username: str = payload.get("sub", "")
    role_str: str = payload.get("role", Role.VIEWER.value)
    jti: str = payload.get("jti", "")

    try:
        role = Role(role_str)
    except ValueError:
        role = Role.VIEWER

    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão inválida.",
        )

    return AuthUser(username=username, role=role, jti=jti)


# ── RBAC dependencies ─────────────────────────────────────────────────────────

def require_role(min_role: Role):
    """
    Factory de dependency FastAPI que exige papel mínimo.

    Uso:
        @router.post("/admin-action")
        async def action(user: Annotated[AuthUser, Depends(require_role(Role.ADMIN))]):
            ...
    """
    async def dependency(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if _ROLE_LEVEL[user.role] < _ROLE_LEVEL[min_role]:
            log.warning(
                "AUTHZ_DENIED user=%s role=%s required=%s",
                user.username, user.role.value, min_role.value,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permissão insuficiente.",
            )
        return user
    return dependency


# ── Convenience type aliases ──────────────────────────────────────────────────

CurrentUser   = Annotated[AuthUser, Depends(get_current_user)]
RequireViewer  = Annotated[AuthUser, Depends(require_role(Role.VIEWER))]
RequireAnalyst = Annotated[AuthUser, Depends(require_role(Role.ANALYST))]
RequireAdmin   = Annotated[AuthUser, Depends(require_role(Role.ADMIN))]
