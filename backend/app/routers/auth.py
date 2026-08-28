"""
Endpoints de autenticação — login, logout, perfil.

Segurança:
- Rate limiting: 5 tentativas/minuto por IP (in-memory, single-process)
- Senha verificada via Argon2id (nunca comparação em texto puro)
- Token entregue apenas via cookie HttpOnly (não no corpo da resposta)
- Mensagem de erro genérica (não revela se foi username ou password)
- Logging de autenticação: IP, username (sem senha)
- Logout revoga jti no conjunto in-memory
"""

import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, HTTPException, Request, Response, status, Depends

from ..auth import (
    CurrentUser,
    Role,
    clear_auth_cookie,
    create_token,
    set_auth_cookie,
)
from ..config import get_settings
from ..models.schemas import LoginRequest
from ..security import revoke_token, verify_password

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])
settings = get_settings()

# ── Rate limiter in-memory ────────────────────────────────────────────────────
# Limitação: não persiste entre reinicializações, não compartilhado entre workers.
# Para produção multi-processo, usar Redis/slowapi.

_AUTH_MAX_ATTEMPTS = 5
_AUTH_WINDOW_SECONDS = 60
_auth_attempts: dict[str, list[datetime]] = defaultdict(list)
_auth_lock = asyncio.Lock()


async def _check_rate_limit(ip: str) -> None:
    async with _auth_lock:
        now = datetime.now(tz=timezone.utc)
        cutoff = now - timedelta(seconds=_AUTH_WINDOW_SECONDS)
        _auth_attempts[ip] = [t for t in _auth_attempts[ip] if t > cutoff]
        if len(_auth_attempts[ip]) >= _AUTH_MAX_ATTEMPTS:
            log.warning("AUTH_RATE_LIMITED ip=%s", ip)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Muitas tentativas. Tente novamente em 60 segundos.",
                headers={"Retry-After": "60"},
            )
        _auth_attempts[ip].append(now)


def _get_client_ip(request: Request) -> str:
    """
    Extrai IP real do cliente via X-Real-IP (definido pelo nginx).

    Não usa X-Forwarded-For: o primeiro valor é controlável pelo cliente e pode ser
    forjado para contornar rate limiting. X-Real-IP é definido exclusivamente pelo
    nginx e reflete o IP da conexão TCP recebida pelo proxy.

    Em conexão direta (desenvolvimento), usa request.client.host.
    """
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/token", status_code=200)
async def login(
    request: Request,
    response: Response,
    body: LoginRequest,
):
    """
    Autentica e define cookie de sessão.
    Mensagem de erro genérica independente do campo inválido (OWASP ASVS §2.1).
    """
    ip = _get_client_ip(request)
    await _check_rate_limit(ip)

    _GENERIC_ERROR = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas.",
    )

    # Comparação de username em tempo constante
    import hmac
    username_ok = hmac.compare_digest(
        body.username.lower().encode(),
        settings.app_username.lower().encode(),
    )

    # Verificação de senha Argon2id — sempre executada (evita timing oracle)
    password_ok = verify_password(body.password, settings.app_password_hash)

    if not username_ok or not password_ok:
        log.warning(
            "AUTH_FAILED ip=%s username=%s",
            ip,
            body.username[:64],  # trunca para evitar log injection
        )
        raise _GENERIC_ERROR

    token = create_token(body.username, role=Role.ADMIN)
    set_auth_cookie(response, token)

    log.info("AUTH_SUCCESS ip=%s username=%s", ip, body.username[:64])

    return {"message": "Autenticado com sucesso."}


@router.post("/logout", status_code=200)
async def logout(
    request: Request,
    response: Response,
    user: CurrentUser,
):
    """Encerra a sessão: revoga jti e remove cookie."""
    revoke_token(user.jti)
    clear_auth_cookie(response)
    log.info("AUTH_LOGOUT ip=%s username=%s", _get_client_ip(request), user.username)
    return {"message": "Sessão encerrada."}


@router.get("/me", status_code=200)
async def me(user: CurrentUser):
    """Retorna informações mínimas do usuário autenticado."""
    return {
        "username": user.username,
        "role": user.role.value,
    }
