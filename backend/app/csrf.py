"""
CSRF — proteção via validação de Origin/Referer.

Estratégia: verifica header Origin (ou Referer como fallback) em toda requisição
mutante (POST, PUT, PATCH, DELETE) sobre caminhos /api/*, exceto o endpoint de
login (/api/auth/token), que não possui cookie de sessão pré-existente para proteger.

Referência:
  - OWASP CSRF Prevention Cheat Sheet — "Verifying Origin With Standard Headers"
  - https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

Limitações documentadas:
  - Não protege contra CSRF em login (login CSRF). Mitigação: SameSite=Strict no cookie.
  - Ambientes de desenvolvimento com múltiplas origens locais ignoram a verificação
    quando BYPASS_CSRF_FOR_DEV=true (nunca usar em produção).
"""

import logging
from urllib.parse import urlparse

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

log = logging.getLogger(__name__)

# Métodos que alteram estado — exigem validação de origem
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Endpoints isentos da verificação CSRF:
# - /api/auth/token: login público (sem cookie de sessão a proteger)
_CSRF_EXEMPT_PATHS = frozenset({
    "/api/auth/token",
})


def _extract_host(header_value: str) -> str | None:
    """Extrai host (scheme+netloc) de um header Origin ou Referer."""
    if not header_value:
        return None
    try:
        parsed = urlparse(header_value)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        pass
    return None


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    Valida Origin/Referer em requisições mutantes para /api/*.

    O header Origin é enviado pelo browser em requisições cross-origin e,
    dependendo do browser e contexto (XHR vs fetch), também em same-origin.
    O Referer é usado como fallback quando Origin está ausente.

    Em produção: aceita origens na lista configurada (CORS_ORIGINS) mais o
    próprio host da requisição (same-origin). Requisições sem Origin nem Referer
    são bloqueadas como não verificáveis. Em desenvolvimento a verificação é
    permissiva para facilitar o desenvolvimento local.
    """

    def __init__(self, app, allowed_origins: list[str], is_development: bool = False):
        super().__init__(app)
        self._allowed_origins = set(allowed_origins)
        self._is_development = is_development

    async def dispatch(self, request: Request, call_next) -> Response:
        # Aplica apenas a métodos mutantes em /api/*
        if request.method not in _MUTATING_METHODS:
            return await call_next(request)
        if not request.url.path.startswith("/api/"):
            return await call_next(request)
        if request.url.path in _CSRF_EXEMPT_PATHS:
            return await call_next(request)

        # Em desenvolvimento, avisa mas não bloqueia
        if self._is_development:
            return await call_next(request)

        origin = request.headers.get("Origin")
        referer = request.headers.get("Referer")

        # Determina a origem esperada a partir do host da requisição
        host = request.headers.get("Host", "")
        scheme = "https"  # produção sempre HTTPS
        expected_origin = f"{scheme}://{host}" if host else None

        # Origens aceitáveis: host da requisição + origens configuradas explicitamente
        acceptable: set[str] = set()
        if expected_origin:
            acceptable.add(expected_origin)
        acceptable |= self._allowed_origins

        request_source = origin or _extract_host(referer or "")

        if request_source is None:
            # Sem Origin nem Referer: bloqueia requisições de contextos não-browser
            # que tentam mutações. Browsers sempre enviam Origin em cross-origin.
            # Em same-origin com SameSite=Strict este caminho é improvável.
            log.warning(
                "CSRF_BLOCKED method=%s path=%s — sem Origin nem Referer",
                request.method, request.url.path,
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "Requisição bloqueada: origem não verificável."},
            )

        if request_source not in acceptable:
            log.warning(
                "CSRF_BLOCKED method=%s path=%s origin=%s acceptable=%s",
                request.method, request.url.path, request_source, acceptable,
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "Requisição bloqueada: origem não autorizada."},
            )

        return await call_next(request)
