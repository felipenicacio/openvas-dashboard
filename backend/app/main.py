"""
FastAPI application factory — OpenVAS Dashboard v1.1.0

Mudanças de segurança em v1.1.0:
- CORS restrito: sem wildcard, apenas origins configuradas
- Documentação Swagger/OpenAPI desabilitada por padrão (ENABLE_API_DOCS=false)
- Security headers middleware adicionado
- /api/health retorna apenas {"status":"ok","version":"1.1.0"}
- Logging configurado para não registrar segredos
"""

import logging
import logging.config
from contextlib import asynccontextmanager

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from .config import get_settings
from .csrf import CSRFMiddleware
from .database import init_db
from .sync import run_sync

from .routers import auth, dashboard, vulnerabilities, hosts, scans, reports

settings = get_settings()

# ── Logging ───────────────────────────────────────────────────────────────────
# Nunca logar: senhas, tokens JWT, cookies de sessão, segredos

logging.config.dictConfig({
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s %(levelname)-8s %(name)s — %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
        }
    },
    "root": {"level": "INFO", "handlers": ["console"]},
    "loggers": {
        "uvicorn.access": {"level": "WARNING"},  # evita log de todos requests
        "apscheduler": {"level": "WARNING"},
    },
})

log = logging.getLogger(__name__)

# ── Scheduler ─────────────────────────────────────────────────────────────────
scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    log.info("OpenVAS Dashboard v1.1.0 iniciando (env=%s)", settings.app_env)

    scheduler.add_job(
        run_sync,
        "interval",
        minutes=settings.sync_interval_minutes,
        id="auto_sync",
        replace_existing=True,
    )
    scheduler.start()
    log.info("Scheduler iniciado (intervalo=%d min)", settings.sync_interval_minutes)

    yield

    scheduler.shutdown(wait=False)
    log.info("Scheduler encerrado.")


# ── Security headers middleware ────────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adiciona security headers em todas as respostas.
    CSP configurada para aplicação React + Recharts (Vite build).
    Referência: OWASP Secure Headers Project.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # X-Content-Type-Options — previne MIME sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # X-Frame-Options — previne clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Referrer-Policy — limita informações no Referer
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions-Policy — desabilita features não utilizadas
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )

        # Content-Security-Policy — restrita para React SPA (Vite build)
        # - script-src 'self': apenas scripts do próprio domínio (Vite gera .js separados)
        # - style-src 'self' 'unsafe-inline': Tailwind pode usar inline styles
        # - img-src 'self' data:: ícones inline via data URI
        # - connect-src 'self': Axios chama /api/* no mesmo domínio
        # - frame-ancestors 'none': previne clickjacking (complementa X-Frame-Options)
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

        return response


# ── App factory ───────────────────────────────────────────────────────────────

# Swagger/OpenAPI exposto apenas quando explicitamente habilitado
_docs_url    = "/api/docs"      if settings.enable_api_docs else None
_redoc_url   = "/api/redoc"     if settings.enable_api_docs else None
_openapi_url = "/api/openapi.json" if settings.enable_api_docs else None

if settings.enable_api_docs:
    log.warning("SECURITY WARNING: API docs habilitada (ENABLE_API_DOCS=true). Desabilite em produção.")

app = FastAPI(
    title="OpenVAS Dashboard",
    version="1.1.0",
    docs_url=_docs_url,
    redoc_url=_redoc_url,
    openapi_url=_openapi_url,
    lifespan=lifespan,
)

# CORS — adicionado apenas quando há origens explicitamente configuradas.
# Em deployments same-origin (nginx serve frontend e /api no mesmo domínio),
# CORS_ORIGINS deve ficar vazio: nenhum cross-origin request ocorre e o
# CORSMiddleware não precisa ser ativado.
cors_origins = settings.cors_list
if not cors_origins and settings.is_development:
    cors_origins = ["http://localhost:5173", "http://localhost:3000"]
    log.warning("SECURITY WARNING: CORS em modo desenvolvimento — %s", cors_origins)

if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,           # necessário para cookies
        allow_methods=["GET", "POST"],    # apenas métodos utilizados
        allow_headers=["Content-Type"],   # apenas headers necessários
    )
else:
    log.info("CORS cross-origin desabilitado (same-origin deployment).")

app.add_middleware(SecurityHeadersMiddleware)

# CSRF — valida Origin/Referer em requisições mutantes para /api/*
# Isenção: /api/auth/token (login público, sem cookie pré-existente)
app.add_middleware(
    CSRFMiddleware,
    allowed_origins=cors_origins,
    is_development=settings.is_development,
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(vulnerabilities.router)
app.include_router(hosts.router)
app.include_router(scans.router)
app.include_router(reports.router)


# ── Health check ─────────────────────────────────────────────────────────────
# Público — retorna apenas status mínimo (sem detalhes de infra)
@app.get("/api/health", tags=["system"])
async def health():
    return {"status": "ok", "version": "1.1.0"}
