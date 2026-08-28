"""
Configuração da aplicação — fail-secure.

Regras de inicialização:
- JWT_SECRET obrigatório, mínimo 32 chars, não pode ser o valor padrão de dev.
- APP_PASSWORD_HASH obrigatório (Argon2id), não armazenamos senha em claro.
- APP_USERNAME obrigatório, não pode ser vazio.
- GVM_USERNAME obrigatório quando integração GVM for usada.
- A aplicação recusa inicialização se qualquer requisito não for atendido.
"""

import sys
import logging
from functools import lru_cache
from typing import Optional
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings

log = logging.getLogger(__name__)

# Valores conhecidamente inseguros que não devem estar em produção
_FORBIDDEN_SECRETS = {
    "dev-secret-change-in-production",
    "dev-secret",
    "secret",
    "changeme",
    "password",
    "admin",
    "",
}


class Settings(BaseSettings):
    # ── GVM ───────────────────────────────────────────────────────────
    gvm_host: str = "127.0.0.1"
    gvm_port: int = 9390
    gvm_username: str = Field(default="", description="GVM admin username — obrigatório")
    gvm_password: str = Field(default="", description="GVM admin password — obrigatório sem socket")
    gvm_socket_path: str = ""

    # ── App auth ──────────────────────────────────────────────────────
    app_username: str = Field(default="", description="Dashboard username — obrigatório")
    app_password_hash: str = Field(
        default="",
        description="Hash Argon2id da senha do dashboard — obrigatório. "
                    "Gere com: python generate_hash.py",
    )
    # Manter app_password apenas para compatibilidade de leitura; jamais usado como verdade
    app_password: str = Field(default="", exclude=True)

    jwt_secret: str = Field(default="", description="JWT signing secret — mínimo 32 chars, obrigatório")
    jwt_expire_minutes: int = Field(default=30, ge=5, le=1440)
    jwt_issuer: str = "openvas-dashboard"
    jwt_audience: str = "openvas-dashboard-ui"

    # ── Feature flags ─────────────────────────────────────────────────
    enable_api_docs: bool = False
    app_env: str = "production"          # production | development
    cookie_secure: bool = True           # False apenas em development

    # ── Sync ──────────────────────────────────────────────────────────
    sync_interval_minutes: int = 30

    # ── Dados ─────────────────────────────────────────────────────────
    data_dir: str = "/opt/openvas-dashboard/data"

    # ── CORS ─────────────────────────────────────────────────────────
    cors_origins: str = ""

    @property
    def cors_list(self) -> list[str]:
        if not self.cors_origins.strip():
            return []
        origins = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
        for origin in origins:
            if origin == "*":
                raise ValueError(
                    "CORS_ORIGINS não pode ser wildcard '*' quando credentials estão habilitados."
                )
        return origins

    @property
    def is_development(self) -> bool:
        return self.app_env.lower() == "development"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
    }


def _fail(msg: str) -> None:
    """Encerra a aplicação com mensagem de erro clara."""
    log.critical("STARTUP FAILED — %s", msg)
    print(f"\n[ERRO CRÍTICO] {msg}\n", file=sys.stderr)
    sys.exit(1)


def validate_settings(s: Settings) -> None:
    """
    Valida requisitos de segurança obrigatórios.
    Encerra a aplicação se qualquer requisito não for atendido.
    """
    errors: list[str] = []

    # JWT_SECRET
    if not s.jwt_secret:
        errors.append(
            "JWT_SECRET não definido. Gere com: openssl rand -hex 32"
        )
    elif s.jwt_secret.lower() in _FORBIDDEN_SECRETS:
        errors.append(
            "JWT_SECRET contém valor inseguro padrão. "
            "Gere com: openssl rand -hex 32"
        )
    elif len(s.jwt_secret) < 32:
        errors.append(
            f"JWT_SECRET muito curto ({len(s.jwt_secret)} chars). Mínimo: 32 chars. "
            "Gere com: openssl rand -hex 32"
        )

    # APP_USERNAME
    if not s.app_username.strip():
        errors.append("APP_USERNAME não definido.")

    # APP_PASSWORD_HASH — deve estar definido
    if not s.app_password_hash.strip():
        errors.append(
            "APP_PASSWORD_HASH não definido. "
            "Gere com: python generate_hash.py"
        )
    elif not s.app_password_hash.startswith("$argon2"):
        errors.append(
            "APP_PASSWORD_HASH não é um hash Argon2id válido. "
            "Gere com: python generate_hash.py"
        )

    # GVM_USERNAME
    if not s.gvm_username.strip():
        errors.append("GVM_USERNAME não definido.")

    # GVM_PASSWORD (obrigatório quando não usa socket)
    if not s.gvm_socket_path and not s.gvm_password:
        errors.append(
            "GVM_PASSWORD não definido e GVM_SOCKET_PATH também não. "
            "Defina ao menos um dos dois."
        )

    # CORS em produção (não validado em development/test)
    if s.app_env.lower() == "production" and not s.cors_list:
        errors.append(
            "CORS_ORIGINS não definido. "
            "Exemplo: CORS_ORIGINS=https://dashboard.sua-empresa.com"
        )

    if errors:
        msg = "Configuração inválida para produção:\n" + "\n".join(
            f"  • {e}" for e in errors
        )
        _fail(msg)

    # Avisos não bloqueantes
    if s.app_username.lower() == "admin":
        log.warning("SECURITY WARNING: APP_USERNAME='admin' é previsível. Considere usar outro nome.")
    if s.is_development:
        log.warning("SECURITY WARNING: APP_ENV=development — não use em produção.")
    if not s.cookie_secure:
        log.warning("SECURITY WARNING: COOKIE_SECURE=false — cookies não serão Secure.")


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    validate_settings(s)
    return s
