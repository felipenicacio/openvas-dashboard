"""
Configuração da aplicação — fail-secure.

Regras de inicialização:
- JWT_SECRET obrigatório, mínimo 32 chars, não pode ser o valor padrão de dev.
  Preferencial: systemd credential. Legado .env: DEPRECATED (removido na v1.3.0).
- APP_PASSWORD_HASH obrigatório (Argon2id), não armazenamos senha em claro.
- APP_USERNAME obrigatório, não pode ser vazio.
- GVM_USERNAME obrigatório.
- GVM_PASSWORD obrigatório independente do transporte (TLS ou socket Unix).
  Motivo: gvm_client.py sempre chama gmp.authenticate() via GMP protocol.
  Preferencial: systemd credential. Legado .env: DEPRECATED (removido na v1.3.0).
- A aplicação recusa inicialização se qualquer requisito não for atendido.
"""

import os
import stat
import sys
import logging
from functools import lru_cache
from pathlib import Path
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

_MAX_CREDENTIAL_BYTES = 4096


def resolve_secret(
    credential_name: str,
    legacy_env_value: Optional[str],
    legacy_env_name: str,
) -> str:
    """
    Resolve um secret de runtime com a seguinte precedência:

    1. systemd credential via CREDENTIALS_DIRECTORY (preferencial em produção)
    2. Variável de ambiente legada — deprecated, emite SECURITY WARNING
    3. Fail-secure: levanta ValueError se nenhuma fonte válida

    Regras de leitura de arquivo de credential:
    - Abrir diretamente (open) e verificar tipo via fstat — mitiga TOCTOU.
      Como os arquivos de credential são criados pelo systemd em runtime dir
      protegido, o risco TOCTOU é considerado baixo; a abordagem via fstat é
      uma camada adicional de defesa documentada (não substitui controles do SO).
    - Rejeitar qualquer objeto que não seja arquivo regular (diretório, socket, FIFO).
    - Ler no máximo _MAX_CREDENTIAL_BYTES + 1 bytes (evita carregar arquivo
      arbitrariamente grande em memória antes do check de tamanho).
    - Tratar PermissionError, OSError e UnicodeDecodeError com mensagens seguras
      (sem path completo, sem conteúdo do secret).
    - Rejeitar arquivo vazio após remoção de terminador de linha.
    - Remover exatamente UM terminador de linha final (LF ou CRLF).
      Um arquivo com dois newlines finais produz valor com \n interno — isso é
      tratado como erro de conteúdo (autenticação falha explicitamente), não
      silenciado. Nunca usar rstrip() genérico que pode ocultar corrupção.
    - Nunca logar o valor lido.

    Se credential E env var legada ambos presentes:
    - Usa credential, emite warning sobre env var ignorada (sem valores).
    """
    creds_dir = os.environ.get("CREDENTIALS_DIRECTORY", "")
    cred_value: Optional[str] = None
    cred_found = False

    if creds_dir:
        cred_path = Path(creds_dir) / credential_name

        try:
            f_obj = open(cred_path, "rb")  # noqa: WPS515
        except FileNotFoundError:
            pass  # Credential ausente — cai para legacy
        except PermissionError:
            raise ValueError(
                f"Sem permissão para abrir systemd credential '{credential_name}'. "
                f"Verifique as permissões do arquivo de credential."
            )
        except OSError as exc:
            raise ValueError(
                f"Erro ao abrir systemd credential '{credential_name}': "
                f"{type(exc).__name__}."
            )
        else:
            cred_found = True
            with f_obj:
                try:
                    fd_stat = os.fstat(f_obj.fileno())
                except OSError as exc:
                    raise ValueError(
                        f"Erro ao inspecionar systemd credential '{credential_name}': "
                        f"{type(exc).__name__}."
                    )
                if not stat.S_ISREG(fd_stat.st_mode):
                    raise ValueError(
                        f"systemd credential '{credential_name}' não é um arquivo regular "
                        f"(diretório, socket ou FIFO detectado)."
                    )
                # Ler MAX+1 bytes para detectar excesso sem carregar tudo na memória
                try:
                    raw_bytes = f_obj.read(_MAX_CREDENTIAL_BYTES + 1)
                except PermissionError:
                    raise ValueError(
                        f"Sem permissão para ler systemd credential '{credential_name}'. "
                        f"Verifique as permissões do arquivo de credential."
                    )
                except OSError as exc:
                    raise ValueError(
                        f"Erro ao ler systemd credential '{credential_name}': "
                        f"{type(exc).__name__}."
                    )

            if len(raw_bytes) > _MAX_CREDENTIAL_BYTES:
                raise ValueError(
                    f"systemd credential '{credential_name}' excede o limite de "
                    f"{_MAX_CREDENTIAL_BYTES} bytes."
                )

            try:
                raw_str = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError(
                    f"systemd credential '{credential_name}' contém bytes inválidos (não UTF-8)."
                )

            # Remover exatamente UM terminador de linha final (LF ou CRLF).
            # Nunca usar rstrip() que removeria múltiplos terminadores silenciosamente.
            if raw_str.endswith("\r\n"):
                value = raw_str[:-2]
            elif raw_str.endswith("\n"):
                value = raw_str[:-1]
            else:
                value = raw_str

            if not value:
                raise ValueError(
                    f"systemd credential '{credential_name}' está vazia."
                )
            cred_value = value

    has_legacy = bool(legacy_env_value)

    if cred_found and cred_value is not None:
        if has_legacy:
            log.warning(
                "systemd credential %s detected; legacy %s ignored.",
                credential_name,
                legacy_env_name,
            )
        return cred_value

    if has_legacy:
        log.warning(
            "SECURITY WARNING: Legacy %s environment variable is deprecated. "
            "Migrate to systemd credentials. Support will be removed in v1.3.0.",
            legacy_env_name,
        )
        return legacy_env_value  # type: ignore[return-value]

    raise ValueError(
        f"Secret '{credential_name}' não encontrado. "
        f"Configure via systemd credential (preferencial) ou variável de ambiente "
        f"{legacy_env_name} (deprecated, removido na v1.3.0). "
        f"Veja README.md -> Gerenciamento de Secrets."
    )


class Settings(BaseSettings):
    # ── GVM ───────────────────────────────────────────────────────────
    gvm_host: str = "127.0.0.1"
    gvm_port: int = 9390
    gvm_username: str = Field(default="", description="GVM admin username — obrigatório")
    # gvm_password agora é Optional — pode vir de systemd credential
    gvm_password: Optional[str] = Field(
        default=None,
        description="GVM admin password — DEPRECATED (v1.3.0): use systemd credential 'gvm_password'"
    )
    gvm_socket_path: str = ""

    # ── GVM TLS (obrigatório em modo remoto, i.e. quando gvm_socket_path vazio) ─
    gvm_tls_ca_file: Optional[str] = None
    gvm_tls_cert_file: Optional[str] = None
    gvm_tls_key_file: Optional[str] = None

    # ── App auth ──────────────────────────────────────────────────────
    app_username: str = Field(default="", description="Dashboard username — obrigatório")
    app_password_hash: str = Field(
        default="",
        description="Hash Argon2id da senha do dashboard — obrigatório. "
                    "Gere com: python generate_hash.py",
    )
    # Manter app_password apenas para compatibilidade de leitura; jamais usado como verdade
    app_password: str = Field(default="", exclude=True)

    # jwt_secret agora é Optional — pode vir de systemd credential
    jwt_secret: Optional[str] = Field(
        default=None,
        description="JWT signing secret — DEPRECATED (v1.3.0): use systemd credential 'jwt_secret'"
    )
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

    @property
    def resolved_gvm_password(self) -> str:
        """
        Resolve GVM password via systemd credential (preferencial) ou .env (deprecated).
        Nunca logar o valor retornado.
        GVM_PASSWORD é obrigatório independente do transporte (TLS ou socket Unix)
        pois gvm_client.py sempre chama gmp.authenticate() via protocolo GMP.
        """
        return resolve_secret(
            credential_name="gvm_password",
            legacy_env_value=self.gvm_password,
            legacy_env_name="GVM_PASSWORD",
        )

    @property
    def resolved_jwt_secret(self) -> str:
        """
        Resolve JWT secret via systemd credential (preferencial) ou .env (deprecated).
        Nunca logar o valor retornado.
        """
        return resolve_secret(
            credential_name="jwt_secret",
            legacy_env_value=self.jwt_secret,
            legacy_env_name="JWT_SECRET",
        )

    @model_validator(mode="after")
    def _validate_tls_remote(self) -> "Settings":
        """
        Em modo remoto (gvm_socket_path vazio), exige host, porta, credenciais
        e os três arquivos TLS (CA, certificado cliente, chave privada).
        Nunca loga senha, chave privada ou hash.
        """
        if self.gvm_socket_path:
            # Modo Unix socket — sem requisito TLS.
            return self

        errors: list[str] = []

        if not self.gvm_host:
            errors.append("GVM_HOST é obrigatório em modo remoto")
        if not (1 <= self.gvm_port <= 65535):
            errors.append(f"GVM_PORT deve ser 1-65535; recebido: {self.gvm_port}")
        if not self.gvm_username:
            errors.append("GVM_USERNAME é obrigatório em modo remoto")

        for env_name, value in [
            ("GVM_TLS_CA_FILE", self.gvm_tls_ca_file),
            ("GVM_TLS_CERT_FILE", self.gvm_tls_cert_file),
            ("GVM_TLS_KEY_FILE", self.gvm_tls_key_file),
        ]:
            if not value:
                errors.append(f"{env_name} é obrigatório em modo remoto")
            elif not Path(value).is_file():
                # Rejeita diretórios, sockets, FIFOs e qualquer objeto não-regular
                errors.append(
                    f"{env_name}: caminho não é um arquivo regular: {value}"
                )

        if errors:
            raise ValueError(
                "Configuração GVM TLS inválida para modo remoto:\n"
                + "\n".join(f"  • {e}" for e in errors)
            )
        return self

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
    Validações JWT são aplicadas ao valor RESOLVIDO (via systemd credential ou legacy env).
    """
    errors: list[str] = []

    # JWT_SECRET — validar o valor resolvido
    try:
        resolved_jwt = s.resolved_jwt_secret
        if resolved_jwt.lower() in _FORBIDDEN_SECRETS:
            errors.append(
                "jwt_secret contém valor inseguro padrão. "
                "Gere com: openssl rand -hex 32"
            )
        elif len(resolved_jwt) < 32:
            errors.append(
                f"jwt_secret muito curto ({len(resolved_jwt)} chars). Mínimo: 32 chars. "
                "Gere com: openssl rand -hex 32"
            )
        # Não logar o valor resolvido
    except ValueError as exc:
        errors.append(str(exc))

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

    # GVM_PASSWORD — obrigatório independente do modo de transporte.
    # Motivo: gvm_client.py sempre chama gmp.authenticate() via protocolo GMP,
    # independente de usar socket Unix ou TLS. O socket Unix altera apenas o
    # transporte de rede, não elimina a camada de autenticação GMP.
    try:
        s.resolved_gvm_password  # raises ValueError if not available
    except ValueError as exc:
        errors.append(str(exc))

    # CORS em produção — apenas aviso, não bloqueante.
    # Quando nginx serve frontend e /api no mesmo domínio (same-origin),
    # CORS_ORIGINS deve ficar vazio: nenhuma requisição cross-origin ocorre
    # e o CORSMiddleware não é adicionado. Definir apenas para deployments
    # onde frontend e API estão em origens distintas.
    if s.app_env.lower() == "production" and not s.cors_list:
        log.warning(
            "CORS_ORIGINS não definido — CORS cross-origin desabilitado. "
            "Correto para deployments same-origin (nginx). "
            "Defina CORS_ORIGINS apenas se frontend e API estiverem em origens distintas."
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
