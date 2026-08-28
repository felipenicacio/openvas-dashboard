"""
Utilitários de segurança — hashing de senha e geração de tokens.

Usa Argon2id (argon2-cffi) como algoritmo de hashing de senha.
Argon2id é a recomendação atual do NIST e OWASP ASVS v4.

Referências:
- OWASP ASVS v4.0 — §2.4 Credential Storage
- CWE-256: Plaintext Storage of a Password
- RFC 9106: Argon2 Memory-Hard Function
"""

import secrets
import uuid
import logging
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

log = logging.getLogger(__name__)

# Parâmetros Argon2id — conforme OWASP ASVS §2.4 e RFC 9106 §4
# time_cost=3, memory_cost=65536 (64 MB), parallelism=4
_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    """
    Gera hash Argon2id da senha fornecida.
    O salt é gerado aleatoriamente a cada chamada.
    """
    if not password:
        raise ValueError("Senha não pode ser vazia.")
    return _ph.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """
    Verifica senha em texto puro contra hash Argon2id.
    Retorna False silenciosamente em caso de falha.
    Usa comparação em tempo constante internamente.
    """
    if not plain or not hashed:
        return False
    try:
        return _ph.verify(hashed, plain)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:
        log.exception("Erro inesperado na verificação de senha")
        return False


def generate_jti() -> str:
    """Gera identificador único para o JWT (jti claim)."""
    return str(uuid.uuid4())


def generate_secret(bytes_length: int = 32) -> str:
    """Gera segredo criptograficamente seguro em hex."""
    return secrets.token_hex(bytes_length)


# ── Revogação de tokens (in-memory, single-process) ─────────────────────────
# Limitação documentada: não persiste entre reinicializações e não funciona
# com múltiplos workers. Para ambientes multi-processo ou HA, utilize Redis.
_revoked_jtis: set[str] = set()


def revoke_token(jti: str) -> None:
    """Adiciona jti ao conjunto de tokens revogados (logout)."""
    _revoked_jtis.add(jti)


def is_token_revoked(jti: str) -> bool:
    """Retorna True se o token foi explicitamente revogado."""
    return jti in _revoked_jtis
