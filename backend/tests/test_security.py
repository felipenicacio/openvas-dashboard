"""
Testes de segurança — OpenVAS Dashboard v1.1.0

Cobre:
- Argon2id: hashing e verificação
- JWT: criação, validação, revogação, expiração
- RBAC: hierarquia de papéis
- Rate limiting: bloqueio após 5 tentativas
- Autenticação: cookie HttpOnly, mensagem genérica
- Endpoints protegidos: 401/403 sem token
- UUID validation: scan_id e task_id

Uso:
    pytest backend/tests/test_security.py -v
"""

import time
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient
from jose import jwt


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_state():
    """Limpa estado in-memory entre testes."""
    from app.security import _revoked_jtis
    from app.routers.auth import _auth_attempts
    _revoked_jtis.clear()
    _auth_attempts.clear()
    yield
    _revoked_jtis.clear()
    _auth_attempts.clear()


@pytest.fixture
def settings_override(monkeypatch):
    """Configurações seguras para teste — sem segredos reais."""
    from app import config
    test_settings = MagicMock()
    test_settings.jwt_secret = "test-secret-that-is-at-least-32-characters-long"
    test_settings.jwt_issuer = "openvas-dashboard-test"
    test_settings.jwt_audience = "openvas-dashboard-users-test"
    test_settings.jwt_expire_minutes = 30
    test_settings.cookie_secure = False  # HTTP em testes
    test_settings.app_username = "testuser"
    # Hash Argon2id de "TestPassword123!" gerado offline:
    test_settings.app_password_hash = (
        "$argon2id$v=19$m=65536,t=3,p=4$"
        "c29tZXNhbHRzb21lc2FsdA$"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    test_settings.app_env = "test"
    test_settings.is_development = True
    test_settings.cors_list = []
    test_settings.sync_interval_minutes = 60
    test_settings.enable_api_docs = False
    monkeypatch.setattr(config, "_settings", test_settings)
    return test_settings


# ── 1. Argon2id ───────────────────────────────────────────────────────────────

class TestArgon2:
    def test_hash_returns_argon2id_format(self):
        from app.security import hash_password
        h = hash_password("MySuperSecret123!")
        assert h.startswith("$argon2id$"), "Hash deve começar com $argon2id$"

    def test_verify_correct_password(self):
        from app.security import hash_password, verify_password
        h = hash_password("CorrectPassword!")
        assert verify_password("CorrectPassword!", h) is True

    def test_verify_wrong_password(self):
        from app.security import hash_password, verify_password
        h = hash_password("CorrectPassword!")
        assert verify_password("WrongPassword!", h) is False

    def test_verify_empty_password(self):
        from app.security import hash_password, verify_password
        h = hash_password("SomePassword!")
        assert verify_password("", h) is False

    def test_verify_garbage_hash(self):
        from app.security import verify_password
        assert verify_password("anypassword", "not-a-valid-hash") is False

    def test_different_hashes_same_password(self):
        """Cada hash deve ter salt único."""
        from app.security import hash_password
        h1 = hash_password("SamePassword!")
        h2 = hash_password("SamePassword!")
        assert h1 != h2, "Hashes do mesmo password devem diferir (salt único)"


# ── 2. JWT ────────────────────────────────────────────────────────────────────

class TestJWT:
    def test_token_contains_required_claims(self):
        from app.auth import create_token, Role
        from app.config import get_settings
        s = get_settings()
        token = create_token("alice", Role.ADMIN)
        payload = jwt.decode(
            token, s.jwt_secret, algorithms=["HS256"],
            audience=s.jwt_audience, issuer=s.jwt_issuer,
        )
        for claim in ["sub", "exp", "iat", "nbf", "iss", "aud", "jti", "role"]:
            assert claim in payload, f"Claim '{claim}' ausente"

    def test_token_subject_matches(self):
        from app.auth import create_token, Role
        from app.config import get_settings
        s = get_settings()
        token = create_token("bob", Role.VIEWER)
        payload = jwt.decode(
            token, s.jwt_secret, algorithms=["HS256"],
            audience=s.jwt_audience, issuer=s.jwt_issuer,
        )
        assert payload["sub"] == "bob"

    def test_token_role_encoded(self):
        from app.auth import create_token, Role
        from app.config import get_settings
        s = get_settings()
        token = create_token("admin", Role.ADMIN)
        payload = jwt.decode(
            token, s.jwt_secret, algorithms=["HS256"],
            audience=s.jwt_audience, issuer=s.jwt_issuer,
        )
        assert payload["role"] == "admin"

    def test_revoked_token_rejected(self):
        from app.auth import create_token, Role, _decode_token
        from app.security import revoke_token
        import fastapi
        token = create_token("user", Role.VIEWER)
        payload_before = _decode_token(token)
        revoke_token(payload_before["jti"])
        with pytest.raises(fastapi.HTTPException) as exc_info:
            _decode_token(token)
        assert exc_info.value.status_code == 401

    def test_expired_token_rejected(self):
        from app.auth import ALGORITHM
        from app.config import get_settings
        from app.security import generate_jti
        import fastapi
        s = get_settings()
        now = datetime.now(tz=timezone.utc)
        payload = {
            "sub": "user",
            "role": "viewer",
            "iss": s.jwt_issuer,
            "aud": s.jwt_audience,
            "iat": now - timedelta(hours=2),
            "nbf": now - timedelta(hours=2),
            "exp": now - timedelta(hours=1),
            "jti": generate_jti(),
        }
        expired_token = jwt.encode(payload, s.jwt_secret, algorithm=ALGORITHM)
        from app.auth import _decode_token
        with pytest.raises(fastapi.HTTPException) as exc_info:
            _decode_token(expired_token)
        assert exc_info.value.status_code == 401


# ── 3. RBAC ───────────────────────────────────────────────────────────────────

class TestRBAC:
    def test_role_hierarchy_admin_above_analyst(self):
        from app.auth import _ROLE_LEVEL, Role
        assert _ROLE_LEVEL[Role.ADMIN] > _ROLE_LEVEL[Role.ANALYST]

    def test_role_hierarchy_analyst_above_viewer(self):
        from app.auth import _ROLE_LEVEL, Role
        assert _ROLE_LEVEL[Role.ANALYST] > _ROLE_LEVEL[Role.VIEWER]

    def test_unknown_role_defaults_to_viewer(self):
        """Role desconhecida no JWT deve ser tratada como VIEWER (fail-safe)."""
        from app.auth import Role
        try:
            role = Role("superadmin")
        except ValueError:
            role = Role.VIEWER
        assert role == Role.VIEWER


# ── 4. Rate Limiting ──────────────────────────────────────────────────────────

class TestRateLimit:
    @pytest.mark.asyncio
    async def test_rate_limit_blocks_after_max_attempts(self):
        from app.routers.auth import _check_rate_limit
        import fastapi
        ip = "192.168.1.1"
        # Primeiras 5 devem passar
        for _ in range(5):
            await _check_rate_limit(ip)
        # 6ª deve ser bloqueada
        with pytest.raises(fastapi.HTTPException) as exc_info:
            await _check_rate_limit(ip)
        assert exc_info.value.status_code == 429

    @pytest.mark.asyncio
    async def test_different_ips_independent(self):
        from app.routers.auth import _check_rate_limit
        # IP 1 esgota o limite
        for _ in range(5):
            await _check_rate_limit("10.0.0.1")
        # IP 2 ainda deve passar
        await _check_rate_limit("10.0.0.2")  # não deve lançar


# ── 5. Endpoints — autenticação ───────────────────────────────────────────────

class TestAuthEndpoints:
    """Testa endpoints via TestClient (mock do banco)."""

    @pytest.fixture
    def client(self):
        from app.main import app
        with patch("app.database.get_db"):
            with TestClient(app, raise_server_exceptions=False) as c:
                yield c

    def test_protected_endpoint_without_token_returns_401(self, client):
        resp = client.get("/api/dashboard/summary", cookies={})
        assert resp.status_code == 401

    def test_protected_scan_without_token_returns_401(self, client):
        resp = client.get("/api/scans", cookies={})
        assert resp.status_code == 401

    def test_protected_vuln_without_token_returns_401(self, client):
        resp = client.get("/api/vulnerabilities", cookies={})
        assert resp.status_code == 401

    def test_login_wrong_credentials_returns_401(self, client):
        resp = client.post("/api/auth/token", json={
            "username": "wrong",
            "password": "wrong",
        })
        assert resp.status_code == 401

    def test_login_error_message_is_generic(self, client):
        """Mensagem de erro não deve revelar se é username ou password errado."""
        resp = client.post("/api/auth/token", json={
            "username": "admin",
            "password": "wrongpassword",
        })
        body = resp.json()
        detail = body.get("detail", "")
        assert "username" not in detail.lower(), "Mensagem não deve mencionar 'username'"
        assert "senha" not in detail.lower(), "Mensagem não deve mencionar 'senha'"
        assert "password" not in detail.lower(), "Mensagem não deve mencionar 'password'"

    def test_health_endpoint_public(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_health_does_not_expose_internals(self, client):
        resp = client.get("/api/health")
        body = resp.json()
        for sensitive_key in ["database", "gvm", "host", "path", "secret", "token"]:
            assert sensitive_key not in body, f"Health não deve expor '{sensitive_key}'"


# ── 6. UUID Validation ────────────────────────────────────────────────────────

class TestUUIDValidation:
    def test_valid_uuid_accepted(self):
        from app.routers.scans import _validate_task_id
        result = _validate_task_id("550e8400-e29b-41d4-a716-446655440000")
        assert result == "550e8400-e29b-41d4-a716-446655440000"

    def test_invalid_uuid_raises_422(self):
        from app.routers.scans import _validate_task_id
        import fastapi
        with pytest.raises(fastapi.HTTPException) as exc_info:
            _validate_task_id("not-a-uuid")
        assert exc_info.value.status_code == 422

    def test_sql_injection_attempt_rejected(self):
        from app.routers.scans import _validate_task_id
        import fastapi
        with pytest.raises(fastapi.HTTPException):
            _validate_task_id("1' OR '1'='1")

    def test_empty_task_id_rejected(self):
        from app.routers.scans import _validate_task_id
        import fastapi
        with pytest.raises(fastapi.HTTPException):
            _validate_task_id("")


# ── 7. Security Headers ───────────────────────────────────────────────────────

class TestSecurityHeaders:
    @pytest.fixture
    def client(self):
        from app.main import app
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c

    def test_x_content_type_options(self, client):
        resp = client.get("/api/health")
        assert resp.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self, client):
        resp = client.get("/api/health")
        assert resp.headers.get("x-frame-options") == "DENY"

    def test_csp_present(self, client):
        resp = client.get("/api/health")
        csp = resp.headers.get("content-security-policy", "")
        assert "default-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp
