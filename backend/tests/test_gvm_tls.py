"""
Testes GVM TLS — OpenVAS Dashboard v1.1.0

Cobre:
A. Unix socket definido → não exige certificados TLS
B. Modo remoto sem CA → ValidationError ou ValueError
C. Modo remoto sem cert → ValidationError ou ValueError
D. Modo remoto sem key → ValidationError ou ValueError
E. Modo remoto completo (CA+cert+key existentes) → aceito
E2. CA declarado mas arquivo ausente → ValidationError
F. TLSConnection recebe hostname, port, CA, cert, key e timeout
F2. UnixSocketConnection usada em modo socket; TLSConnection não chamada
G. CA declarado como diretório (não arquivo regular) → ValidationError

Sem conexão real com GVM — usa monkeypatch, tmp_path e unittest.mock.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from pydantic import ValidationError


# Env mínimo para validações não-TLS passarem nos testes que criam Settings()
_BASE_ENV = {
    "JWT_SECRET": "test-secret-that-is-at-least-32-characters-long-for-ci",
    "JWT_ISSUER": "openvas-dashboard-test",
    "JWT_AUDIENCE": "openvas-dashboard-users-test",
    "APP_USERNAME": "testuser",
    "APP_PASSWORD_HASH": (
        "$argon2id$v=19$m=65536,t=3,p=4$"
        "c29tZXNhbHRzb21lc2FsdA$"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    ),
    "GVM_USERNAME": "testgvm",
    "GVM_PASSWORD": "testgvmpass",
    "APP_ENV": "test",
    "COOKIE_SECURE": "false",
}


def _set_env(monkeypatch, overrides: dict):
    """Aplica env base + overrides; limpa GVM_SOCKET_PATH e GVM_TLS_* antes."""
    for key in ("GVM_SOCKET_PATH", "GVM_TLS_CA_FILE", "GVM_TLS_CERT_FILE", "GVM_TLS_KEY_FILE"):
        monkeypatch.delenv(key, raising=False)
    for k, v in _BASE_ENV.items():
        monkeypatch.setenv(k, v)
    for k, v in overrides.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)


def _make_settings(monkeypatch, overrides: dict):
    """Cria Settings() limpo (sem cache) com env configurado."""
    _set_env(monkeypatch, overrides)
    from app.config import Settings
    return Settings()


class TestGvmTlsConfig:
    """Testes de validação de configuração TLS do GVM."""

    # ── A. Unix socket → TLS não obrigatório ─────────────────────────────────

    def test_a_unix_socket_no_tls_required(self, monkeypatch):
        """Quando GVM_SOCKET_PATH está definido, TLS não é exigido."""
        s = _make_settings(monkeypatch, {
            "GVM_SOCKET_PATH": "/var/run/gvmd.sock",
            "GVM_PASSWORD": "",  # sem senha OK em modo socket
        })
        assert s.gvm_socket_path == "/var/run/gvmd.sock"
        assert s.gvm_tls_ca_file is None
        assert s.gvm_tls_cert_file is None
        assert s.gvm_tls_key_file is None

    # ── B. Modo remoto sem CA → erro ──────────────────────────────────────────

    def test_b_remote_no_ca_raises(self, monkeypatch, tmp_path):
        """Modo remoto sem GVM_TLS_CA_FILE → ValidationError."""
        cert = tmp_path / "client.crt"
        key = tmp_path / "client.key"
        cert.write_text("CERT")
        key.write_text("KEY")

        with pytest.raises((ValidationError, ValueError)) as exc_info:
            _make_settings(monkeypatch, {
                "GVM_HOST": "192.168.1.10",
                "GVM_TLS_CERT_FILE": str(cert),
                "GVM_TLS_KEY_FILE": str(key),
                # GVM_TLS_CA_FILE não definido
            })
        assert "GVM_TLS_CA_FILE" in str(exc_info.value)

    # ── C. Modo remoto sem cert → erro ────────────────────────────────────────

    def test_c_remote_no_cert_raises(self, monkeypatch, tmp_path):
        """Modo remoto sem GVM_TLS_CERT_FILE → ValidationError."""
        ca = tmp_path / "ca.pem"
        key = tmp_path / "client.key"
        ca.write_text("CA")
        key.write_text("KEY")

        with pytest.raises((ValidationError, ValueError)) as exc_info:
            _make_settings(monkeypatch, {
                "GVM_HOST": "192.168.1.10",
                "GVM_TLS_CA_FILE": str(ca),
                "GVM_TLS_KEY_FILE": str(key),
                # GVM_TLS_CERT_FILE não definido
            })
        assert "GVM_TLS_CERT_FILE" in str(exc_info.value)

    # ── D. Modo remoto sem key → erro ─────────────────────────────────────────

    def test_d_remote_no_key_raises(self, monkeypatch, tmp_path):
        """Modo remoto sem GVM_TLS_KEY_FILE → ValidationError."""
        ca = tmp_path / "ca.pem"
        cert = tmp_path / "client.crt"
        ca.write_text("CA")
        cert.write_text("CERT")

        with pytest.raises((ValidationError, ValueError)) as exc_info:
            _make_settings(monkeypatch, {
                "GVM_HOST": "192.168.1.10",
                "GVM_TLS_CA_FILE": str(ca),
                "GVM_TLS_CERT_FILE": str(cert),
                # GVM_TLS_KEY_FILE não definido
            })
        assert "GVM_TLS_KEY_FILE" in str(exc_info.value)

    # ── E. Modo remoto completo → aceito ──────────────────────────────────────

    def test_e_remote_full_tls_accepted(self, monkeypatch, tmp_path):
        """Modo remoto com CA, cert e key existentes → configuração aceita."""
        ca = tmp_path / "ca.pem"
        cert = tmp_path / "client.crt"
        key = tmp_path / "client.key"
        ca.write_text("CA")
        cert.write_text("CERT")
        key.write_text("KEY")

        s = _make_settings(monkeypatch, {
            "GVM_HOST": "192.168.1.10",
            "GVM_TLS_CA_FILE": str(ca),
            "GVM_TLS_CERT_FILE": str(cert),
            "GVM_TLS_KEY_FILE": str(key),
        })
        assert s.gvm_host == "192.168.1.10"
        assert s.gvm_tls_ca_file == str(ca)
        assert s.gvm_tls_cert_file == str(cert)
        assert s.gvm_tls_key_file == str(key)

    # ── E2. Arquivo declarado mas não existe → erro ───────────────────────────

    def test_e2_remote_ca_file_missing_on_disk_raises(self, monkeypatch, tmp_path):
        """CA declarado mas arquivo ausente no disco → ValidationError."""
        cert = tmp_path / "client.crt"
        key = tmp_path / "client.key"
        cert.write_text("CERT")
        key.write_text("KEY")

        with pytest.raises((ValidationError, ValueError)) as exc_info:
            _make_settings(monkeypatch, {
                "GVM_HOST": "192.168.1.10",
                "GVM_TLS_CA_FILE": str(tmp_path / "nonexistent_ca.pem"),
                "GVM_TLS_CERT_FILE": str(cert),
                "GVM_TLS_KEY_FILE": str(key),
            })
        assert "GVM_TLS_CA_FILE" in str(exc_info.value)

    # ── G. Caminho TLS existente mas diretório → erro ─────────────────────────

    def test_g_tls_ca_is_directory_raises(self, monkeypatch, tmp_path):
        """CA declarado como diretório (não arquivo regular) → ValidationError."""
        ca_dir = tmp_path / "ca_dir"
        ca_dir.mkdir()
        cert = tmp_path / "client.crt"
        key = tmp_path / "client.key"
        cert.write_text("CERT")
        key.write_text("KEY")

        with pytest.raises((ValidationError, ValueError)) as exc_info:
            _make_settings(monkeypatch, {
                "GVM_HOST": "192.168.1.10",
                "GVM_TLS_CA_FILE": str(ca_dir),
                "GVM_TLS_CERT_FILE": str(cert),
                "GVM_TLS_KEY_FILE": str(key),
            })
        assert "GVM_TLS_CA_FILE" in str(exc_info.value)


class TestGvmTlsConnection:
    """Verifica que TLSConnection/UnixSocketConnection recebem parâmetros corretos."""

    # ── F. TLSConnection recebe hostname, port, CA, cert, key e timeout ──────

    def test_f_tls_connection_receives_all_params(self, tmp_path):
        """
        _gmp_session em modo remoto passa hostname, port, cafile, certfile,
        keyfile e timeout ao construtor TLSConnection. Sem conexão real ao GVM.
        """
        ca = tmp_path / "ca.pem"
        cert = tmp_path / "client.crt"
        key = tmp_path / "client.key"
        ca.write_text("CA")
        cert.write_text("CERT")
        key.write_text("KEY")

        mock_settings = MagicMock()
        mock_settings.gvm_socket_path = ""
        mock_settings.gvm_host = "gvm.example.com"
        mock_settings.gvm_port = 9390
        mock_settings.gvm_tls_ca_file = str(ca)
        mock_settings.gvm_tls_cert_file = str(cert)
        mock_settings.gvm_tls_key_file = str(key)
        mock_settings.gvm_username = "admin"
        mock_settings.gvm_password = "secret"

        mock_conn_instance = MagicMock()
        mock_gmp_instance = MagicMock()
        mock_gmp_instance.__enter__ = MagicMock(return_value=mock_gmp_instance)
        mock_gmp_instance.__exit__ = MagicMock(return_value=False)

        import app.gvm_client as gvm_mod

        with patch.object(gvm_mod, "settings", mock_settings), \
             patch.object(gvm_mod, "TLSConnection") as mock_tls_cls, \
             patch.object(gvm_mod, "Gmp") as mock_gmp_cls:

            mock_tls_cls.return_value = mock_conn_instance
            mock_gmp_cls.return_value = mock_gmp_instance

            with gvm_mod._gmp_session():
                pass

        mock_tls_cls.assert_called_once_with(
            hostname="gvm.example.com",
            port=9390,
            cafile=str(ca),
            certfile=str(cert),
            keyfile=str(key),
            timeout=300,
        )

    # ── F2. Unix socket → UnixSocketConnection usada; TLSConnection não chamada

    def test_f2_unix_socket_uses_unix_connection(self):
        """
        Em modo Unix socket, UnixSocketConnection é usada e TLSConnection
        não é chamada.
        """
        mock_settings = MagicMock()
        mock_settings.gvm_socket_path = "/var/run/gvmd.sock"
        mock_settings.gvm_username = "admin"
        mock_settings.gvm_password = "secret"

        mock_conn_instance = MagicMock()
        mock_gmp_instance = MagicMock()
        mock_gmp_instance.__enter__ = MagicMock(return_value=mock_gmp_instance)
        mock_gmp_instance.__exit__ = MagicMock(return_value=False)

        import app.gvm_client as gvm_mod

        with patch.object(gvm_mod, "settings", mock_settings), \
             patch.object(gvm_mod, "TLSConnection") as mock_tls_cls, \
             patch.object(gvm_mod, "UnixSocketConnection") as mock_unix_cls, \
             patch.object(gvm_mod, "Gmp") as mock_gmp_cls:

            mock_unix_cls.return_value = mock_conn_instance
            mock_gmp_cls.return_value = mock_gmp_instance

            with gvm_mod._gmp_session():
                pass

        mock_unix_cls.assert_called_once_with(
            path="/var/run/gvmd.sock", timeout=300
        )
        mock_tls_cls.assert_not_called()
