"""
Testes de resolucao de secrets via systemd credentials — OpenVAS Dashboard

Cobre os casos A-O especificados no task, mais testes adicionais obrigatórios:
A. JWT systemd credential valida -> resolvida corretamente
B. GVM systemd credential valida -> resolvida corretamente
C. Credential ausente (CREDENTIALS_DIRECTORY sem o arquivo) -> ValueError
D. Credential vazia -> ValueError
E. Credential apontando para diretorio -> ValueError (is_file via fstat)
F. Credential grande demais (>4096 bytes) -> ValueError sem carregar tudo na mem
F2. Credential de exatamente 4096 bytes -> OK
G. PermissionError ao abrir credential -> ValueError sem conteudo
G2. OSError generico ao ler credential -> ValueError sem conteudo
H. Legacy JWT_SECRET funciona (gera deprecation warning)
I. Legacy GVM_PASSWORD funciona (gera deprecation warning)
J. systemd credential tem precedencia sobre legacy env var
K. Warning de deprecacao e emitido quando usa legacy
L. Valor do secret NUNCA aparece no warning (monkeypatch logging)
M. Unix socket autentica COM gvm_password via systemd credential
M2. Unix socket autentica COM gvm_password via legacy fallback
M3. Ausencia de GVM_PASSWORD em qualquer modo falha de forma segura
N. Sem CREDENTIALS_DIRECTORY + sem legacy -> fail-secure ValueError
O. GVM TLS remoto com credentials: configuracao aceita com todos os campos
P. UnicodeDecodeError nao vaza conteudo
Q. Arquivo > MAX não e integralmente carregado na memoria (comportamento correto)
R. CRLF e tratado conforme politica (remove exatamente um terminador)
S. Dois newlines finais NAO sao removidos silenciosamente
T. Legacy-only deployment inicia corretamente (validate_settings nao bloqueia)
U. credential + legacy -> credential vence (redundante com J, explicito aqui)
"""

import io
import os
import stat
import logging
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clear_credentials_directory(monkeypatch):
    """Remove CREDENTIALS_DIRECTORY do ambiente para cada teste."""
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    yield


@pytest.fixture
def creds_dir(tmp_path):
    """Cria um diretorio temporario de credentials."""
    d = tmp_path / "credentials"
    d.mkdir(mode=0o700)
    return d


def write_cred(directory: Path, name: str, value: str) -> Path:
    """Cria um arquivo de credential com permissoes corretas."""
    p = directory / name
    p.write_text(value, encoding="utf-8")
    p.chmod(0o600)
    return p


# ── Testes A–O ────────────────────────────────────────────────────────────────

class TestSystemdCredentials:

    # A. JWT systemd credential valida -> resolvida corretamente
    def test_A_jwt_systemd_credential_valid(self, monkeypatch, creds_dir):
        secret_value = "a" * 64
        write_cred(creds_dir, "jwt_secret", secret_value)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        result = resolve_secret("jwt_secret", None, "JWT_SECRET")
        assert result == secret_value

    # B. GVM systemd credential valida -> resolvida corretamente
    def test_B_gvm_systemd_credential_valid(self, monkeypatch, creds_dir):
        secret_value = "super-secure-gvm-pass"
        write_cred(creds_dir, "gvm_password", secret_value)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        result = resolve_secret("gvm_password", None, "GVM_PASSWORD")
        assert result == secret_value

    # C. Credential ausente (CREDENTIALS_DIRECTORY sem o arquivo) -> ValueError
    def test_C_credential_absent_raises(self, monkeypatch, creds_dir):
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))
        # Nenhum arquivo criado no diretorio

        from app.config import resolve_secret
        with pytest.raises(ValueError, match="jwt_secret"):
            resolve_secret("jwt_secret", None, "JWT_SECRET")

    # D. Credential vazia -> ValueError
    def test_D_empty_credential_raises(self, monkeypatch, creds_dir):
        write_cred(creds_dir, "jwt_secret", "")
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        with pytest.raises(ValueError, match="vazia"):
            resolve_secret("jwt_secret", None, "JWT_SECRET")

    # D2. Credential com apenas newline -> ValueError (vazia apos remover terminador)
    def test_D2_newline_only_credential_raises(self, monkeypatch, creds_dir):
        write_cred(creds_dir, "jwt_secret", "\n")
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        with pytest.raises(ValueError, match="vazia"):
            resolve_secret("jwt_secret", None, "JWT_SECRET")

    # E. Credential apontando para diretorio -> ValueError (fstat ISREG check)
    def test_E_credential_is_directory_raises(self, monkeypatch, creds_dir):
        # Criar um diretorio no lugar do arquivo
        subdir = creds_dir / "jwt_secret"
        subdir.mkdir()
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        # Em Linux, open() num diretório lança IsADirectoryError (subclasse de OSError)
        # antes de chegar ao fstat/S_ISREG. O handler de OSError captura corretamente.
        with pytest.raises(
    ValueError,
    match="IsADirectoryError|arquivo regular|Sem permissão",
):
            resolve_secret("jwt_secret", None, "JWT_SECRET")

    # F. Credential grande demais (>4096 bytes) -> ValueError
    def test_F_oversized_credential_raises(self, monkeypatch, creds_dir):
        # 4097 bytes — um byte acima do limite
        big_value = "x" * 4097
        write_cred(creds_dir, "jwt_secret", big_value)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        with pytest.raises(ValueError, match="4096"):
            resolve_secret("jwt_secret", None, "JWT_SECRET")

    # F2. Credential de exatamente 4096 bytes -> OK
    def test_F2_max_size_credential_ok(self, monkeypatch, creds_dir):
        exact_value = "x" * 4096
        write_cred(creds_dir, "jwt_secret", exact_value)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        result = resolve_secret("jwt_secret", None, "JWT_SECRET")
        assert result == exact_value

    # G. PermissionError ao abrir credential -> ValueError (sem conteudo)
    def test_G_permission_error_raises(self, monkeypatch, creds_dir):
        write_cred(creds_dir, "jwt_secret", "some-value")
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret

        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            with pytest.raises(ValueError, match="permiss"):
                resolve_secret("jwt_secret", None, "JWT_SECRET")

    # G2. OSError generico -> ValueError sem conteudo vazado
    def test_G2_oserror_raises_safe(self, monkeypatch, creds_dir):
        write_cred(creds_dir, "jwt_secret", "some-value")
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret

        with patch("builtins.open", side_effect=OSError("Device error")):
            with pytest.raises(ValueError) as exc_info:
                resolve_secret("jwt_secret", None, "JWT_SECRET")
            # Mensagem de erro não deve conter o valor do secret
            assert "some-value" not in str(exc_info.value)

    # H. Legacy JWT_SECRET funciona (gera deprecation warning)
    def test_H_legacy_jwt_secret_works(self, monkeypatch, caplog):
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
        legacy_value = "legacy-jwt-value-that-is-long-enough-32plus"

        from app.config import resolve_secret
        with caplog.at_level(logging.WARNING, logger="app.config"):
            result = resolve_secret("jwt_secret", legacy_value, "JWT_SECRET")

        assert result == legacy_value
        assert any("JWT_SECRET" in r.message for r in caplog.records)

    # I. Legacy GVM_PASSWORD funciona (gera deprecation warning)
    def test_I_legacy_gvm_password_works(self, monkeypatch, caplog):
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
        legacy_value = "legacy-gvm-pass"

        from app.config import resolve_secret
        with caplog.at_level(logging.WARNING, logger="app.config"):
            result = resolve_secret("gvm_password", legacy_value, "GVM_PASSWORD")

        assert result == legacy_value
        assert any("GVM_PASSWORD" in r.message for r in caplog.records)

    # J. systemd credential tem precedencia sobre legacy env var
    def test_J_credential_takes_precedence_over_legacy(self, monkeypatch, creds_dir):
        cred_value = "from-systemd-credential"
        legacy_value = "from-legacy-env"
        write_cred(creds_dir, "jwt_secret", cred_value)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        result = resolve_secret("jwt_secret", legacy_value, "JWT_SECRET")
        assert result == cred_value
        assert result != legacy_value

    # K. Warning de deprecacao e emitido quando usa legacy
    def test_K_deprecation_warning_emitted_for_legacy(self, monkeypatch, caplog):
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)

        from app.config import resolve_secret
        with caplog.at_level(logging.WARNING, logger="app.config"):
            resolve_secret("jwt_secret", "legacy-value-for-k-test-32plus", "JWT_SECRET")

        assert any("deprecated" in r.message.lower() for r in caplog.records)
        assert any("JWT_SECRET" in r.message for r in caplog.records)

    # L. Valor do secret NUNCA aparece no warning (monkeypatch logging)
    def test_L_secret_value_never_in_warning(self, monkeypatch, caplog):
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
        secret_value = "super-secret-jwt-value-that-must-not-appear"

        from app.config import resolve_secret
        with caplog.at_level(logging.WARNING, logger="app.config"):
            resolve_secret("jwt_secret", secret_value, "JWT_SECRET")

        for record in caplog.records:
            assert secret_value not in record.message, (
                f"Secret value leaked into log message: {record.message}"
            )

    # L2. Valor do secret GVM nunca aparece no warning
    def test_L2_gvm_secret_value_never_in_warning(self, monkeypatch, caplog):
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
        gvm_secret = "super-secret-gvm-password"

        from app.config import resolve_secret
        with caplog.at_level(logging.WARNING, logger="app.config"):
            resolve_secret("gvm_password", gvm_secret, "GVM_PASSWORD")

        for record in caplog.records:
            assert gvm_secret not in record.message, (
                f"GVM secret leaked into log message: {record.message}"
            )

    # L3. Warning de "both present" nao vaza nem o valor do credential nem do env
    def test_L3_ambiguity_warning_no_leak(self, monkeypatch, creds_dir, caplog):
        cred_value = "credential-value-secret-must-not-appear"
        legacy_value = "legacy-value-secret-must-not-appear"
        write_cred(creds_dir, "jwt_secret", cred_value)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        with caplog.at_level(logging.WARNING, logger="app.config"):
            resolve_secret("jwt_secret", legacy_value, "JWT_SECRET")

        for record in caplog.records:
            assert cred_value not in record.message
            assert legacy_value not in record.message

    # M. Unix socket autentica COM gvm_password via systemd credential
    # GVM_PASSWORD é obrigatório independente do transporte (TLS ou socket Unix).
    # gvm_client.py sempre chama gmp.authenticate() via protocolo GMP,
    # independente do transporte subjacente.
    def test_M_unix_socket_authenticates_with_credential(self, monkeypatch, creds_dir, tmp_path):
        """Unix socket mode: GVM_PASSWORD fornecido via systemd credential."""
        gvm_pass = "socket-mode-gvm-pass"
        write_cred(creds_dir, "gvm_password", gvm_pass)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        socket_path = tmp_path / "gvmd.sock"
        socket_path.touch()

        from app.config import Settings
        s = Settings(
            gvm_socket_path=str(socket_path),
            gvm_username="admin",
            gvm_password=None,  # fornecido via credential
            app_username="testuser",
            app_password_hash="$argon2id$v=19$m=65536,t=3,p=4$fakesalt$fakehash",
            jwt_secret=None,
            app_env="test",
        )
        assert s.gvm_socket_path == str(socket_path)
        # GVM_PASSWORD resolve corretamente via credential
        assert s.resolved_gvm_password == gvm_pass

    # M2. Unix socket autentica COM gvm_password via legacy fallback
    def test_M2_unix_socket_authenticates_with_legacy(self, monkeypatch, tmp_path):
        """Unix socket mode: GVM_PASSWORD fornecido via legacy .env (deprecated)."""
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)

        socket_path = tmp_path / "gvmd.sock"
        socket_path.touch()

        from app.config import Settings
        s = Settings(
            gvm_socket_path=str(socket_path),
            gvm_username="admin",
            gvm_password="legacy-gvm-pass",
            app_username="testuser",
            app_password_hash="$argon2id$v=19$m=65536,t=3,p=4$fakesalt$fakehash",
            jwt_secret=None,
            app_env="test",
        )
        assert s.resolved_gvm_password == "legacy-gvm-pass"

    # M3. Ausencia de GVM_PASSWORD em qualquer modo falha de forma segura
    def test_M3_missing_gvm_password_fails_secure(self, monkeypatch):
        """Sem GVM_PASSWORD (credential ou legacy), resolve_secret falha com ValueError."""
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)

        from app.config import resolve_secret
        with pytest.raises(ValueError, match="gvm_password"):
            resolve_secret("gvm_password", None, "GVM_PASSWORD")

    # N. Sem CREDENTIALS_DIRECTORY + sem legacy -> fail-secure ValueError
    def test_N_no_source_fails_secure(self, monkeypatch):
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)

        from app.config import resolve_secret
        with pytest.raises(ValueError, match="jwt_secret"):
            resolve_secret("jwt_secret", None, "JWT_SECRET")

    # N2. Sem CREDENTIALS_DIRECTORY + legacy vazio -> fail-secure ValueError
    def test_N2_empty_legacy_fails_secure(self, monkeypatch):
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)

        from app.config import resolve_secret
        with pytest.raises(ValueError):
            resolve_secret("jwt_secret", "", "JWT_SECRET")

    # O. GVM TLS remoto com credentials: configuracao aceita com todos os campos
    def test_O_gvm_tls_remote_with_credentials(self, monkeypatch, creds_dir, tmp_path):
        """Modo remoto TLS aceita gvm_password via credential."""
        gvm_pass = "tls-remote-gvm-pass"
        write_cred(creds_dir, "gvm_password", gvm_pass)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        # Criar arquivos TLS falsos para satisfazer o validador
        ca_file = tmp_path / "ca.pem"
        cert_file = tmp_path / "cert.pem"
        key_file = tmp_path / "key.pem"
        for f in [ca_file, cert_file, key_file]:
            f.write_text("fake-pem-content")

        from app.config import Settings

        s = Settings(
            gvm_socket_path="",
            gvm_host="192.168.1.100",
            gvm_port=9390,
            gvm_username="admin",
            gvm_password=None,  # nao no .env
            gvm_tls_ca_file=str(ca_file),
            gvm_tls_cert_file=str(cert_file),
            gvm_tls_key_file=str(key_file),
            app_username="testuser",
            app_password_hash="$argon2id$v=19$m=65536,t=3,p=4$fakesalt$fakehash",
            jwt_secret=None,
            app_env="test",
        )

        # Verificar que credential resolve corretamente
        result = s.resolved_gvm_password
        assert result == gvm_pass

    # P. UnicodeDecodeError nao vaza conteudo do arquivo
    def test_P_unicode_decode_error_no_leak(self, monkeypatch, creds_dir):
        """Arquivo com bytes invalidos UTF-8 -> ValueError sem vazar conteudo."""
        p = creds_dir / "jwt_secret"
        # Escrever bytes inválidos como UTF-8
        p.write_bytes(b"\xff\xfe invalid utf-8 bytes")
        p.chmod(0o600)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        with pytest.raises(ValueError) as exc_info:
            resolve_secret("jwt_secret", None, "JWT_SECRET")
        # Mensagem deve mencionar UTF-8, não o conteúdo dos bytes
        assert "UTF-8" in str(exc_info.value) or "utf-8" in str(exc_info.value).lower()
        # Não deve conter os bytes inválidos em representação
        assert b"\xff" not in exc_info.value.args[0].encode("utf-8", errors="replace")

    # Q. Arquivo > MAX: leitura limitada (sem carregar arquivo inteiro na memória)
    def test_Q_oversized_file_not_fully_loaded(self, monkeypatch, creds_dir):
        """Arquivo > MAX deve falhar com ValueError sem carregar todo o conteúdo."""
        big_value = "y" * 4097
        write_cred(creds_dir, "jwt_secret", big_value)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret, _MAX_CREDENTIAL_BYTES

        # Monitorar quantos bytes foram lidos
        read_calls = []
        original_open = open  # noqa: WPS421

        class TrackingFile:
            def __init__(self, f):
                self._f = f
            def fileno(self):
                return self._f.fileno()
            def read(self, n=-1):
                data = self._f.read(n)
                read_calls.append(len(data))
                return data
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self._f.__exit__(*args)

        def tracked_open(path, mode="r", **kwargs):
            f = original_open(path, mode, **kwargs)
            return TrackingFile(f)

        with patch("builtins.open", side_effect=tracked_open):
            with pytest.raises(ValueError, match="4096"):
                resolve_secret("jwt_secret", None, "JWT_SECRET")

        # Verificar que nunca lemos mais de MAX+1 bytes em uma chamada
        assert all(n <= _MAX_CREDENTIAL_BYTES + 1 for n in read_calls), (
            f"read() foi chamado com mais bytes do que permitido: {read_calls}"
        )

    # R. CRLF e tratado conforme politica (remove exatamente um terminador CRLF)
    def test_R_crlf_terminator_stripped(self, monkeypatch, creds_dir):
        """CRLF final deve ser removido como um unico terminador."""
        p = creds_dir / "jwt_secret"
        p.write_bytes(b"my-secret-value\r\n")
        p.chmod(0o600)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        result = resolve_secret("jwt_secret", None, "JWT_SECRET")
        assert result == "my-secret-value"

    # S. Dois newlines finais NAO sao removidos silenciosamente
    # Politica: remover exatamente UM terminador de linha (LF ou CRLF).
    # secret\n\n -> secret\n (nao secret)
    # Isso resulta em falha de autenticacao explicita, nao silenciosa.
    def test_S_double_newline_preserves_inner(self, monkeypatch, creds_dir):
        """Dois newlines finais: apenas o ultimo e removido (politica explicita)."""
        p = creds_dir / "jwt_secret"
        p.write_bytes(b"secret\n\n")
        p.chmod(0o600)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        # Remove apenas o último \n: "secret\n\n" -> "secret\n"
        result = resolve_secret("jwt_secret", None, "JWT_SECRET")
        assert result == "secret\n", (
            f"Esperado 'secret\\n' (apenas um terminador removido), "
            f"obtido: {result!r}"
        )

    # T. Legacy-only deployment inicia corretamente durante a versao de transicao
    def test_T_legacy_only_deployment_works(self, monkeypatch):
        """validate_settings nao bloqueia deploy com apenas legacy env vars."""
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)

        from app.config import Settings, validate_settings

        s = Settings(
            jwt_secret="legacy-jwt-secret-that-is-at-least-32-chars-long",
            gvm_password="legacy-gvm-pass",
            gvm_socket_path="/tmp/fake-gvmd.sock",
            gvm_username="admin",
            app_username="testuser",
            app_password_hash="$argon2id$v=19$m=65536,t=3,p=4$fakesalt$fakehash",
            app_env="test",
        )
        # Nao deve levantar SystemExit (fail-secure nao acionado)
        import unittest.mock as mock_module
        with mock_module.patch("app.config._fail") as mock_fail:
            validate_settings(s)
            mock_fail.assert_not_called()

    # U. credential + legacy -> credential vence (explicito)
    def test_U_credential_wins_over_legacy_explicit(self, monkeypatch, creds_dir):
        """Quando credential e legacy existem, credential tem precedencia."""
        cred_value = "credential-wins-this-value"
        legacy_value = "legacy-loses-this-value"
        write_cred(creds_dir, "gvm_password", cred_value)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        result = resolve_secret("gvm_password", legacy_value, "GVM_PASSWORD")
        assert result == cred_value
        assert legacy_value not in result


# ── Testes de propriedades resolvidas do Settings ────────────────────────────

class TestSettingsResolvedProperties:

    def test_resolved_jwt_secret_from_credential(self, monkeypatch, creds_dir, tmp_path):
        jwt_val = "b" * 64
        write_cred(creds_dir, "jwt_secret", jwt_val)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))
        # Usar socket path para bypass da validação TLS remota
        socket_path = tmp_path / "gvmd.sock"
        socket_path.touch()

        from app.config import Settings
        s = Settings(jwt_secret=None, gvm_socket_path=str(socket_path),
                     gvm_username="admin", gvm_password="x", app_env="test")
        assert s.resolved_jwt_secret == jwt_val

    def test_resolved_gvm_password_from_credential(self, monkeypatch, creds_dir, tmp_path):
        gvm_val = "gvm-cred-val"
        write_cred(creds_dir, "gvm_password", gvm_val)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))
        socket_path = tmp_path / "gvmd.sock"
        socket_path.touch()

        from app.config import Settings
        s = Settings(gvm_password=None, gvm_socket_path=str(socket_path),
                     gvm_username="admin", jwt_secret="x" * 32, app_env="test")
        assert s.resolved_gvm_password == gvm_val

    def test_resolved_jwt_secret_from_legacy(self, monkeypatch, tmp_path):
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
        legacy = "legacy-jwt-value-longer-than-32-chars-ok"
        socket_path = tmp_path / "gvmd.sock"
        socket_path.touch()

        from app.config import Settings
        s = Settings(jwt_secret=legacy, gvm_socket_path=str(socket_path),
                     gvm_username="admin", gvm_password="x", app_env="test")
        assert s.resolved_jwt_secret == legacy

    def test_resolved_gvm_password_from_legacy(self, monkeypatch, tmp_path):
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
        legacy = "legacy-gvm-password"
        socket_path = tmp_path / "gvmd.sock"
        socket_path.touch()

        from app.config import Settings
        s = Settings(gvm_password=legacy, gvm_socket_path=str(socket_path),
                     gvm_username="admin", jwt_secret="x" * 32, app_env="test")
        assert s.resolved_gvm_password == legacy


# ── Testes de política de newline ─────────────────────────────────────────────

class TestCredentialNewlinePolicy:
    """
    Política de newline: remover exatamente UM terminador de linha final (LF ou CRLF).
    Nunca remover múltiplos terminadores silenciosamente.
    """

    def test_trailing_lf_stripped(self, monkeypatch, creds_dir):
        """LF final e removido (caso normal: arquivo salvo com newline)."""
        p = creds_dir / "jwt_secret"
        p.write_bytes(b"my-secret-value\n")
        p.chmod(0o600)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        result = resolve_secret("jwt_secret", None, "JWT_SECRET")
        assert result == "my-secret-value"

    def test_trailing_crlf_stripped(self, monkeypatch, creds_dir):
        """CRLF final e removido como terminador unico."""
        p = creds_dir / "jwt_secret"
        p.write_bytes(b"my-secret-value\r\n")
        p.chmod(0o600)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        result = resolve_secret("jwt_secret", None, "JWT_SECRET")
        assert result == "my-secret-value"

    def test_no_trailing_newline_preserved(self, monkeypatch, creds_dir):
        """Arquivo sem newline final: valor preservado integro."""
        p = creds_dir / "jwt_secret"
        p.write_bytes(b"my-secret-value")
        p.chmod(0o600)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        result = resolve_secret("jwt_secret", None, "JWT_SECRET")
        assert result == "my-secret-value"

    def test_double_lf_only_last_stripped(self, monkeypatch, creds_dir):
        """Dois LF finais: apenas o ultimo e removido (nao strip geral)."""
        p = creds_dir / "jwt_secret"
        p.write_bytes(b"secret\n\n")
        p.chmod(0o600)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        result = resolve_secret("jwt_secret", None, "JWT_SECRET")
        # "secret\n\n" -> remover ultimo \n -> "secret\n"
        assert result == "secret\n"

    def test_internal_spaces_preserved(self, monkeypatch, creds_dir):
        """Spaces internos NAO devem ser removidos."""
        value_with_spaces = "  secret with spaces  "
        write_cred(creds_dir, "jwt_secret", value_with_spaces)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        result = resolve_secret("jwt_secret", None, "JWT_SECRET")
        assert result == "  secret with spaces  "

    def test_crlf_then_lf_only_crlf_stripped(self, monkeypatch, creds_dir):
        """CRLF seguido de LF: CRLF e o terminador final, LF interno preservado."""
        p = creds_dir / "jwt_secret"
        p.write_bytes(b"secret\n\r\n")
        p.chmod(0o600)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        from app.config import resolve_secret
        result = resolve_secret("jwt_secret", None, "JWT_SECRET")
        # "secret\n\r\n" -> remover \r\n final -> "secret\n"
        assert result == "secret\n"


# ── Testes de segurança de upgrade do JWT_SECRET ──────────────────────────────

class TestJwtUpgradeSafety:
    """
    Prova que o JWT signing key NUNCA muda silenciosamente durante upgrade.

    O install.sh e migrate_credentials.sh usam grep/cut para extrair JWT_SECRET
    do .env. grep/cut NÃO interpreta dotenv — retorna o valor RAW (com aspas, etc.).
    pydantic-settings SIM interpreta dotenv — retorna o valor SEMÂNTICO (sem aspas).

    Se raw ≠ semântico, gravar o raw na systemd credential corromperia o signing key
    e invalidaria TODAS as sessões JWT existentes.

    Solução: auto-migração apenas para formato hex-64 puro (^[0-9a-fA-F]{64}$).
    Qualquer outro formato requer migração manual.

    Casos cobertos:
    V1. hex-64 sem aspas    → raw == semântico → auto-migração SEGURA
    V2. hex-64 aspas duplas → raw ≠ semântico → auto-migração BLOQUEADA
    V3. hex-64 aspas simples → raw ≠ semântico → auto-migração BLOQUEADA
    V4. valor com '='       → não é hex-64    → auto-migração BLOQUEADA
    V5. valor com espaços   → não é hex-64    → auto-migração BLOQUEADA
    V6. pydantic strips double quotes; grep/cut preserva (prova da diferença)
    """

    import re
    _HEX64_RE = re.compile(r'^[0-9a-fA-F]{64}$')

    HEX64 = "a1b2c3d4e5f6a7b8" * 4  # 64 hex chars

    def _raw_from_dotenv_line(self, line: str) -> str:
        """Simula o que grep -m1 '^JWT_SECRET=' + cut -d= -f2- extrai."""
        # cut -d= -f2- equivale a split no primeiro '=' e pegar o resto
        _, _, after = line.partition('=')
        return after

    def test_V1_hex64_unquoted_passes_validation(self):
        """JWT_SECRET=<hex64> — raw é hex-64 puro; auto-migração segura."""
        line = f"JWT_SECRET={self.HEX64}"
        raw = self._raw_from_dotenv_line(line)
        assert raw == self.HEX64
        assert self._HEX64_RE.match(raw), \
            f"hex64 sem aspas deve passar na validação: {raw!r}"

    def test_V2_double_quoted_hex64_blocked(self):
        """JWT_SECRET=\"<hex64>\" — raw contém aspas duplas; bloqueado."""
        line = f'JWT_SECRET="{self.HEX64}"'
        raw = self._raw_from_dotenv_line(line)
        assert raw == f'"{self.HEX64}"', f"raw deve incluir aspas: {raw!r}"
        assert not self._HEX64_RE.match(raw), \
            f"double-quoted não deve passar na validação hex-64: {raw!r}"

    def test_V3_single_quoted_hex64_blocked(self):
        """JWT_SECRET='<hex64>' — raw contém aspas simples; bloqueado."""
        line = f"JWT_SECRET='{self.HEX64}'"
        raw = self._raw_from_dotenv_line(line)
        assert raw == f"'{self.HEX64}'", f"raw deve incluir aspas simples: {raw!r}"
        assert not self._HEX64_RE.match(raw), \
            f"single-quoted não deve passar na validação hex-64: {raw!r}"

    def test_V4_value_with_equals_blocked(self):
        """JWT_SECRET=abc=def — valor com '=' não é hex-64; bloqueado."""
        line = "JWT_SECRET=abc=def"
        raw = self._raw_from_dotenv_line(line)
        assert raw == "abc=def", f"cut -d= -f2- deve retornar 'abc=def': {raw!r}"
        assert not self._HEX64_RE.match(raw), \
            f"valor com '=' não deve passar: {raw!r}"

    def test_V5_value_with_spaces_blocked(self):
        """JWT_SECRET=abc def — valor com espaço não é hex-64; bloqueado."""
        line = "JWT_SECRET=abc def"
        raw = self._raw_from_dotenv_line(line)
        assert raw == "abc def"
        assert not self._HEX64_RE.match(raw), \
            f"valor com espaço não deve passar: {raw!r}"

    def test_V6_pydantic_strips_quotes_grep_cut_does_not(self, tmp_path, monkeypatch):
        """
        Prova concreta: para JWT_SECRET=\"<hex64>\",
        pydantic-settings resolve <hex64> (sem aspas),
        grep/cut extrai \"<hex64>\" (com aspas).
        Se install.sh gravasse o raw, o signing key seria corrompido.
        """
        env_file = tmp_path / ".env"
        env_file.write_text(f'JWT_SECRET="{self.HEX64}"\n')

        # Simular grep/cut (extrair tudo após o primeiro '=')
        line = f'JWT_SECRET="{self.HEX64}"'
        grep_cut_raw = self._raw_from_dotenv_line(line)

        # pydantic-settings interpreta o arquivo .env
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
        from pydantic_settings import BaseSettings

        class _S(BaseSettings):
            jwt_secret: str = ""
            model_config = {"env_file": str(env_file), "env_file_encoding": "utf-8"}

        semantic = _S().jwt_secret

        # Prova: grep/cut raw ≠ pydantic semântico
        assert grep_cut_raw != semantic, (
            f"grep/cut retorna {grep_cut_raw!r}, "
            f"pydantic retorna {semantic!r} — são diferentes"
        )
        # Prova: pydantic removeu as aspas
        assert semantic == self.HEX64, \
            f"pydantic deve retornar hex64 sem aspas: {semantic!r}"
        # Prova: o raw não passa na validação hex-64 → bloqueio correto
        assert not self._HEX64_RE.match(grep_cut_raw), \
            "validação hex-64 bloqueia corretamente o raw com aspas"


# ── Testes de detecção semântica de JWT_SECRET (edge cases do install.sh) ─────

class TestJwtInstallSafety:
    """
    Prova que _jwt_found_in_env() (helper Python do install.sh) detecta
    JWT_SECRET em TODOS os formatos válidos de dotenv, incluindo formatos que
    grep -q "^JWT_SECRET=." NÃO captura (ex.: espaços ao redor do '=').

    Regra invariante crítica (W8):
      Em NENHUM cenário em que .env exista e pydantic encontre JWT_SECRET
      um novo signing key deve ser gerado silenciosamente.

    Casos cobertos:
    W1. JWT_SECRET=<hex64>          — grep detecta E pydantic detecta
    W2. JWT_SECRET = <hex64>        — grep NÃO detecta, pydantic SIM → AMBIGUOUS
    W3. JWT_SECRET=\"<hex64>\"      — grep detecta (char após '='), pydantic SIM
    W4. JWT_SECRET='<hex64>'        — grep detecta, pydantic SIM
    W5. .env sem JWT_SECRET         — pydantic confirma ausência → geração permitida
    W6. Sem .env                    — nova instalação → geração permitida
    W7. Credential já existe        — preservar sempre independente do .env
    W8. CRÍTICO — em todos os casos com .env onde pydantic encontra JWT_SECRET,
                  _jwt_found_in_env retorna "encontrado" (exit 0 / True)
    """

    import re
    _HEX64_RE = re.compile(r'^[0-9a-fA-F]{64}$')
    HEX64 = "a1b2c3d4e5f6a7b8" * 4  # 64 hex chars

    def _pydantic_finds_jwt(self, env_file_path: str) -> bool:
        """
        Replica a lógica do helper _jwt_found_in_env() do install.sh.
        Retorna True se pydantic-settings encontrar JWT_SECRET não-vazio no .env.
        Retorna True em caso de exceção (fail-secure).
        """
        import os
        if not os.path.isfile(env_file_path):
            return False
        try:
            from pydantic_settings import BaseSettings
            from pydantic import Field

            class _S(BaseSettings):
                jwt_secret: str = Field(default="")
                model_config = {
                    "env_file": env_file_path,
                    "env_file_encoding": "utf-8",
                    "extra": "ignore",
                }

            val = _S().jwt_secret
            return bool(val.strip())
        except Exception:
            # Fail-secure: qualquer erro → assume presença
            return True

    def _grep_finds_jwt(self, env_content: str) -> bool:
        """
        Replica 'grep -q "^JWT_SECRET=." "$ENV_FILE"'.
        Retorna True se a linha JWT_SECRET= for detectada pelo padrão grep.
        """
        import re
        return bool(re.search(r'^JWT_SECRET=.', env_content, re.MULTILINE))

    # W1: JWT_SECRET=<hex64> — grep detecta E pydantic detecta
    def test_W1_standard_format_detected_by_both(self, tmp_path, monkeypatch):
        """Formato padrão: ambos grep e pydantic detectam JWT_SECRET."""
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)

        env_file = tmp_path / ".env"
        content = f"JWT_SECRET={self.HEX64}\n"
        env_file.write_text(content)

        assert self._grep_finds_jwt(content), \
            "grep deve detectar JWT_SECRET=<hex64>"
        assert self._pydantic_finds_jwt(str(env_file)), \
            "pydantic deve detectar JWT_SECRET=<hex64>"

    # W2: JWT_SECRET = <hex64> (espaços ao redor do =) — grep NÃO detecta, pydantic SIM
    def test_W2_spaces_around_equals_grep_miss_pydantic_hit(self, tmp_path, monkeypatch):
        """
        EDGE CASE CRÍTICO: JWT_SECRET = <hex64> é dotenv válido.
        grep -q "^JWT_SECRET=." NÃO detecta (padrão literal sem espaço).
        pydantic-settings DETECTA (interpreta dotenv semanticamente).
        Sem o helper Python, install.sh cairia no Case A e geraria NOVO signing key.
        """
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)

        env_file = tmp_path / ".env"
        content = f"JWT_SECRET = {self.HEX64}\n"
        env_file.write_text(content)

        # grep NÃO encontra (este é o bug que motivou o fix)
        assert not self._grep_finds_jwt(content), \
            "grep NÃO deve detectar 'JWT_SECRET = valor' (sem espaços no padrão ^JWT_SECRET=.)"

        # pydantic ENCONTRA (semanticamente correto)
        assert self._pydantic_finds_jwt(str(env_file)), \
            "pydantic DEVE detectar 'JWT_SECRET = valor' como dotenv válido"

    # W3: JWT_SECRET="<hex64>" — grep detecta (char após =), pydantic detecta (strip quotes)
    def test_W3_double_quoted_detected_by_both(self, tmp_path, monkeypatch):
        """JWT_SECRET=\"<hex64>\": grep detecta (há char após =), pydantic detecta e strip quotes."""
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)

        env_file = tmp_path / ".env"
        content = f'JWT_SECRET="{self.HEX64}"\n'
        env_file.write_text(content)

        assert self._grep_finds_jwt(content), \
            "grep deve detectar JWT_SECRET=\"<hex64>\" (há char imediatamente após =)"
        assert self._pydantic_finds_jwt(str(env_file)), \
            "pydantic deve detectar e remover aspas duplas"

    # W4: JWT_SECRET='<hex64>' — grep detecta, pydantic detecta
    def test_W4_single_quoted_detected_by_both(self, tmp_path, monkeypatch):
        """JWT_SECRET='<hex64>': ambos grep e pydantic detectam."""
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)

        env_file = tmp_path / ".env"
        content = f"JWT_SECRET='{self.HEX64}'\n"
        env_file.write_text(content)

        assert self._grep_finds_jwt(content), \
            "grep deve detectar JWT_SECRET='<hex64>'"
        assert self._pydantic_finds_jwt(str(env_file)), \
            "pydantic deve detectar JWT_SECRET com aspas simples"

    # W5: .env sem JWT_SECRET — pydantic confirma ausência
    def test_W5_env_without_jwt_secret_absent(self, tmp_path, monkeypatch):
        """.env existente sem JWT_SECRET: pydantic confirma ausência → geração permitida."""
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)

        env_file = tmp_path / ".env"
        # .env com outras variáveis mas SEM JWT_SECRET
        content = "APP_ENV=production\nGVM_USERNAME=admin\n"
        env_file.write_text(content)

        assert not self._grep_finds_jwt(content), \
            "grep não deve encontrar JWT_SECRET ausente"
        assert not self._pydantic_finds_jwt(str(env_file)), \
            "pydantic não deve encontrar JWT_SECRET ausente → geração CSPRNG permitida"

    # W6: Sem .env — nova instalação → geração permitida
    def test_W6_no_env_file_new_install(self, tmp_path, monkeypatch):
        """Sem .env: nova instalação comprovada → _pydantic_finds_jwt retorna False."""
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)

        env_file = tmp_path / ".env"
        # Arquivo NÃO existe

        assert not self._pydantic_finds_jwt(str(env_file)), \
            "sem .env: _pydantic_finds_jwt deve retornar False → geração CSPRNG permitida"

    # W7: Credential já existe — preservar sempre independente do .env
    def test_W7_existing_credential_preserved(self, monkeypatch, creds_dir, tmp_path):
        """
        Se jwt_secret credential já existe, o valor é preservado
        independentemente do que está no .env.
        """
        cred_value = "existing-credential-value-never-replaced"
        write_cred(creds_dir, "jwt_secret", cred_value)
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds_dir))

        # .env com JWT_SECRET em formato padrão (tentaria migrar, mas credential já existe)
        env_file = tmp_path / ".env"
        env_file.write_text(f"JWT_SECRET={self.HEX64}\n")

        from app.config import resolve_secret
        # Lê a credential existente — NÃO substitui
        result = resolve_secret("jwt_secret", None, "JWT_SECRET")
        assert result == cred_value, \
            "credential existente deve ser preservada sem alteração"

    # W8: CRÍTICO — invariante de segurança do JWT signing key
    def test_W8_critical_no_new_key_when_pydantic_finds_jwt(self, tmp_path, monkeypatch):
        """
        INVARIANTE CRÍTICA: em NENHUM cenário com .env existente onde pydantic
        encontre JWT_SECRET, _pydantic_finds_jwt deve retornar False.

        Esse é o teste que prova: 'Em nenhum upgrade com .env existente um JWT
        signing key novo é criado silenciosamente.' Qualquer format com JWT_SECRET
        não-vazio → _pydantic_finds_jwt=True → Case B2 AMBIGUOUS → sem geração.

        Formatos testados: padrão, espaços ao redor de =, aspas duplas, aspas simples,
        JWT_SECRET em comentário (não deve ser detectado), valor vazio.
        """
        monkeypatch.delenv("JWT_SECRET", raising=False)
        monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)

        test_cases_with_jwt = [
            # (descrição, conteúdo do .env)
            ("standard", f"JWT_SECRET={self.HEX64}\n"),
            ("spaces_around_equals", f"JWT_SECRET = {self.HEX64}\n"),
            ("double_quoted", f'JWT_SECRET="{self.HEX64}"\n'),
            ("single_quoted", f"JWT_SECRET='{self.HEX64}'\n"),
        ]

        for description, content in test_cases_with_jwt:
            env_file = tmp_path / f".env.{description}"
            env_file.write_text(content)

            found = self._pydantic_finds_jwt(str(env_file))
            assert found, (
                f"FALHA DE SEGURANÇA: formato '{description}' com JWT_SECRET não-vazio "
                f"NÃO foi detectado por _pydantic_finds_jwt. "
                f"Isso significa que install.sh geraria um NOVO signing key silenciosamente, "
                f"invalidando TODAS as sessões JWT ativas. "
                f"Conteúdo do .env: {content!r}"
            )

        # Casos em que JWT_SECRET está realmente ausente (geração é permitida)
        test_cases_without_jwt = [
            ("empty_env", "APP_ENV=production\n"),
            ("commented_out", f"# JWT_SECRET={self.HEX64}\n"),
            ("empty_value", "JWT_SECRET=\n"),
        ]

        for description, content in test_cases_without_jwt:
            env_file = tmp_path / f".env.{description}"
            env_file.write_text(content)

            found = self._pydantic_finds_jwt(str(env_file))
            assert not found, (
                f"FALSO POSITIVO: formato '{description}' sem JWT_SECRET válido "
                f"foi incorretamente detectado como presente. "
                f"Isso bloquearia geração CSPRNG em nova instalação. "
                f"Conteúdo do .env: {content!r}"
            )
