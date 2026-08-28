"""
conftest.py — Configuração global da suíte de testes.

Define variáveis de ambiente mínimas ANTES da importação de qualquer módulo
durante a fase de collection do pytest. Isso é necessário porque auth.py
e config.py chamam get_settings() em nível de módulo, o que falha sem
GVM_SOCKET_PATH definido (aciona validação TLS remoto).

Este conftest resolve o erro de collection pré-existente em test_vulnerabilities.py
sem modificar o código de produção.
"""

import os


def pytest_configure(config):
    """
    Hook executado antes da collection — define env vars mínimas para que
    Settings() não falhe durante a importação dos módulos de teste.

    GVM_SOCKET_PATH: qualquer string não-vazia desativa a validação TLS remoto
    em _validate_tls_remote (que só é acionada quando gvm_socket_path está vazio).
    O caminho não precisa existir para a inicialização do Settings.
    """
    defaults = {
        "APP_ENV": "development",
        "APP_USERNAME": "testuser",
        # Hash Argon2id de "testpassword" — válido para validação do campo
        "APP_PASSWORD_HASH": (
            "$argon2id$v=19$m=65536,t=3,p=4$"
            "c29tZXNhbHQ$"
            "RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
        ),
        "GVM_SOCKET_PATH": "/tmp/fake-gvmd.sock",
        "GVM_USERNAME": "admin",
        "GVM_PASSWORD": "testgvmpassword",
        # JWT_SECRET: 32+ chars, não pode ser valor proibido (dev-secret, etc.)
        "JWT_SECRET": "t3st-jwt-secr3t-for-pytest-suíte-only-not-production",
        "JWT_EXPIRE_MINUTES": "30",
        "JWT_ISSUER": "openvas-dashboard",
        "JWT_AUDIENCE": "openvas-dashboard-users",
        "COOKIE_SECURE": "false",
        "ENABLE_API_DOCS": "false",
        "SYNC_INTERVAL_MINUTES": "30",
    }
    for key, value in defaults.items():
        os.environ.setdefault(key, value)
