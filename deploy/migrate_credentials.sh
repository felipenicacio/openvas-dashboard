#!/usr/bin/env bash
# migrate_credentials.sh — OpenVAS Dashboard v1.2.0
# Migra GVM_PASSWORD e JWT_SECRET do .env para systemd credentials.
#
# Uso:
#   sudo bash deploy/migrate_credentials.sh [--env-file /caminho/.env]
#
# NOTA: O install.sh já realiza a migração do JWT_SECRET automaticamente durante
# um upgrade. Use este script apenas para migrar o GVM_PASSWORD, ou para
# re-executar a migração manualmente.
#
# Requer: root, arquivo .env existente com as variáveis a migrar.

set -euo pipefail

# ── Configuração ──────────────────────────────────────────────────────────────
ENV_FILE="${1:-/opt/openvas-dashboard/.env}"
CREDS_DIR="/etc/openvas-dashboard/credentials"
JWT_CRED="$CREDS_DIR/jwt_secret"
GVM_CRED="$CREDS_DIR/gvm_password"
SERVICE_NAME="ovdash-backend"

# ── Verificações ──────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "ERRO: execute como root (sudo bash deploy/migrate_credentials.sh)" >&2
    exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERRO: arquivo .env não encontrado: $ENV_FILE" >&2
    echo "  Use: sudo bash deploy/migrate_credentials.sh /caminho/para/.env" >&2
    exit 1
fi

# ── Criar estrutura (idempotente) ─────────────────────────────────────────────
install -d -m 700 -o root -g root /etc/openvas-dashboard
install -d -m 700 -o root -g root "$CREDS_DIR"

echo "=== Migração de credentials — OpenVAS Dashboard ==="
echo "Fonte: $ENV_FILE"
echo ""

migrated=0

# ── Helper: detecta JWT_SECRET via pydantic-settings (qualquer formato dotenv) ─
# Exit 0  = JWT_SECRET encontrado com valor não-vazio.
# Exit 1  = JWT_SECRET ausente ou vazio.
# Em erro → exit 0 (fail-secure: assume presença, impede geração acidental).
# NUNCA imprime o valor do secret — sinaliza apenas presença/ausência.
_jwt_found_in_env() {
    local env_file="$1"
    local py_bin
    # Usar o venv de instalação se disponível; fallback para python3 do sistema
    if [ -x "/opt/openvas-dashboard/.venv/bin/python3" ]; then
        py_bin="/opt/openvas-dashboard/.venv/bin/python3"
    else
        py_bin="python3"
    fi
    "$py_bin" - "$env_file" <<'PYEOF'
import sys, os
env_file = sys.argv[1]
if not os.path.isfile(env_file):
    sys.exit(1)
try:
    from pydantic_settings import BaseSettings
    from pydantic import Field
    class _S(BaseSettings):
        jwt_secret: str = Field(default="")
        model_config = {
            "env_file": env_file,
            "env_file_encoding": "utf-8",
            "extra": "ignore",
        }
    val = _S().jwt_secret
    # Não imprimir o valor — apenas sinalizar presença
    sys.exit(0 if val.strip() else 1)
except Exception:
    # Fail-secure: qualquer erro → assume que JWT_SECRET existe.
    # Impede substituição acidental do signing key.
    sys.exit(0)
PYEOF
}

# ── JWT_SECRET ────────────────────────────────────────────────────────────────
# IMPORTANTE: JWT_SECRET é o signing key dos tokens JWT.
# Migrar o valor existente — NUNCA gerar novo — para preservar sessões ativas.
#
# Auto-migração segura APENAS para formato hex-64 puro (^[0-9a-fA-F]{64}$).
# Motivo: grep/cut extrai o valor RAW do .env sem interpretar dotenv.
# Se o valor tiver aspas, espaços ou outros chars, raw ≠ semântico →
# o signing key seria corrompido → TODAS as sessões JWT seriam invalidadas.
#
# Formatos alternativos válidos (ex.: "JWT_SECRET = valor" com espaços ao redor
# do '=') são cobertos pelo helper Python _jwt_found_in_env() que usa
# pydantic-settings para detecção semântica fail-secure.
if [[ -f "$JWT_CRED" ]]; then
    # Credential já existe — preservar sem exceção.
    # AVISO: jwt_secret é o signing key. Substituí-lo invalida TODAS as sessões.
    # Rotação requer procedimento administrativo explícito — não remova este arquivo.
    echo "[SKIP] jwt_secret: credential já existe — preservando."

else
    # Extrai o valor raw no formato padrão (JWT_SECRET=valor, sem espaços ao redor do =)
    jwt_raw=$(grep -m1 '^JWT_SECRET=' "$ENV_FILE" | cut -d= -f2- 2>/dev/null || true)

    if [ -n "$jwt_raw" ]; then
        # Formato padrão detectado — validar se raw == semântico (hex-64 puro)
        if printf '%s' "$jwt_raw" | grep -qE '^[0-9a-fA-F]{64}$'; then
            echo "[INFO] Migrando JWT_SECRET (formato hex-64 seguro)..."
            # Pipe direto para install: valor nunca passa por stdout nem argv
            printf '%s' "$jwt_raw" \
                | install -m 600 -o root -g root /dev/stdin "$JWT_CRED"
            unset jwt_raw
            echo "[OK] jwt_secret migrado para $JWT_CRED"
            echo "[OK] Remova JWT_SECRET do .env após verificar que o serviço funciona."
            migrated=$((migrated + 1))
        else
            unset jwt_raw
            echo "[MANUAL] JWT_SECRET detectado mas valor não é hex-64 puro."
            echo "[MANUAL] Auto-migração desativada para evitar corrupção do signing key."
            echo "[MANUAL] Motivo: grep/cut não interpreta dotenv — aspas, espaços ou"
            echo "[MANUAL]   chars especiais produziriam raw ≠ semântico, corrompendo"
            echo "[MANUAL]   o JWT signing key e invalidando TODAS as sessões ativas."
            echo "[MANUAL] Migre manualmente (cole o valor sem aspas/espaços extras):"
            echo ""
            echo "  sudo install -m 600 -o root -g root /dev/null $JWT_CRED"
            echo "  sudo sudoedit $JWT_CRED"
            echo "  # O valor deve ser idêntico ao que pydantic-settings interpreta."
            echo "  # Após verificar que o serviço funciona:"
            echo "  sudo sed -i '/^JWT_SECRET=/d' $ENV_FILE"
            echo "  sudo bash deploy/install.sh"
        fi

    else
        # grep ^JWT_SECRET= não detectou — verificar semanticamente via pydantic-settings
        # para cobrir formatos alternativos como "JWT_SECRET = valor" (espaços ao redor do =).
        unset jwt_raw 2>/dev/null || true
        if _jwt_found_in_env "$ENV_FILE"; then
            # JWT_SECRET encontrado em formato não padrão — migração manual obrigatória.
            # Fail-secure: não é possível extrair o valor com segurança via grep/cut.
            echo "[AMBIGUOUS] JWT_SECRET detectado semanticamente em $ENV_FILE,"
            echo "[AMBIGUOUS] mas em formato não extraível inequivocamente por grep/cut"
            echo "[AMBIGUOUS] (possível: 'JWT_SECRET = valor' com espaços ao redor do '=')."
            echo "[AMBIGUOUS] NENHUM jwt_secret novo será gerado — signing key preservado."
            echo "[AMBIGUOUS] Migre manualmente (cole exatamente o valor sem aspas/espaços extras):"
            echo ""
            echo "  sudo install -m 600 -o root -g root /dev/null $JWT_CRED"
            echo "  sudo sudoedit $JWT_CRED"
            echo "  # Cole exatamente o valor que pydantic-settings interpreta,"
            echo "  # sem aspas externas adicionais."
            echo "  # Após verificar que o serviço funciona:"
            echo "  sudo sed -i '/JWT_SECRET/d' $ENV_FILE"
            echo "  sudo bash deploy/install.sh"
        else
            echo "[SKIP] JWT_SECRET não encontrado em $ENV_FILE — ignorando."
        fi
    fi
fi

echo ""

# ── GVM_PASSWORD ──────────────────────────────────────────────────────────────
# GVM_PASSWORD NÃO é migrado automaticamente via script por segurança:
# o valor pode conter aspas, espaços ou caracteres especiais que tornam
# a extração via grep/cut não-trivial e potencialmente incorreta.
# Migre manualmente para garantir integridade.
if grep -q "^GVM_PASSWORD=." "$ENV_FILE" 2>/dev/null; then
    if [[ -f "$GVM_CRED" ]]; then
        echo "[SKIP] gvm_password: credential já existe — preservando."
    else
        echo "[MANUAL] GVM_PASSWORD detectado em $ENV_FILE."
        echo "[MANUAL] Por segurança, a migração é manual:"
        echo ""
        echo "  # Opção 1 — sudoedit (recomendado, sem exibir no terminal):"
        echo "  sudo install -m 600 -o root -g root /dev/null $GVM_CRED"
        echo "  sudo sudoedit $GVM_CRED"
        echo "  # Cole a senha, salve e feche o editor."
        echo ""
        echo "  # Opção 2 — read + tee (tee redireciona stdout para /dev/null):"
        echo "  read -rsp 'GVM password: ' GVM_PASS \\"
        echo "    && printf '%s' \"\$GVM_PASS\" | sudo tee $GVM_CRED >/dev/null \\"
        echo "    && unset GVM_PASS"
        echo ""
        echo "  Após criar o arquivo:"
        echo "  sudo bash deploy/install.sh   # atualiza o drop-in systemd"
    fi
else
    echo "[SKIP] GVM_PASSWORD não encontrado em $ENV_FILE — ignorando."
fi

echo ""

# ── Próximos passos ──────────────────────────────────────────────────────────
if [[ $migrated -gt 0 ]]; then
    echo "=== Próximos passos ==="
    echo "1. Verifique que o serviço inicia corretamente:"
    echo "   sudo bash deploy/install.sh"
    echo "   sudo systemctl status $SERVICE_NAME"
    echo ""
    echo "2. Após confirmar que tudo funciona, remova os secrets do .env:"
    if grep -q "^JWT_SECRET=" "$ENV_FILE" 2>/dev/null; then
        echo "   sudo sed -i '/^JWT_SECRET=/d' $ENV_FILE"
    fi
    echo ""
    echo "3. Reinicie o serviço:"
    echo "   sudo systemctl restart $SERVICE_NAME"
    echo ""
    echo "IMPORTANTE: Nunca exponha o conteúdo dos arquivos de credential."
    echo "  Permissões corretas: stat $CREDS_DIR/"
fi
