#!/usr/bin/env bash
# install.sh — OpenVAS Dashboard v1.1.0
# Instala/atualiza backend e frontend com permissões corretas
#
# Uso:
#   sudo bash deploy/install.sh
#
# Pré-requisito: usuário 'ovdash' e diretório /opt/openvas-dashboard existentes
# Para criar o usuário:
#   sudo useradd --system --no-create-home --shell /usr/sbin/nologin ovdash

set -euo pipefail

INSTALL_DIR="/opt/openvas-dashboard"
DATA_DIR="$INSTALL_DIR/data"
VENV="$INSTALL_DIR/.venv"
SERVICE_NAME="ovdash-backend"

# ── Verificações ──────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "ERRO: execute como root (sudo bash deploy/install.sh)" >&2
    exit 1
fi

if ! id ovdash &>/dev/null; then
    echo "Criando usuário ovdash..."
    useradd --system --no-create-home --shell /usr/sbin/nologin ovdash
fi

# ── Diretórios e permissões ───────────────────────────────────────────────────
echo "Configurando diretórios..."
mkdir -p "$DATA_DIR"
chown -R ovdash:ovdash "$DATA_DIR"
chmod 750 "$DATA_DIR"

# .env: apenas root e ovdash — nunca world-readable
if [[ -f "$INSTALL_DIR/.env" ]]; then
    chown root:ovdash "$INSTALL_DIR/.env"
    chmod 640 "$INSTALL_DIR/.env"
    echo "Permissões de .env ajustadas (640, root:ovdash)"
else
    echo "AVISO: .env não encontrado em $INSTALL_DIR — copie .env.example e configure."
fi

# ── Virtualenv e dependências ─────────────────────────────────────────────────
echo "Instalando dependências Python..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$INSTALL_DIR/backend/requirements.txt"
chown -R ovdash:ovdash "$VENV"

# ── Frontend (build estático) ─────────────────────────────────────────────────
if command -v npm &>/dev/null && [[ -d "$INSTALL_DIR/frontend" ]]; then
    echo "Construindo frontend React..."
    cd "$INSTALL_DIR/frontend"
    npm ci --silent
    npm run build --silent
    echo "Frontend compilado em frontend/dist/"
else
    echo "AVISO: npm não encontrado — build do frontend pulado."
fi

# ── Permissões do código (não-executável pelo serviço) ────────────────────────
chown -R root:ovdash "$INSTALL_DIR/backend"
chmod -R 750 "$INSTALL_DIR/backend"
find "$INSTALL_DIR/backend" -name "*.py" -exec chmod 640 {} \;

# ── systemd ───────────────────────────────────────────────────────────────────
echo "Instalando serviço systemd..."
cp "$INSTALL_DIR/deploy/ovdash-backend.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo ""
echo "=== Instalação concluída ==="
systemctl status "$SERVICE_NAME" --no-pager -l
