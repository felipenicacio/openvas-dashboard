#!/usr/bin/env bash
# install.sh — OpenVAS Dashboard v1.1.0
# Instala ou atualiza o dashboard a partir do diretório do repositório.
#
# Uso (a partir da raiz do repositório clonado):
#   sudo bash deploy/install.sh
#
# O script detecta automaticamente o diretório raiz do repositório
# (o diretório pai de deploy/) e copia os arquivos necessários para
# /opt/openvas-dashboard antes de configurar o serviço.
#
# Pré-requisito: sistema Debian/Ubuntu com Python 3.11+ e npm 20+.

set -euo pipefail

# ── Detectar diretório raiz do repositório ────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

INSTALL_DIR="/opt/openvas-dashboard"
DATA_DIR="$INSTALL_DIR/data"
VENV="$INSTALL_DIR/.venv"
SERVICE_NAME="ovdash-backend"

echo "=== OpenVAS Dashboard v1.1.0 — Instalação ==="
echo "Repositório: $REPO_DIR"
echo "Destino:     $INSTALL_DIR"
echo ""

# ── Verificações ──────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "ERRO: execute como root (sudo bash deploy/install.sh)" >&2
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "ERRO: python3 não encontrado." >&2
    exit 1
fi

# ── Usuário do serviço ────────────────────────────────────────────────────────
if ! id ovdash &>/dev/null; then
    echo "Criando usuário do serviço 'ovdash'..."
    useradd --system --no-create-home --shell /usr/sbin/nologin ovdash
fi

# ── Criar diretório de instalação ─────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"

# ── Limpeza de layout legado ──────────────────────────────────────────────────
# Versões antigas podiam deixar uma cópia aninhada em
# /opt/openvas-dashboard/frontend/openvas-dashboard. Como os padrões de exclusão
# do rsync podem preservar node_modules/dist dentro dela, --delete sozinho não
# consegue remover o diretório e emite "cannot delete non-empty directory".
LEGACY_FRONTEND_DIR="$INSTALL_DIR/frontend/openvas-dashboard"
if [[ -d "$LEGACY_FRONTEND_DIR" ]]; then
    echo "Removendo diretório legado: $LEGACY_FRONTEND_DIR"
    rm -rf -- "$LEGACY_FRONTEND_DIR"
fi

# ── Copiar arquivos do repositório para /opt ──────────────────────────────────
echo "Copiando arquivos para $INSTALL_DIR..."
# IMPORTANTE: --exclude=data/ garante que o banco SQLite e arquivos WAL/SHM
# em $DATA_DIR NÃO sejam removidos durante atualizações. O diretório de dados
# é gerenciado exclusivamente pelo serviço e nunca deve vir do repositório.
rsync -a --delete \
    --exclude='.git' \
    --exclude='.env' \
    --exclude='data/' \
    --exclude='frontend/node_modules' \
    --exclude='frontend/dist' \
    --exclude='backend/__pycache__' \
    --exclude='backend/.venv' \
    --exclude='backend/tests/__pycache__' \
    "$REPO_DIR/" "$INSTALL_DIR/"

# ── Diretórios e permissões ───────────────────────────────────────────────────
echo "Configurando diretórios e permissões..."
mkdir -p "$DATA_DIR"
chown -R ovdash:ovdash "$DATA_DIR"
chmod 750 "$DATA_DIR"

# .env: apenas root e ovdash — nunca world-readable
if [[ -f "$INSTALL_DIR/.env" ]]; then
    chown root:ovdash "$INSTALL_DIR/.env"
    chmod 640 "$INSTALL_DIR/.env"
    echo "Permissões de .env ajustadas (640, root:ovdash)"
else
    echo ""
    echo "AVISO: .env não encontrado em $INSTALL_DIR"
    echo "  Copie o exemplo e configure antes de iniciar o serviço:"
    echo "    sudo cp $INSTALL_DIR/.env.example $INSTALL_DIR/.env"
    echo "    sudo nano $INSTALL_DIR/.env"
    echo ""
fi

# ── Virtualenv e dependências Python ─────────────────────────────────────────
echo "Instalando dependências Python..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$INSTALL_DIR/backend/requirements.txt"
chown -R ovdash:ovdash "$VENV"

# ── Frontend (build estático) ─────────────────────────────────────────────────
if command -v npm &>/dev/null; then
    echo "Construindo frontend React..."
    cd "$INSTALL_DIR/frontend"
    npm ci --silent
    npm run build --silent
    echo "Frontend compilado em $INSTALL_DIR/frontend/dist/"
    cd "$REPO_DIR"
else
    echo "AVISO: npm não encontrado — build do frontend pulado."
    echo "  Instale Node.js 20+ e execute manualmente:"
    echo "    cd $INSTALL_DIR/frontend && npm ci && npm run build"
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

if [[ -f "$INSTALL_DIR/.env" ]]; then
    systemctl restart "$SERVICE_NAME"
    echo ""
    echo "=== Instalação concluída ==="
    systemctl status "$SERVICE_NAME" --no-pager -l
else
    echo ""
    echo "=== Instalação concluída (serviço NÃO iniciado — .env ausente) ==="
    echo "Configure $INSTALL_DIR/.env e execute:"
    echo "  sudo systemctl start $SERVICE_NAME"
fi
