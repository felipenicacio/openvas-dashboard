#!/usr/bin/env bash
# install.sh — Deploy do OpenVAS Dashboard (bare metal / systemd)
# Testado em: Ubuntu 22.04 / Debian 12 / RHEL 9
# Uso: sudo bash deploy/install.sh
set -euo pipefail

INSTALL_DIR="/opt/openvas-dashboard"
DATA_DIR="$INSTALL_DIR/data"
FRONTEND_DIST="/var/www/ovdash"
SERVICE_USER="ovdash"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }
section() { echo -e "\n${YELLOW}══ $* ══${NC}"; }

# ── Pré-requisitos ────────────────────────────────────────────────────────────
section "Verificando pré-requisitos"

[[ $EUID -eq 0 ]] || error "Execute como root: sudo bash deploy/install.sh"

for cmd in python3 pip3 node npm nginx; do
    command -v "$cmd" &>/dev/null || error "'$cmd' não encontrado. Instale antes de continuar."
done

PYTHON_VER=$(python3 -c 'import sys; print(sys.version_info >= (3,11))')
[[ "$PYTHON_VER" == "True" ]] || error "Python 3.11+ requerido (encontrado: $(python3 --version))"

info "Dependências OK"

# ── Usuário do serviço ────────────────────────────────────────────────────────
section "Configurando usuário do serviço"

if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    info "Usuário '$SERVICE_USER' criado"
else
    info "Usuário '$SERVICE_USER' já existe"
fi

# ── Copiar arquivos ───────────────────────────────────────────────────────────
section "Instalando arquivos em $INSTALL_DIR"

mkdir -p "$INSTALL_DIR" "$DATA_DIR"
rsync -a --delete \
    --exclude '.git' \
    --exclude 'frontend/node_modules' \
    --exclude 'frontend/dist' \
    --exclude 'backend/.venv' \
    --exclude '*.pyc' \
    --exclude '__pycache__' \
    --exclude 'data' \
    "$REPO_DIR/" "$INSTALL_DIR/"

# Configurar .env se não existir
if [[ ! -f "$INSTALL_DIR/.env" ]]; then
    if [[ -f "$INSTALL_DIR/.env.example" ]]; then
        cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
        warn ".env criado a partir de .env.example — EDITE antes de iniciar o serviço:"
        warn "  $INSTALL_DIR/.env"
    else
        error ".env.example não encontrado em $INSTALL_DIR"
    fi
else
    info ".env já existe — mantido sem alteração"
fi

# Garantir DATA_DIR no .env
grep -q "^DATA_DIR=" "$INSTALL_DIR/.env" || echo "DATA_DIR=$DATA_DIR" >> "$INSTALL_DIR/.env"

chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
chmod 750 "$DATA_DIR"
info "Arquivos instalados"

# ── Backend: virtualenv + dependências ───────────────────────────────────────
section "Configurando backend Python"

python3 -m venv "$INSTALL_DIR/backend/.venv"
"$INSTALL_DIR/backend/.venv/bin/pip" install --upgrade pip -q
"$INSTALL_DIR/backend/.venv/bin/pip" install -r "$INSTALL_DIR/backend/requirements.txt" -q
info "Dependências Python instaladas"

# ── Frontend: build estático ──────────────────────────────────────────────────
section "Build do frontend React"

cd "$INSTALL_DIR/frontend"
npm ci --silent
npm run build --silent

mkdir -p "$FRONTEND_DIST"
rsync -a --delete dist/ "$FRONTEND_DIST/"
info "Frontend buildado e copiado para $FRONTEND_DIST"

# ── Nginx ─────────────────────────────────────────────────────────────────────
section "Configurando nginx"

# Detectar diretório de sites do nginx
if [[ -d /etc/nginx/sites-available ]]; then
    NGINX_CONF=/etc/nginx/sites-available/ovdash
    cp "$INSTALL_DIR/deploy/nginx.conf" "$NGINX_CONF"
    ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/ovdash
    [[ -f /etc/nginx/sites-enabled/default ]] && rm -f /etc/nginx/sites-enabled/default && warn "Site 'default' do nginx desabilitado"
elif [[ -d /etc/nginx/conf.d ]]; then
    cp "$INSTALL_DIR/deploy/nginx.conf" /etc/nginx/conf.d/ovdash.conf
fi

nginx -t && info "Configuração nginx OK"
systemctl reload nginx
info "nginx recarregado"

# ── Systemd ───────────────────────────────────────────────────────────────────
section "Registrando serviço systemd"

cp "$INSTALL_DIR/deploy/ovdash-backend.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable ovdash-backend
systemctl restart ovdash-backend

sleep 2
if systemctl is-active --quiet ovdash-backend; then
    info "Serviço 'ovdash-backend' ativo"
else
    error "Serviço falhou ao iniciar. Verifique: journalctl -u ovdash-backend -n 50"
fi

# ── Resumo ────────────────────────────────────────────────────────────────────
section "Instalação concluída"

IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "  ${GREEN}Dashboard:${NC}    http://$IP"
echo -e "  ${GREEN}API docs:${NC}     http://$IP/api/docs"
echo -e "  ${GREEN}Config:${NC}       $INSTALL_DIR/.env"
echo -e "  ${GREEN}Dados (DB):${NC}   $DATA_DIR"
echo ""
echo -e "  Logs:    journalctl -u ovdash-backend -f"
echo -e "  Parar:   systemctl stop ovdash-backend"
echo -e "  Status:  systemctl status ovdash-backend"
echo ""
warn "Se editou o .env, reinicie: systemctl restart ovdash-backend"
echo ""
