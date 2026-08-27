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

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }
section() { echo -e "\n${CYAN}══ $* ══${NC}"; }
prompt()  { echo -e "${YELLOW}[?]${NC} $*"; }

# ── Pré-requisitos ────────────────────────────────────────────────────────────
section "Verificando pré-requisitos"

[[ $EUID -eq 0 ]] || error "Execute como root: sudo bash deploy/install.sh"

# Detect interactive mode
INTERACTIVE=true
[[ -t 0 ]] || INTERACTIVE=false

# Ensure Python 3.11+
if ! command -v python3 &>/dev/null; then
    error "python3 não encontrado. Instale python3.11+ antes de continuar."
fi
PYTHON_VER=$(python3 -c 'import sys; print(sys.version_info >= (3,11))')
[[ "$PYTHON_VER" == "True" ]] || error "Python 3.11+ requerido (encontrado: $(python3 --version))"

# Ensure pip (install if missing)
if ! command -v pip3 &>/dev/null && ! python3 -m pip --version &>/dev/null 2>&1; then
    warn "pip não encontrado — instalando…"
    if command -v apt-get &>/dev/null; then
        apt-get install -y python3-pip -q
    elif command -v dnf &>/dev/null; then
        dnf install -y python3-pip -q
    elif command -v yum &>/dev/null; then
        yum install -y python3-pip -q
    else
        error "Não foi possível instalar pip automaticamente. Instale python3-pip manualmente."
    fi
fi

# Ensure Node/npm
for cmd in node npm; do
    command -v "$cmd" &>/dev/null || error "'$cmd' não encontrado. Instale Node.js 20+ antes de continuar."
done

# Ensure nginx
command -v nginx &>/dev/null || error "'nginx' não encontrado. Instale nginx antes de continuar."

# Ensure openssl (for secret generation)
command -v openssl &>/dev/null || error "'openssl' não encontrado."

info "Pré-requisitos OK"

# ── Detectar instalação GVM ───────────────────────────────────────────────────
section "Detectando instalação GVM"

GVM_INSTALL_TYPE="none"
DETECTED_SOCKET=""

DOCKER_SOCKET="/var/lib/docker/volumes/greenbone-community-edition_gvmd_socket_vol/_data/gvmd.sock"
NATIVE_SOCKETS=(
    "/run/gvmd/gvmd.sock"
    "/var/run/gvmd/gvmd.sock"
    "/tmp/gvmd.sock"
)

if [[ -S "$DOCKER_SOCKET" ]]; then
    GVM_INSTALL_TYPE="docker"
    DETECTED_SOCKET="/run/gvmd.sock"
    info "GVM via Docker detectado (volume: greenbone-community-edition)"
else
    for sock in "${NATIVE_SOCKETS[@]}"; do
        if [[ -S "$sock" ]]; then
            GVM_INSTALL_TYPE="native"
            DETECTED_SOCKET="$sock"
            info "GVM nativo detectado: $sock"
            break
        fi
    done
fi

if [[ "$GVM_INSTALL_TYPE" == "none" ]]; then
    warn "Socket GVM não detectado automaticamente."
    warn "Você pode configurar GVM_SOCKET_PATH ou GVM_HOST/GVM_PORT manualmente no .env após a instalação."
fi

# ── Configurar socat relay (apenas Docker) ────────────────────────────────────
if [[ "$GVM_INSTALL_TYPE" == "docker" ]]; then
    section "Configurando relay socat para Docker GVM"

    if ! command -v socat &>/dev/null; then
        warn "socat não encontrado — instalando…"
        if command -v apt-get &>/dev/null; then
            apt-get install -y socat -q
        elif command -v dnf &>/dev/null; then
            dnf install -y socat -q
        elif command -v yum &>/dev/null; then
            yum install -y socat -q
        else
            error "Não foi possível instalar socat automaticamente. Instale socat manualmente."
        fi
    fi
    info "socat disponível"

    cp "$REPO_DIR/deploy/gvmd-relay.service" /etc/systemd/system/gvmd-relay.service
    systemctl daemon-reload
    systemctl enable gvmd-relay
    systemctl restart gvmd-relay
    sleep 1
    if systemctl is-active --quiet gvmd-relay; then
        info "Serviço gvmd-relay ativo (relay Docker → /run/gvmd.sock)"
    else
        warn "gvmd-relay não iniciou — verifique: journalctl -u gvmd-relay -n 20"
    fi
fi

# ── Usuário do serviço ────────────────────────────────────────────────────────
section "Configurando usuário do serviço"

if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    info "Usuário '$SERVICE_USER' criado"
else
    info "Usuário '$SERVICE_USER' já existe"
fi

# Grant access to native GVM socket group if applicable
if [[ "$GVM_INSTALL_TYPE" == "native" ]]; then
    SOCK_GROUP=$(stat -c '%G' "$DETECTED_SOCKET" 2>/dev/null || true)
    if [[ -n "$SOCK_GROUP" && "$SOCK_GROUP" != "root" ]]; then
        usermod -aG "$SOCK_GROUP" "$SERVICE_USER" 2>/dev/null && \
            info "Usuário '$SERVICE_USER' adicionado ao grupo '$SOCK_GROUP' (acesso ao socket GVM)" || true
    fi
fi

# ── Copiar arquivos ───────────────────────────────────────────────────────────
section "Instalando arquivos em $INSTALL_DIR"

mkdir -p "$INSTALL_DIR" "$DATA_DIR"
rsync -a --delete \
    --exclude '.git' \
    --exclude 'data' \
    --exclude 'frontend/node_modules' \
    --exclude 'frontend/dist' \
    --exclude 'backend/.venv' \
    --exclude '*.pyc' \
    --exclude '__pycache__' \
    "$REPO_DIR/" "$INSTALL_DIR/"

# Ensure data dir exists (rsync --exclude 'data' won't touch it)
mkdir -p "$DATA_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
chmod 750 "$DATA_DIR"
info "Arquivos instalados"

# ── Coletar credenciais e gerar .env ─────────────────────────────────────────
section "Configurando .env"

ENV_FILE="$INSTALL_DIR/.env"

if [[ -f "$ENV_FILE" ]]; then
    info ".env já existe — mantido sem alteração"
else
    # Generate JWT secret
    JWT_SECRET=$(openssl rand -hex 32)

    # Prompt or generate APP_PASSWORD
    if [[ "$INTERACTIVE" == "true" ]]; then
        prompt "Defina a senha do dashboard (APP_PASSWORD) [Enter para gerar automaticamente]:"
        read -rsp "  > " APP_PASSWORD
        echo ""
        if [[ -z "$APP_PASSWORD" ]]; then
            APP_PASSWORD=$(openssl rand -hex 16)
            warn "Senha gerada automaticamente: $APP_PASSWORD  (anote antes de continuar!)"
        fi
    else
        APP_PASSWORD=$(openssl rand -hex 16)
        warn "Executando sem terminal — APP_PASSWORD gerado automaticamente: $APP_PASSWORD"
    fi

    # Prompt or use defaults for GVM credentials
    GVM_USERNAME="admin"
    GVM_PASSWORD=""
    if [[ "$INTERACTIVE" == "true" ]]; then
        prompt "GVM username [admin]:"
        read -r _GVM_USER
        [[ -n "$_GVM_USER" ]] && GVM_USERNAME="$_GVM_USER"

        prompt "GVM password (obrigatório):"
        read -rsp "  > " GVM_PASSWORD
        echo ""
    fi

    # Socket / host settings
    GVM_SOCKET_LINE="GVM_SOCKET_PATH="
    GVM_HOST_LINE="GVM_HOST="
    GVM_PORT_LINE="GVM_PORT=9390"
    if [[ "$GVM_INSTALL_TYPE" == "docker" ]]; then
        GVM_SOCKET_LINE="GVM_SOCKET_PATH=/run/gvmd.sock"
        GVM_HOST_LINE="# GVM_HOST= (socket mode ativo — comente esta linha se usar host/porta)"
    elif [[ "$GVM_INSTALL_TYPE" == "native" ]]; then
        GVM_SOCKET_LINE="GVM_SOCKET_PATH=$DETECTED_SOCKET"
        GVM_HOST_LINE="# GVM_HOST= (socket mode ativo — comente esta linha se usar host/porta)"
    else
        GVM_HOST_LINE="GVM_HOST=192.168.1.100   # Altere para o IP do servidor GVM"
    fi

    cat > "$ENV_FILE" <<EOF
# ─────────────────────────────────────────────────────────────────────────────
# OpenVAS Dashboard — Configuração de Ambiente
# NÃO versione este arquivo (ele contém segredos). Já está no .gitignore.
# ─────────────────────────────────────────────────────────────────────────────

# ── Conexão GVM ──────────────────────────────────────────────────────────────
# Modo socket Unix (Docker ou nativo): preencha GVM_SOCKET_PATH e deixe GVM_HOST vazio.
# Modo rede (TLS): preencha GVM_HOST/GVM_PORT e deixe GVM_SOCKET_PATH vazio.
$GVM_SOCKET_LINE
$GVM_HOST_LINE
$GVM_PORT_LINE
GVM_USERNAME=$GVM_USERNAME
GVM_PASSWORD=$GVM_PASSWORD

# ── Autenticação do dashboard ─────────────────────────────────────────────────
APP_USERNAME=admin
APP_PASSWORD=$APP_PASSWORD

# ── JWT ──────────────────────────────────────────────────────────────────────
# Gere um novo segredo com: openssl rand -hex 32
JWT_SECRET=$JWT_SECRET
JWT_EXPIRE_MINUTES=480

# ── Sincronização ─────────────────────────────────────────────────────────────
SYNC_INTERVAL_MINUTES=30

# ── Armazenamento ─────────────────────────────────────────────────────────────
DATA_DIR=$DATA_DIR

# ── CORS ─────────────────────────────────────────────────────────────────────
CORS_ORIGINS=http://localhost:5173,http://localhost:3000
EOF

    chown "$SERVICE_USER:$SERVICE_USER" "$ENV_FILE"
    chmod 640 "$ENV_FILE"
    info ".env criado em $ENV_FILE"

    if [[ -z "$GVM_PASSWORD" ]]; then
        warn "GVM_PASSWORD não definido no .env — edite antes de iniciar o serviço:"
        warn "  nano $ENV_FILE"
    fi
fi

# Garantir DATA_DIR no .env
grep -q "^DATA_DIR=" "$ENV_FILE" || echo "DATA_DIR=$DATA_DIR" >> "$ENV_FILE"

# ── Backend: virtualenv + dependências ───────────────────────────────────────
section "Configurando backend Python"

python3 -m venv "$INSTALL_DIR/backend/.venv"
"$INSTALL_DIR/backend/.venv/bin/pip" install --upgrade pip -q
"$INSTALL_DIR/backend/.venv/bin/pip" install -r "$INSTALL_DIR/backend/requirements.txt" -q
info "Dependências Python instaladas"

# ── Frontend: build estático ──────────────────────────────────────────────────
section "Build do frontend React"

cd "$INSTALL_DIR/frontend"
npm install --silent
npm run build --silent

mkdir -p "$FRONTEND_DIST"
rsync -a --delete dist/ "$FRONTEND_DIST/"
info "Frontend buildado e copiado para $FRONTEND_DIST"

# ── Nginx ─────────────────────────────────────────────────────────────────────
section "Configurando nginx"

if [[ -d /etc/nginx/sites-available ]]; then
    NGINX_CONF=/etc/nginx/sites-available/ovdash
    cp "$INSTALL_DIR/deploy/nginx.conf" "$NGINX_CONF"
    ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/ovdash
    [[ -f /etc/nginx/sites-enabled/default ]] && \
        rm -f /etc/nginx/sites-enabled/default && \
        warn "Site 'default' do nginx desabilitado"
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
echo -e "  ${GREEN}Dashboard:${NC}      http://$IP"
echo -e "  ${GREEN}API docs:${NC}       http://$IP/api/docs"
echo -e "  ${GREEN}Config:${NC}         $ENV_FILE"
echo -e "  ${GREEN}Dados (DB):${NC}     $DATA_DIR"
echo ""
if [[ "$GVM_INSTALL_TYPE" == "docker" ]]; then
    echo -e "  ${CYAN}Modo GVM:${NC}       Docker (relay socat ativo em /run/gvmd.sock)"
    echo -e "             Serviço: systemctl status gvmd-relay"
elif [[ "$GVM_INSTALL_TYPE" == "native" ]]; then
    echo -e "  ${CYAN}Modo GVM:${NC}       Nativo Linux ($DETECTED_SOCKET)"
else
    echo -e "  ${YELLOW}Atenção:${NC}        Socket GVM não detectado — configure GVM_HOST ou GVM_SOCKET_PATH no .env"
fi
echo ""
echo -e "  Logs:     journalctl -u ovdash-backend -f"
echo -e "  Parar:    systemctl stop ovdash-backend"
echo -e "  Status:   systemctl status ovdash-backend"
echo ""
warn "Se editou o .env, reinicie: systemctl restart ovdash-backend"
echo ""
