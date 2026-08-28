#!/usr/bin/env bash
# install.sh — OpenVAS Dashboard v1.2.0
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
ENV_FILE="$INSTALL_DIR/.env"

echo "=== OpenVAS Dashboard v1.2.0 — Instalação ==="
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
    --exclude='.venv/' \
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
if [[ -f "$ENV_FILE" ]]; then
    chown root:ovdash "$ENV_FILE"
    chmod 640 "$ENV_FILE"
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

# ── Estrutura de systemd credentials ─────────────────────────────────────────
# Gerenciamento seguro de secrets em produção (preferencial ao .env)
echo "Configurando estrutura de systemd credentials..."

CREDS_DIR="/etc/openvas-dashboard/credentials"
JWT_CRED="$CREDS_DIR/jwt_secret"
GVM_CRED="$CREDS_DIR/gvm_password"

# Criar estrutura (idempotente)
install -d -m 700 -o root -g root /etc/openvas-dashboard
install -d -m 700 -o root -g root "$CREDS_DIR"

# ── JWT_SECRET: quatro cenários de instalação ─────────────────────────────────
# C.  Credential já existe → preservar sempre (nunca sobrescrever)
# B1. .env existe + JWT_SECRET no formato padrão → migrar (hex-64) ou manual
# B2. .env existe + JWT_SECRET em formato não padrão → AMBÍGUO → fail-secure
# A.  Nova instalação comprovada → gerar com CSPRNG
#
# REGRA FAIL-SECURE: nunca gerar novo JWT signing key enquanto .env existir sem
# prova inequívoca de que JWT_SECRET não está presente em nenhum formato.
#
# Motivo: grep/cut cobre apenas ^JWT_SECRET=valor (sem espaços ao redor do =).
# pydantic-settings (via python-dotenv) interpreta formatos alternativos válidos
# como "JWT_SECRET = valor" — que grep não detecta. Sem esta proteção, um upgrade
# sobre um .env com esse formato substituiria silenciosamente o signing key,
# invalidando todas as sessões JWT ativas.

# Helper: detecta JWT_SECRET via pydantic-settings (qualquer formato dotenv).
# Exit 0  = JWT_SECRET encontrado com valor não-vazio.
# Exit 1  = JWT_SECRET ausente ou vazio.
# Em erro → exit 0 (fail-secure: assume presença, impede geração acidental).
# NUNCA imprime o valor do secret — sinaliza apenas presença/ausência.
_jwt_found_in_env() {
    local env_file="$1"
    local py_bin
    if [ -x "$VENV/bin/python3" ]; then
        py_bin="$VENV/bin/python3"
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

if [ -f "$JWT_CRED" ]; then
    # Caso C: já migrado — credential existente preservada.
    # AVISO: jwt_secret é o signing key dos tokens JWT.
    # Substituí-lo invalida TODAS as sessões ativas. Rotação requer
    # procedimento administrativo explícito — não remova este arquivo acidentalmente.
    echo "[INFO] jwt_secret credential já existe em $JWT_CRED — preservando."

elif [ -f "$ENV_FILE" ]; then
    # .env EXISTE — análise obrigatória antes de qualquer geração.
    # Nunca gerar novo signing key com .env presente sem prova de ausência.

    # Tentativa de extração no formato padrão (JWT_SECRET=valor, sem espaços ao redor do =)
    jwt_raw=$(grep -m1 '^JWT_SECRET=' "$ENV_FILE" | cut -d= -f2-)

    if [ -n "$jwt_raw" ]; then
        # Caso B1: grep detectou JWT_SECRET no formato padrão.
        # SEGURANÇA: auto-migração segura apenas para formato hex-64 puro.
        #
        # Motivo: grep/cut extrai o valor RAW do .env (sem interpretar dotenv).
        # pydantic-settings interpreta o valor SEMÂNTICO (remove aspas, etc.).
        # Se raw ≠ semântico, gravar o raw corromperia o signing key e invalidaria
        # todas as sessões JWT existentes.
        #
        # Formato hex-64 (openssl rand -hex 32):
        #   JWT_SECRET=a1b2c3...  → raw == semântico → auto-migração segura
        #
        # Formatos que BLOQUEIAM auto-migração (raw ≠ semântico):
        #   JWT_SECRET="a1b2c3..." → raw inclui aspas → signing key diferente
        #   JWT_SECRET='a1b2c3...' → idem aspas simples
        #   JWT_SECRET=valor com espaço → raw ≠ o que pydantic interpreta
        #   JWT_SECRET=abc=def     → não é hex-64
        #
        # A variável jwt_raw existe apenas enquanto necessário — removida com unset.
        if printf '%s' "$jwt_raw" | grep -qE '^[0-9a-fA-F]{64}$'; then
            # Formato seguro: gravar diretamente via pipe, nunca via arquivo intermediário
            echo "[MIGRATION] JWT_SECRET legacy detectado em $ENV_FILE (formato hex-64 seguro)."
            echo "[MIGRATION] Migrando para systemd credential (sessões existentes preservadas)..."
            printf '%s' "$jwt_raw" \
                | install -m 600 -o root -g root /dev/stdin "$JWT_CRED"
            unset jwt_raw
            echo "[MIGRATION] jwt_secret migrado para $JWT_CRED"
            echo "[MIGRATION] Após verificar que o serviço inicia corretamente,"
            echo "[MIGRATION] remova JWT_SECRET do .env e reinicie o serviço:"
            echo "[MIGRATION]   sudo sed -i '/^JWT_SECRET=/d' $ENV_FILE"
            echo "[MIGRATION]   sudo systemctl restart $SERVICE_NAME"
        else
            unset jwt_raw
            echo "[MANUAL] JWT_SECRET detectado em $ENV_FILE."
            echo "[MANUAL] Auto-migração desativada: valor não é hex-64 puro."
            echo "[MANUAL] Motivo: grep/cut não interpreta dotenv — aspas, espaços ou"
            echo "[MANUAL]   chars especiais produziriam raw ≠ semântico, corrompendo"
            echo "[MANUAL]   o JWT signing key e invalidando TODAS as sessões ativas."
            echo "[MANUAL] O serviço iniciará em modo legacy (.env) até migração manual."
            echo "[MANUAL]"
            echo "[MANUAL] Para migrar com segurança (cole o valor sem aspas/espaços extras):"
            echo "[MANUAL]   sudo install -m 600 -o root -g root /dev/null $JWT_CRED"
            echo "[MANUAL]   sudo sudoedit $JWT_CRED"
            echo "[MANUAL]   # O valor deve ser idêntico ao que pydantic-settings interpreta."
            echo "[MANUAL]   # Após verificar que o serviço funciona:"
            echo "[MANUAL]   sudo sed -i '/^JWT_SECRET=/d' $ENV_FILE"
            echo "[MANUAL]   sudo bash deploy/install.sh   # atualiza o drop-in systemd"
        fi

    else
        # grep ^JWT_SECRET= não detectou — verificar semanticamente via pydantic-settings
        # para cobrir formatos alternativos como "JWT_SECRET = valor" (espaços ao redor do =).
        unset jwt_raw
        if _jwt_found_in_env "$ENV_FILE"; then
            # Caso B2: pydantic encontrou JWT_SECRET em formato não padrão.
            # Fail-secure: não gerar novo secret — signing key legado preservado.
            echo "[AMBIGUOUS] JWT_SECRET detectado semanticamente em $ENV_FILE,"
            echo "[AMBIGUOUS] mas em formato não extraível inequivocamente por grep/cut"
            echo "[AMBIGUOUS] (possível: 'JWT_SECRET = valor' com espaços ao redor do '=')."
            echo "[AMBIGUOUS] NENHUM jwt_secret novo será gerado — signing key preservado."
            echo "[AMBIGUOUS] O serviço continuará em modo legacy (.env) até migração manual."
            echo "[AMBIGUOUS]"
            echo "[AMBIGUOUS] Para migrar com segurança:"
            echo "[AMBIGUOUS]   sudo install -m 600 -o root -g root /dev/null $JWT_CRED"
            echo "[AMBIGUOUS]   sudo sudoedit $JWT_CRED"
            echo "[AMBIGUOUS]   # Cole exatamente o valor que pydantic-settings interpreta,"
            echo "[AMBIGUOUS]   # sem aspas externas adicionais."
            echo "[AMBIGUOUS]   # Após verificar que o serviço funciona:"
            echo "[AMBIGUOUS]   sudo sed -i '/JWT_SECRET/d' $ENV_FILE"
            echo "[AMBIGUOUS]   sudo bash deploy/install.sh"
        else
            # pydantic também confirma ausência: nova instalação comprovada mesmo com .env.
            # Caso A parcial: geração CSPRNG segura.
            openssl rand -hex 32 | install -m 600 -o root -g root /dev/stdin "$JWT_CRED"
            echo "[INFO] jwt_secret gerado em $JWT_CRED"
            echo "[INFO] NUNCA copie este arquivo para fora do host."
        fi
    fi

else
    # Caso A: .env não existe → nova instalação comprovada → gerar com CSPRNG
    openssl rand -hex 32 | install -m 600 -o root -g root /dev/stdin "$JWT_CRED"
    echo "[INFO] jwt_secret gerado em $JWT_CRED"
    echo "[INFO] NUNCA copie este arquivo para fora do host."
fi

# ── GVM_PASSWORD: nunca auto-gerado ───────────────────────────────────────────
# O operador deve criar manualmente. Instrução segura: sem 'echo', sem exibir no terminal.
if [ ! -f "$GVM_CRED" ]; then
    echo ""
    echo "[WARN] gvm_password credential ausente: $GVM_CRED"
    echo "[WARN] Crie o arquivo com a senha do GVM (sem exibir no terminal):"
    echo "[WARN]   sudo install -m 600 -o root -g root /dev/null $GVM_CRED"
    echo "[WARN]   sudo sudoedit $GVM_CRED"
    echo "[WARN] Alternativa (tee redireciona stdout para /dev/null — sem exibição):"
    echo "[WARN]   read -rsp 'GVM password: ' GVM_PASS && printf '%s' \"\$GVM_PASS\" | sudo tee $GVM_CRED >/dev/null && unset GVM_PASS"
    echo "[WARN] Após criar o credential, execute este script novamente para atualizar"
    echo "[WARN] a configuração do serviço systemd."
    echo ""
fi

# ── Drop-in systemd credentials ───────────────────────────────────────────────
# O drop-in é gerado condicionalmente: apenas adiciona LoadCredential para os
# arquivos de credential que já existem. Isso garante backward compatibility:
# - Se o credential não existe, LoadCredential não é adicionado e o serviço
#   inicia em modo legacy (.env), sem falhar antes da aplicação.
# - Se o credential existe, LoadCredential é adicionado e tem precedência.
# - Após criar um novo credential, re-execute este script para atualizar o drop-in.
#
# Funciona em todas as versões de systemd (sem dependência de sintaxe opcional).
# Compatibilidade testada: Ubuntu 22.04 (systemd 249), Ubuntu 24.04 (systemd 255),
# Debian 12 (systemd 252). Versões mais antigas com systemd >= 246 (Ubuntu 20.04)
# também suportam LoadCredential via drop-in.
DROPIN_DIR="/etc/systemd/system/${SERVICE_NAME}.service.d"
DROPIN_FILE="$DROPIN_DIR/credentials.conf"
mkdir -p "$DROPIN_DIR"

{
    echo "# Auto-gerado por install.sh em $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "# NÃO edite manualmente — regenerado pelo install.sh"
    echo "[Service]"
    if [ -f "$JWT_CRED" ]; then
        echo "LoadCredential=jwt_secret:$JWT_CRED"
    fi
    if [ -f "$GVM_CRED" ]; then
        echo "LoadCredential=gvm_password:$GVM_CRED"
    fi
} > "$DROPIN_FILE"

# Permissões do drop-in: legível apenas por root
chmod 600 "$DROPIN_FILE"
echo "[INFO] Drop-in de credentials atualizado: $DROPIN_FILE"

# ── systemd ───────────────────────────────────────────────────────────────────
echo "Instalando serviço systemd..."
cp "$INSTALL_DIR/deploy/ovdash-backend.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

if [[ -f "$ENV_FILE" ]]; then
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
