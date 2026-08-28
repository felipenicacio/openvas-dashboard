# OpenVAS Dashboard

Dashboard moderno para gestão de vulnerabilidades OpenVAS/GVM — inspirado em Nessus, Qualys e Rapid7.

## Preview

![OpenVAS Dashboard — Dashboard principal](docs/images/dashboard-preview.svg)

> Visão consolidada da postura de vulnerabilidades, com indicadores de exposição, distribuição por severidade, hosts afetados, scans ativos e evolução mensal.

## Stack

| Camada    | Tecnologia                                      |
|-----------|-------------------------------------------------|
| Backend   | Python 3.11 · FastAPI · python-gvm · SQLite     |
| Frontend  | React 18 · TypeScript · Tailwind CSS · Recharts |
| Protocolo | GMP via socket Unix (local) ou TLS (remoto)     |
| Deploy    | systemd + nginx (bare metal)                    |

## Funcionalidades

- **Dashboard** — Risk score, distribuição por severidade, evolução mensal, top hosts
- **Vulnerabilidades** — Tabela com filtros, busca, ordenação, drawer de detalhe com CVE links
- **Hosts** — Cards com risk score visual, drill-down de vulnerabilidades por host
- **Scans** — Lista tasks do GVM, inicia/para scans remotamente
- **Sync automática** — Scheduler busca dados do GVM a cada N minutos (configurável)
- **Sessão segura** — Autenticação via cookie HttpOnly (Argon2id + JWT, sem localStorage)

## Requisitos

- Linux com systemd (Ubuntu 22.04+ / Debian 12+ / RHEL 9+)
- Python 3.11+
- Node.js 20+
- nginx
- Acesso ao servidor GVM (socket Unix local ou TCP/TLS remoto)

```bash
# Ubuntu / Debian
apt install python3.11 python3.11-venv nodejs npm nginx rsync -y

# RHEL / Rocky / AlmaLinux
dnf install python3.11 nodejs npm nginx rsync -y
```

## Instalação

```bash
# 1. Clone o repositório
git clone https://github.com/felipenicacio/openvas-dashboard.git
cd openvas-dashboard

# 2. Crie o diretório de destino e configure o .env
sudo mkdir -p /opt/openvas-dashboard
sudo cp .env.example /opt/openvas-dashboard/.env
sudo nano /opt/openvas-dashboard/.env   # preencha os valores obrigatórios

# 3. Execute o instalador como root (detecta o diretório do clone automaticamente)
sudo bash deploy/install.sh
```

O instalador:
- Cria o usuário de sistema `ovdash` (se não existir)
- Copia os arquivos do repositório para `/opt/openvas-dashboard/`
- Cria o virtualenv Python e instala dependências
- Builda o frontend React
- Registra e inicia o serviço systemd `ovdash-backend`

## Configuração (.env)

Copie `.env.example` e preencha os campos obrigatórios:

```dotenv
# ── Conexão GVM ───────────────────────────────────────────────────────────────
# Perfil A — GVM local via socket Unix (recomendado):
GVM_SOCKET_PATH=/run/gvmd/gvmd.sock
GVM_USERNAME=admin
GVM_PASSWORD=senha-do-gvm

# Perfil B — GVM remoto via TLS (comentar GVM_SOCKET_PATH acima):
# GVM_HOST=192.168.1.100
# GVM_PORT=9390
# GVM_USERNAME=admin
# GVM_PASSWORD=senha-do-gvm

# ── Autenticação do dashboard ─────────────────────────────────────────────────
APP_USERNAME=operador           # nome de usuário para login
APP_PASSWORD_HASH=              # hash Argon2id — gere com: python backend/generate_hash.py

# ── JWT ───────────────────────────────────────────────────────────────────────
JWT_SECRET=                     # mínimo 32 bytes — gere com: openssl rand -hex 32
JWT_EXPIRE_MINUTES=30

# ── Cookie ────────────────────────────────────────────────────────────────────
COOKIE_SECURE=true              # false apenas em desenvolvimento HTTP local

# ── CORS ──────────────────────────────────────────────────────────────────────
# Deixar vazio quando nginx serve frontend e /api no mesmo domínio (same-origin).
# Definir apenas se frontend e API estiverem em origens distintas:
# CORS_ORIGINS=https://dashboard.sua-empresa.com

# ── Outros ────────────────────────────────────────────────────────────────────
APP_ENV=production
ENABLE_API_DOCS=false           # NUNCA true em produção
SYNC_INTERVAL_MINUTES=30
```

### Perfil A — GVM via socket Unix (recomendado)

Conceda acesso ao socket para o usuário do serviço:

```bash
sudo usermod -aG gvmd ovdash
sudo systemctl restart ovdash-backend
```

### Perfil B — GVM remoto via TLS

Edite `/etc/systemd/system/ovdash-backend.service` e adicione o IP do servidor GVM
à diretiva `IPAddressAllow` (veja comentários no arquivo). Recarregue:

```bash
sudo systemctl daemon-reload && sudo systemctl restart ovdash-backend
```

## Gerenciamento do serviço

```bash
# Status
systemctl status ovdash-backend

# Logs em tempo real
journalctl -u ovdash-backend -f

# Reiniciar (após alterar .env)
systemctl restart ovdash-backend
```

## Atualização

O script de instalação é idempotente — execute novamente após `git pull`:

```bash
cd openvas-dashboard
git pull
sudo bash deploy/install.sh
```

## Sincronização manual

Faça login no dashboard e clique em **"Sincronizar GVM"** na sidebar, ou via curl
(a sessão é gerenciada por cookie — use `-c`/`-b` para persistir):

```bash
# 1. Login (salva cookie na sessão; login é isento da verificação CSRF)
curl -s -X POST https://<servidor>/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"operador","password":"sua-senha"}' \
  -c cookies.txt

# 2. Sincronização manual (inclui Origin para passar o middleware CSRF)
curl -s -X POST https://<servidor>/api/scans/sync \
  -H "Origin: https://<servidor>" \
  -b cookies.txt
```

## Desenvolvimento local

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env  # edite: APP_ENV=development, COOKIE_SECURE=false
APP_ENV=development DATA_DIR=./data uvicorn app.main:app --reload --port 8000

# Frontend (outro terminal)
cd frontend
npm install
npm run dev
# Acesse http://localhost:5173
```

## Estrutura do projeto

```
openvas-dashboard/
├── backend/
│   ├── app/
│   │   ├── main.py           # FastAPI + middleware + scheduler
│   │   ├── config.py         # Settings (pydantic-settings, fail-secure)
│   │   ├── csrf.py           # Middleware CSRF (Origin/Referer)
│   │   ├── auth.py           # JWT + RBAC + cookie HttpOnly
│   │   ├── security.py       # Argon2id, revogação de JTI
│   │   ├── gvm_client.py     # Wrapper GMP (python-gvm)
│   │   ├── sync.py           # Sync GVM → SQLite
│   │   ├── database.py       # SQLite cache + init
│   │   ├── models/schemas.py # Pydantic schemas
│   │   └── routers/          # auth · dashboard · vulns · hosts · scans
│   ├── tests/
│   │   └── test_security.py  # Testes de segurança (pytest)
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/            # Dashboard · Vulnerabilities · Hosts · Scans
│   │   ├── components/       # Layout · SeverityBadge · RiskGauge · StatCard
│   │   ├── api/client.ts     # Axios + interceptors (cookie auth)
│   │   └── types/index.ts    # TypeScript types
│   └── package.json
├── deploy/
│   ├── ovdash-backend.service  # Systemd unit (hardened)
│   ├── nginx.conf              # Configuração nginx (proxy reverso)
│   └── install.sh              # Script de instalação
├── .env.example
└── README-security.md          # Detalhes de segurança e checklist de produção
```

## API

Autenticação via cookie de sessão HttpOnly (definido no login, enviado automaticamente
pelo browser). Documentação interativa disponível quando `ENABLE_API_DOCS=true`
(apenas em desenvolvimento).

| Endpoint                    | Método | Auth   | Descrição                     |
|-----------------------------|--------|--------|-------------------------------|
| `/api/auth/token`           | POST   | —      | Login (define cookie sessão)  |
| `/api/auth/logout`          | POST   | ✓      | Logout (revoga sessão)        |
| `/api/auth/me`              | GET    | ✓      | Perfil do usuário autenticado |
| `/api/dashboard/summary`    | GET    | ✓      | KPIs, trend, top hosts        |
| `/api/vulnerabilities`      | GET    | ✓      | Lista com filtros e paginação |
| `/api/vulnerabilities/{id}` | GET    | ✓      | Detalhe de uma vulnerab.      |
| `/api/hosts`                | GET    | ✓      | Lista hosts com risk score    |
| `/api/hosts/{ip}`           | GET    | ✓      | Host + vulnerabilidades       |
| `/api/scans`                | GET    | ✓      | Tasks do GVM                  |
| `/api/scans/{id}/start`     | POST   | ✓ ADMIN  | Inicia scan                   |
| `/api/scans/{id}/stop`      | POST   | ✓ ADMIN  | Para scan                     |
| `/api/scans/sync`           | POST   | ✓ ANALYST| Sincronização manual com GVM  |
| `/api/health`               | GET    | —      | Status mínimo do serviço      |

## Licença

MIT
