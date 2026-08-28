# OpenVAS Dashboard

Dashboard moderno para gestão de vulnerabilidades OpenVAS/GVM — inspirado em Nessus, Qualys e Rapid7.

## Stack

| Camada     | Tecnologia                                      |
|------------|-------------------------------------------------|
| Backend    | Python 3.11 · FastAPI · python-gvm · SQLite     |
| Frontend   | React 18 · TypeScript · Tailwind CSS · Recharts |
| Protocolo  | GMP (Greenbone Management Protocol) via TLS     |
| Deploy     | systemd + nginx (bare metal)                    |

## Funcionalidades

- **Dashboard** — Risk score, distribuição por severidade, evolução mensal, top hosts
- **Vulnerabilidades** — Tabela com filtros, busca, ordenação, drawer de detalhe com CVE links
- **Hosts** — Cards com risk score visual, drill-down de vulnerabilidades por host
- **Scans** — Lista tasks do GVM, inicia/para scans remotamente
- **Sync automática** — Scheduler busca dados do GVM a cada N minutos (configurável)
- **JWT Auth** — Login simples com token de sessão

## Requisitos

- Linux com systemd (Ubuntu 22.04+ / Debian 12+ / RHEL 9+)
- Python 3.11+
- Node.js 20+
- nginx
- Acesso de rede ao servidor GVM (porta 9390 por padrão)

```bash
# Ubuntu / Debian
apt install python3.11 python3.11-venv nodejs npm nginx -y

# RHEL / Rocky / AlmaLinux
dnf install python3.11 nodejs npm nginx -y
```

## Instalação (automática)

```bash
# 1. Clone o repositório
git clone https://github.com/felipenicacio/openvas-dashboard.git
cd openvas-dashboard

# 2. Execute o instalador como root
sudo bash deploy/install.sh
```

O script faz automaticamente:
- Cria o usuário de sistema `ovdash`
- Instala os arquivos em `/opt/openvas-dashboard/`
- Cria o virtualenv Python e instala dependências
- Builda o frontend e copia para `/var/www/ovdash/`
- Configura e ativa o site no nginx
- Registra e inicia o serviço systemd `ovdash-backend`

Após a instalação, edite o `.env` com os dados do seu GVM:

```bash
sudo nano /opt/openvas-dashboard/.env
sudo systemctl restart ovdash-backend
```

Acesse: **http://\<ip-do-servidor\>**

## Configuração (.env)

```dotenv
# Conexão GVM
GVM_HOST=192.168.1.100
GVM_PORT=9390
GVM_USERNAME=admin
GVM_PASSWORD=senha-do-gvm

# Autenticação do dashboard
APP_USERNAME=admin
APP_PASSWORD=sua-senha-aqui

# JWT (obrigatório — gere com: openssl rand -hex 32)
JWT_SECRET=seu-segredo-aqui

# Sincronização automática (minutos)
SYNC_INTERVAL_MINUTES=30

# Onde o SQLite fica armazenado
DATA_DIR=/opt/openvas-dashboard/data
```

## Usando Unix Socket (GVM local)

Se o GVM rodar na mesma máquina:

```dotenv
GVM_SOCKET_PATH=/run/gvmd/gvmd.sock
# deixe GVM_HOST vazio
```

Conceda acesso ao socket para o usuário do serviço:

```bash
sudo usermod -aG gvmd ovdash
sudo systemctl restart ovdash-backend
```

## Gerenciamento do serviço

```bash
# Status
systemctl status ovdash-backend

# Logs em tempo real
journalctl -u ovdash-backend -f

# Reiniciar (após alterar .env)
systemctl restart ovdash-backend

# Parar / iniciar
systemctl stop ovdash-backend
systemctl start ovdash-backend
```

## Atualização

```bash
cd /caminho/para/openvas-dashboard
git pull

# Reinstala dependências e rebuilda o frontend
sudo bash deploy/install.sh
```

O script de instalação é idempotente — pode ser executado novamente sem perda de dados ou configuração.

## Primeira sincronização

Após configurar o `.env`, faça login no dashboard e clique em **"Sincronizar GVM"** na sidebar, ou via curl:

```bash
TOKEN=$(curl -s -X POST http://localhost/api/auth/token \
  -d "username=admin&password=sua-senha" | jq -r .access_token)

curl -X POST http://localhost/api/scans/sync \
  -H "Authorization: Bearer $TOKEN"
```

## Desenvolvimento local

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env  # edite conforme necessário
DATA_DIR=./data uvicorn app.main:app --reload --port 8000

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
│   │   ├── main.py           # FastAPI + scheduler
│   │   ├── config.py         # Settings (pydantic-settings)
│   │   ├── gvm_client.py     # Wrapper GMP (python-gvm)
│   │   ├── sync.py           # Sync GVM → SQLite
│   │   ├── database.py       # SQLite cache + init
│   │   ├── auth.py           # JWT
│   │   ├── models/schemas.py # Pydantic schemas
│   │   └── routers/          # dashboard · vulns · hosts · scans · auth
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/            # Dashboard · Vulnerabilities · Hosts · Scans
│   │   ├── components/       # Layout · SeverityBadge · RiskGauge · StatCard
│   │   ├── api/client.ts     # Axios + interceptors
│   │   └── types/index.ts    # TypeScript types
│   └── package.json
├── deploy/
│   ├── ovdash-backend.service  # Systemd unit
│   ├── nginx.conf              # Configuração nginx (host)
│   └── install.sh              # Script de instalação automatizado
└── .env.example
```

## API

Documentação interativa disponível em `http://<servidor>/api/docs` após a instalação.

| Endpoint                         | Método | Descrição                      |
|----------------------------------|--------|--------------------------------|
| `/api/auth/token`                | POST   | Login (retorna JWT)            |
| `/api/dashboard/summary`         | GET    | KPIs, trend, top hosts         |
| `/api/vulnerabilities`           | GET    | Lista com filtros e paginação  |
| `/api/vulnerabilities/{id}`      | GET    | Detalhe de uma vuln            |
| `/api/hosts`                     | GET    | Lista hosts com risk score     |
| `/api/hosts/{ip}`                | GET    | Host + vulnerabilidades        |
| `/api/scans`                     | GET    | Tasks do GVM                   |
| `/api/scans/{id}/start`          | POST   | Inicia scan                    |
| `/api/scans/{id}/stop`           | POST   | Para scan                      |
| `/api/scans/sync`                | POST   | Sincronização manual com GVM   |

## Licença

MIT
