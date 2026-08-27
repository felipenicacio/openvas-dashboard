# OpenVAS Dashboard

Dashboard moderno para gestão de vulnerabilidades OpenVAS/GVM — com visualizações em tempo real, relatórios PDF e sincronização automática.

> **Nota:** Para adicionar uma captura de tela, coloque um arquivo `screenshot.png` na raiz do projeto.

---

## Stack

| Camada      | Tecnologia                                                         |
|-------------|--------------------------------------------------------------------|
| Backend     | Python 3.11 · FastAPI · python-gvm 22.9 · aiosqlite · fpdf2       |
| Frontend    | React 18 · TypeScript · Tailwind CSS · Recharts · TanStack Table  |
| Protocolo   | GMP (Greenbone Management Protocol) via socket Unix ou TLS        |
| Deploy      | systemd + nginx (bare metal)                                       |
| Auth        | JWT (python-jose) · bcrypt (passlib)                              |

---

## Funcionalidades

- **Dashboard** — Risk score 0–10, distribuição por severidade, tendência mensal, top hosts críticos
- **Vulnerabilidades** — Tabela paginada com filtros, busca full-text, ordenação, drawer de detalhe com links CVE
- **Exportação PDF** — Relatório completo ou filtrado por scan, com sumário executivo e tabela colorida por severidade
- **Hosts** — Cards com risk score visual, drill-down de vulnerabilidades por host
- **Scans** — Lista de tasks do GVM, iniciar/parar scans remotamente
- **Sync automática** — Scheduler integrado busca dados do GVM a cada N minutos (configurável)
- **JWT Auth** — Login simples com token de sessão seguro

---

## Pré-requisitos

### Sistema

- Linux com systemd (Ubuntu 22.04+ / Debian 12+ / RHEL 9+)
- Python 3.11+
- Node.js 20+
- nginx
- root / sudo para a instalação

```bash
# Ubuntu / Debian
apt install python3.11 python3.11-venv python3-pip nodejs npm nginx openssl -y

# RHEL / Rocky / AlmaLinux
dnf install python3.11 python3-pip nodejs npm nginx openssl -y
```

### GVM instalado — escolha um dos modos

**Modo A — Docker (Greenbone Community Edition):**

```bash
# Se ainda não tiver instalado:
git clone https://github.com/greenbone/openvas-smb.git   # ou use a imagem oficial
# Ou com o compose da Greenbone:
curl -fsSL https://greenbone.github.io/docs/latest/_static/setup-and-start-greenbone-community-edition.sh | bash
```

O instalador detecta automaticamente o socket Docker e configura o relay socat.

**Modo B — GVM nativo Linux (instalado diretamente no host):**

```bash
apt install gvm -y
gvm-setup   # configura usuário e inicia serviços
```

---

## Instalação (automática)

```bash
# 1. Clone o repositório
git clone https://github.com/felipenicacio/openvas-dashboard.git
cd openvas-dashboard

# 2. Execute o instalador como root
sudo bash deploy/install.sh
```

O script faz automaticamente:

1. Verifica pré-requisitos (Python, Node, nginx, openssl)
2. Instala `pip` se ausente
3. **Detecta GVM**: Docker vs nativo Linux
   - Docker: instala `socat` se necessário, cria e ativa `gvmd-relay.service`
   - Nativo: detecta o caminho do socket automaticamente
4. Cria o usuário de sistema `ovdash`
5. Copia os arquivos para `/opt/openvas-dashboard/` (preservando o diretório `data/`)
6. **Gera o `.env`** interativamente (sem senhas hardcoded):
   - `JWT_SECRET` gerado com `openssl rand -hex 32`
   - Solicita `APP_PASSWORD` e credenciais GVM
7. Cria o virtualenv Python e instala dependências (incluindo fpdf2)
8. Builda o frontend React e copia para `/var/www/ovdash/`
9. Configura nginx e ativa o site
10. Registra e inicia `ovdash-backend.service`

Após a instalação, acesse: **`http://<ip-do-servidor>`**

---

## Pós-instalação

Se precisar ajustar configurações:

```bash
sudo nano /opt/openvas-dashboard/.env
sudo systemctl restart ovdash-backend
```

Para verificar se está funcionando:

```bash
systemctl status ovdash-backend
curl -s http://localhost/api/health
```

---

## Docker GVM — Relay socat

Quando o GVM é instalado via Docker (Greenbone Community Edition), o socket gvmd fica dentro de um volume Docker:

```
/var/lib/docker/volumes/greenbone-community-edition_gvmd_socket_vol/_data/gvmd.sock
```

O instalador configura automaticamente o serviço `gvmd-relay` que usa `socat` para expor esse socket em `/run/gvmd.sock`, acessível ao backend:

```
Docker volume socket  ──socat──►  /run/gvmd.sock  ──►  ovdash-backend
```

O serviço `gvmd-relay` depende de `docker.service` e reinicia automaticamente em falhas.

Para verificar:

```bash
systemctl status gvmd-relay
journalctl -u gvmd-relay -f
```

---

## GVM Nativo Linux

Se o GVM estiver instalado diretamente no host (não Docker), o instalador detecta o socket em um destes caminhos:

- `/run/gvmd/gvmd.sock`
- `/var/run/gvmd/gvmd.sock`
- `/tmp/gvmd.sock`

E adiciona o usuário `ovdash` ao grupo do socket para acesso:

```bash
# Verificar grupo do socket
stat -c '%G' /run/gvmd/gvmd.sock
# Adicionar manualmente se necessário
usermod -aG gvmd ovdash
systemctl restart ovdash-backend
```

---

## Configuração (.env)

Arquivo: `/opt/openvas-dashboard/.env`

| Variável               | Descrição                                                        | Exemplo                          |
|------------------------|------------------------------------------------------------------|----------------------------------|
| `GVM_SOCKET_PATH`      | Caminho do socket Unix GVM (deixe vazio para modo rede)         | `/run/gvmd.sock`                 |
| `GVM_HOST`             | IP/hostname do servidor GVM (modo TLS)                          | `192.168.1.100`                  |
| `GVM_PORT`             | Porta GMP TLS (padrão: 9390)                                    | `9390`                           |
| `GVM_USERNAME`         | Usuário do GVM (gvmd)                                           | `admin`                          |
| `GVM_PASSWORD`         | Senha do GVM — **obrigatório**                                  | —                                |
| `APP_USERNAME`         | Usuário do dashboard web                                        | `admin`                          |
| `APP_PASSWORD`         | Senha do dashboard — **obrigatório**                            | —                                |
| `JWT_SECRET`           | Segredo JWT (gere: `openssl rand -hex 32`)                      | —                                |
| `JWT_EXPIRE_MINUTES`   | Validade do token em minutos                                    | `480`                            |
| `SYNC_INTERVAL_MINUTES`| Intervalo de sincronização automática com GVM                   | `30`                             |
| `DATA_DIR`             | Diretório do banco SQLite                                       | `/opt/openvas-dashboard/data`    |
| `CORS_ORIGINS`         | Origens CORS permitidas (separadas por vírgula)                 | `http://localhost:5173`          |

---

## Segurança

### Trocar a senha do dashboard

Edite `APP_PASSWORD` no `.env` e reinicie:

```bash
sudo nano /opt/openvas-dashboard/.env
sudo systemctl restart ovdash-backend
```

### Rotacionar o JWT_SECRET

Gere um novo segredo e reinicie (todas as sessões ativas serão invalidadas):

```bash
openssl rand -hex 32
# Cole o resultado em JWT_SECRET no .env
sudo systemctl restart ovdash-backend
```

### Permissões do .env

O arquivo `.env` é criado com permissão `640` (leitura apenas pelo dono e grupo). Nunca versione com senhas reais — ele já está no `.gitignore`.

---

## Gerenciamento do Serviço

```bash
# Status
systemctl status ovdash-backend

# Logs em tempo real
journalctl -u ovdash-backend -f

# Reiniciar (obrigatório após editar .env)
systemctl restart ovdash-backend

# Parar / iniciar
systemctl stop ovdash-backend
systemctl start ovdash-backend

# Relay socat (apenas instalações Docker)
systemctl status gvmd-relay
systemctl restart gvmd-relay
```

---

## Atualização

```bash
cd /caminho/para/openvas-dashboard
git pull

# Reinstala dependências, rebuilda o frontend e reinicia o serviço
sudo bash deploy/install.sh
```

O script é idempotente — preserva o `.env` e o diretório `data/` (banco SQLite) existentes.

---

## Relatórios PDF

O dashboard inclui exportação de relatórios PDF com:

- **Cabeçalho** com título e data de geração
- **Sumário executivo**: total de vulnerabilidades, risk score e contagem por severidade
- **Tabela detalhada**: Host, Porta, Severidade (colorida), CVSS, Nome da Vulnerabilidade, CVEs, Primeira Detecção
- **Cores por severidade**: Critical (vermelho), High (laranja), Medium (âmbar), Low (verde), Log (cinza)
- **Rodapé** com numeração de páginas e data

### Como usar

Na página **Vulnerabilidades**, selecione um scan no seletor ou deixe em "Todos os scans" e clique em **Exportar PDF**.

Via API:

```bash
# Exportar todas as vulnerabilidades
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost/api/reports/pdf -o report.pdf

# Filtrar por scan específico
curl -H "Authorization: Bearer $TOKEN" \
     "http://localhost/api/reports/pdf?scan_id=<report_id>" -o report.pdf
```

---

## API Reference

Documentação interativa disponível em `http://<servidor>/api/docs`

| Endpoint                          | Método | Descrição                          |
|-----------------------------------|--------|------------------------------------|
| `/api/auth/token`                 | POST   | Login (retorna JWT)                |
| `/api/health`                     | GET    | Status da API                      |
| `/api/dashboard/summary`          | GET    | KPIs, trend, top hosts             |
| `/api/vulnerabilities`            | GET    | Lista com filtros e paginação      |
| `/api/vulnerabilities/{id}`       | GET    | Detalhe de uma vulnerabilidade     |
| `/api/hosts`                      | GET    | Lista hosts com risk score         |
| `/api/hosts/{ip}`                 | GET    | Host + vulnerabilidades            |
| `/api/scans`                      | GET    | Tasks do GVM                       |
| `/api/scans/{id}/start`           | POST   | Inicia scan                        |
| `/api/scans/{id}/stop`            | POST   | Para scan                          |
| `/api/scans/sync`                 | POST   | Sincronização manual com GVM       |
| `/api/reports/pdf`                | GET    | Exportar relatório PDF             |
| `/api/reports/pdf?scan_id=<id>`   | GET    | PDF filtrado por scan              |

---

## Desenvolvimento Local

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env   # edite com suas configurações locais
DATA_DIR=./data uvicorn app.main:app --reload --port 8000

# Frontend (outro terminal)
cd frontend
npm install
npm run dev
# Acesse http://localhost:5173
```

A variável `VITE_API_URL` não é necessária — o Vite proxy redireciona `/api` para `localhost:8000`.

### Primeira Sincronização

Após configurar o `.env`, faça login e clique em **Sincronizar** na sidebar, ou via curl:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/token \
  -d "username=admin&password=SUA_SENHA" | jq -r .access_token)

curl -X POST http://localhost:8000/api/scans/sync \
  -H "Authorization: Bearer $TOKEN"
```

---

## Estrutura do Projeto

```
openvas-dashboard/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app + scheduler
│   │   ├── config.py            # Settings (pydantic-settings)
│   │   ├── gvm_client.py        # Wrapper GMP (python-gvm)
│   │   ├── sync.py              # Sync GVM → SQLite
│   │   ├── database.py          # SQLite cache + init
│   │   ├── auth.py              # JWT + CurrentUser
│   │   ├── models/schemas.py    # Pydantic schemas
│   │   └── routers/
│   │       ├── auth.py
│   │       ├── dashboard.py
│   │       ├── vulnerabilities.py
│   │       ├── hosts.py
│   │       ├── scans.py
│   │       └── reports.py       # Exportação PDF
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/               # Dashboard · Vulnerabilities · Hosts · Scans
│   │   ├── components/          # Layout · SeverityBadge · RiskGauge · StatCard
│   │   ├── api/client.ts        # Axios + interceptors
│   │   └── types/index.ts       # TypeScript types
│   └── package.json
├── deploy/
│   ├── ovdash-backend.service   # Systemd unit (backend)
│   ├── gvmd-relay.service       # Systemd unit (relay socat Docker)
│   ├── nginx.conf               # Configuração nginx
│   └── install.sh               # Script de instalação automatizado
├── .env.example                 # Modelo de configuração (sem senhas)
└── README.md
```

---

## Licença

MIT
