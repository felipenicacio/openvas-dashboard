# OpenVAS Dashboard — Security Hardening v1.2.0

## O que mudou na v1.2.0

### Runtime Secret Management via systemd credentials
- **GVM_PASSWORD** e **JWT_SECRET** migrados para systemd `LoadCredential` (preferencial em produção)
- Sensitive runtime credentials são fornecidas via systemd credentials, não em texto claro no `.env`
- Suporte legado ao `.env` mantido até a v1.3.0 com aviso explícito de deprecação (`SECURITY WARNING`); removido na v1.3.0
- **APP_PASSWORD_HASH** permanece no `.env` — é hash Argon2id irreversível, não é um secret recuperável
- Camada `resolve_secret()` em `config.py` com precedência: systemd credential > legacy .env > fail-secure
- Validações JWT (`mínimo 32 chars`, valor não inseguro) aplicadas ao valor **resolvido** (não ao raw .env)
- Arquivos de credential: `root:root 0600`, entregues via `CREDENTIALS_DIRECTORY` pelo systemd
- Fail-secure: sem nenhuma fonte válida → recusa startup com `ValueError`
- Nunca loga valores de secrets (nem parcialmente)

## O que mudou na v1.1.0

### Autenticação e sessão
- **Argon2id** (argon2-cffi) substituiu comparação de senha em texto puro
- **Cookie HttpOnly** substituiu armazenamento do JWT em `localStorage`: o cookie `HttpOnly` é inacessível ao JavaScript, impedindo que XSS extraia o token de sessão
- **SameSite=Strict** e **Secure=true** habilitados no cookie de sessão
- **Claims JWT completos**: `sub`, `exp`, `iat`, `nbf`, `iss`, `aud`, `jti`, `role`
- **Validação explícita** de issuer, audience e algoritmo (whitelist `["HS256"]`)
- **Revogação de token por `jti`** no logout (in-memory, single-process)

### Controle de acesso (RBAC)
| Papel   | `GET /api/scans` | `/api/scans/sync` | `/api/scans/:id/start` | PDF export |
|---------|:---:|:---:|:---:|:---:|
| VIEWER  | ✓   | —   | —   | ✓   |
| ANALYST | ✓   | ✓   | —   | ✓   |
| ADMIN   | ✓   | ✓   | ✓   | ✓   |

### Rate limiting
- 5 tentativas de login por IP por minuto (in-memory)
- Resposta `429 Too Many Requests` com header `Retry-After: 60`
- IP extraído via `X-Real-IP` (definido pelo nginx) — não via `X-Forwarded-For`, que é controlável pelo cliente e pode ser forjado para bypass

### Security headers
Todos os endpoints retornam:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
Content-Security-Policy: default-src 'none'; script-src 'self'; ...
```

### CSRF
- Middleware valida header `Origin` (ou `Referer` como fallback) em toda requisição mutante (`POST`, `PUT`, `PATCH`, `DELETE`) sobre `/api/*`
- Endpoint de login (`/api/auth/token`) isento — sem cookie pré-existente para proteger
- O comportamento de `Origin` em same-origin varia por browser e contexto (XHR tipicamente omite, `fetch` pode incluir); o Referer é usado como fallback quando `Origin` está ausente, garantindo cobertura em ambos os casos
- Complementa `SameSite=Strict` no cookie de sessão (defesa em profundidade)

### Outros controles
- CORS cross-origin desabilitado por padrão (same-origin deployment via nginx); habilitado apenas quando `CORS_ORIGINS` é definido explicitamente
- Swagger/OpenAPI desabilitado por padrão (`ENABLE_API_DOCS=false`)
- `/api/health` retorna apenas `{"status":"ok","version":"1.1.0"}`
- `task_id` e `scan_id` validados como UUID RFC 4122 antes de chegar ao GVM
- Stack traces nunca expostos ao cliente (apenas logados internamente)
- Exportação PDF limitada a 5.000 linhas (proteção anti-DoS)
- Dados do OpenVAS sanitizados via `_safe()` antes de inserir no PDF

---

## Checklist de produção

Execute antes de colocar em produção:

- [ ] Executar `install.sh` — cria `jwt_secret` automaticamente em `/etc/openvas-dashboard/credentials/`
- [ ] Criar `/etc/openvas-dashboard/credentials/gvm_password` com a senha GVM (manualmente, sem `echo`)
- [ ] Confirmar permissões `600 root:root` em ambos os arquivos de credential
- [ ] Gerar hash da senha com `python backend/generate_hash.py`
- [ ] Definir `APP_PASSWORD_HASH` (e demais configs não-secret) no `.env`
- [ ] Confirmar que `.env` **não** contém `GVM_PASSWORD` nem `JWT_SECRET` (após migração)
- [ ] Confirmar que `.env` tem permissão `640` (`chmod 640 .env`)
- [ ] Confirmar que `.env` **não** está no repositório (`git status`)
- [ ] Confirmar `ENABLE_API_DOCS=false` no `.env`
- [ ] Confirmar `COOKIE_SECURE=true` no `.env`
- [ ] Confirmar `APP_ENV=production` no `.env`
- [ ] Habilitar HTTPS com TLS 1.2+1.3 (ver `deploy/nginx-https.conf`)
- [ ] Ativar HSTS após validar HTTPS (`Strict-Transport-Security`)
- [ ] Serviço rodando como usuário `ovdash` (nunca `root`)
- [ ] Verificar hardening systemd: `systemd-analyze security ovdash-backend`
- [ ] Executar `pip-audit -r backend/requirements.txt` sem CVEs críticos
- [ ] Executar `npm audit --audit-level=high` no frontend sem vulnerabilidades altas
- [ ] Executar `bandit -r backend/app` sem issues de nível alto

---

## Configuração rápida

### 1. Copiar e configurar .env

```bash
sudo cp .env.example /opt/openvas-dashboard/.env
sudo nano /opt/openvas-dashboard/.env
```

Preencher obrigatoriamente no `.env`:
- `APP_PASSWORD_HASH` — gerado com `python backend/generate_hash.py`
- Demais configurações não-secret (veja `.env.example`)

Gerenciar via systemd credentials (não no `.env`):
- `jwt_secret` — gerado automaticamente pelo `install.sh` em `/etc/openvas-dashboard/credentials/jwt_secret`
- `gvm_password` — criado manualmente pelo operador em `/etc/openvas-dashboard/credentials/gvm_password`

### 2. Instalar

```bash
sudo bash deploy/install.sh
```

### 3. Configurar nginx com HTTPS

```bash
# Gerar certificado autoassinado (dev) ou usar Let's Encrypt (prod)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/openvas-dashboard/key.pem \
    -out /etc/ssl/openvas-dashboard/cert.pem \
    -subj "/CN=openvas-dashboard"

sudo cp deploy/nginx-https.conf /etc/nginx/sites-available/openvas-dashboard
sudo ln -sf /etc/nginx/sites-available/openvas-dashboard \
            /etc/nginx/sites-enabled/openvas-dashboard
sudo nginx -t && sudo systemctl reload nginx
```

---

## Limitações conhecidas (single-process)

- **Rate limiting**: mantido em memória — reiniciar o processo zera os contadores. Para multi-processo/multi-worker, usar slowapi + Redis.
- **Revogação de JTI**: lista em memória — reiniciar invalida tokens revogados. Para produção crítica, usar Redis com TTL = expiração do token.
- **Usuário único**: a v1.1.0 suporta um único usuário com papel ADMIN no .env. RBAC múltiplo (múltiplos usuários) está planejado para versão futura.

---

## CI/CD

O workflow `.github/workflows/security.yml` executa:
- `pip-audit`: CVEs em dependências Python
- `bandit`: análise estática de segurança
- Testes de segurança (`pytest backend/tests/test_security.py`)
- `npm audit`: vulnerabilidades no frontend
- TypeScript type check
- CodeQL para Python e JavaScript — via **GitHub Default Setup** (Settings → Security → Code scanning), não via `security.yml` (conflito com advanced configuration evitado)

O `dependabot.yml` abre PRs semanais para dependências desatualizadas (pip, npm, GitHub Actions).
