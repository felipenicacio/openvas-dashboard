# OpenVAS Dashboard — Security Hardening v1.2.0

## Runtime Secret Management

- **GVM_PASSWORD** e **JWT_SECRET** são fornecidos via systemd credentials (`LoadCredential`).
- **APP_PASSWORD_HASH** permanece no `.env` por ser um hash Argon2id irreversível.
- A aplicação resolve os credentials por meio de `CREDENTIALS_DIRECTORY`.
- Validações de JWT são aplicadas ao valor resolvido em runtime.
- Arquivos de credential devem ser `root:root 0600`.
- Configuração ausente ou inválida falha de forma segura.
- Valores de secrets nunca devem ser registrados em logs.

## Controles de segurança

### Autenticação e sessão
- **Argon2id** para armazenamento da senha do dashboard.
- **Cookie HttpOnly** para sessão JWT, sem uso de `localStorage`.
- **SameSite=Strict** e **Secure=true** no cookie de sessão em produção.
- Claims JWT: `sub`, `exp`, `iat`, `nbf`, `iss`, `aud`, `jti`, `role`.
- Validação explícita de issuer, audience e algoritmo.
- Revogação de token por `jti` no logout.

### Controle de acesso (RBAC)
| Papel   | `GET /api/scans` | `/api/scans/sync` | `/api/scans/:id/start` | PDF export |
|---------|:---:|:---:|:---:|:---:|
| VIEWER  | ✓   | —   | —   | ✓   |
| ANALYST | ✓   | ✓   | —   | ✓   |
| ADMIN   | ✓   | ✓   | ✓   | ✓   |

### Rate limiting
- 5 tentativas de login por IP por minuto.
- Resposta `429 Too Many Requests` com header `Retry-After: 60`.
- IP extraído via `X-Real-IP` definido pelo nginx.

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
- Middleware valida `Origin` ou `Referer` em requisições mutantes sobre `/api/*`.
- Endpoint de login (`/api/auth/token`) é isento.
- Complementa `SameSite=Strict` no cookie de sessão.

### Outros controles
- CORS cross-origin desabilitado por padrão.
- Swagger/OpenAPI desabilitado por padrão (`ENABLE_API_DOCS=false`).
- `task_id` e `scan_id` validados como UUID RFC 4122 antes de chegar ao GVM.
- Stack traces não são expostos ao cliente.
- Exportação PDF limitada a 5.000 linhas.
- Dados do OpenVAS são sanitizados antes da geração de PDF.

---

## Checklist de produção

Execute antes de colocar em produção:

- [ ] Executar `install.sh` — cria `jwt_secret` em `/etc/openvas-dashboard/credentials/` quando necessário.
- [ ] Criar `/etc/openvas-dashboard/credentials/gvm_password` com a senha GVM de forma segura.
- [ ] Confirmar permissões `600 root:root` nos arquivos de credential.
- [ ] Gerar `APP_PASSWORD_HASH` com `python backend/generate_hash.py`.
- [ ] Definir `APP_PASSWORD_HASH` e demais configurações não secretas no `.env`.
- [ ] Confirmar que o `.env` contém apenas configurações não secretas e hashes não reversíveis.
- [ ] Confirmar permissão restritiva do `.env` (`chmod 640 .env`).
- [ ] Confirmar que `.env` não está no repositório (`git status`).
- [ ] Confirmar `ENABLE_API_DOCS=false` no `.env`.
- [ ] Confirmar `COOKIE_SECURE=true` no `.env`.
- [ ] Confirmar `APP_ENV=production` no `.env`.
- [ ] Habilitar HTTPS com TLS 1.2+1.3.
- [ ] Ativar HSTS após validar HTTPS.
- [ ] Serviço rodando como usuário `ovdash`.
- [ ] Verificar hardening systemd: `systemd-analyze security ovdash-backend`.
- [ ] Executar `pip-audit -r backend/requirements.txt` sem CVEs críticos.
- [ ] Executar `npm audit --audit-level=high` no frontend sem vulnerabilidades altas.
- [ ] Executar `bandit -r backend/app` sem issues de nível alto.

---

## Configuração rápida

### 1. Configurar a aplicação

```bash
sudo cp .env.example /opt/openvas-dashboard/.env
sudo nano /opt/openvas-dashboard/.env
```

No `.env`, configure `APP_PASSWORD_HASH` e as demais opções não secretas.

Os secrets de runtime são mantidos em:
- `/etc/openvas-dashboard/credentials/jwt_secret`
- `/etc/openvas-dashboard/credentials/gvm_password`

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

- **Rate limiting**: mantido em memória — reiniciar o processo zera os contadores. Para multi-processo/multi-worker, usar armazenamento compartilhado.
- **Revogação de JTI**: lista em memória — reiniciar remove o estado de revogação. Para produção crítica, usar armazenamento compartilhado com TTL.
- **Usuário único**: a versão atual suporta um único usuário administrativo configurado pela aplicação. RBAC com múltiplos usuários está planejado para versão futura.

---

## CI/CD

O workflow `.github/workflows/security.yml` executa:
- `pip-audit`: CVEs em dependências Python
- `bandit`: análise estática de segurança
- Testes de segurança (`pytest backend/tests/`)
- `npm audit`: vulnerabilidades no frontend
- TypeScript type check
- CodeQL para Python e JavaScript via GitHub Code Scanning

O `dependabot.yml` abre PRs para dependências desatualizadas.