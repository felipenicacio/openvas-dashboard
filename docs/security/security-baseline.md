# Security Baseline

## Objetivo
Definir os controles mínimos obrigatórios para uma versão do OpenVAS Dashboard adequada para produção.

## Authentication and Session
- Nenhuma credencial default utilizável.
- Configuração fail-secure para segredos obrigatórios.
- Password hashing forte, preferencialmente Argon2id.
- JWT com algoritmo explícito, `exp`, `iat`, `iss`, `aud` e `jti`.
- Sessão via cookie HttpOnly, Secure em produção e SameSite adequado.
- Logout suportado.
- Rate limiting para autenticação.
- Proteção CSRF para operações state-changing.

## Authorization
- RBAC server-side com VIEWER, ANALYST e ADMIN.
- VIEWER: leitura e relatórios.
- ANALYST: leitura + sincronização manual GVM.
- ADMIN: permissões anteriores + iniciar/interromper scans.
- Frontend nunca é a única camada de autorização.

## API
- Rotas sensíveis autenticadas.
- `/api/health` retorna apenas estado mínimo.
- Swagger/OpenAPI controlável e desabilitado por padrão em produção.
- Entradas validadas e limitadas.
- Identificadores GVM validados antes do envio.
- Erros internos não são expostos ao cliente.

## Transport and Browser Security
- HTTPS obrigatório em produção.
- TLS 1.2/1.3.
- CORS restritivo.
- Content-Security-Policy sem `unsafe-eval`.
- X-Content-Type-Options.
- Referrer-Policy.
- Permissions-Policy.
- Proteção contra framing.
- HSTS somente em implantação HTTPS validada.

## Secrets and Local Data
- `.env` com permissões mínimas.
- SQLite, WAL, SHM e DATA_DIR acessíveis apenas ao usuário autorizado do serviço.
- Segredos nunca versionados ou emitidos em logs.
- Segredo confirmado exposto deve ser revogado/rotacionado.

## Runtime Hardening
- Backend executado como `ovdash`, nunca root.
- Uvicorn restrito ao loopback.
- systemd com NoNewPrivileges, PrivateTmp, ProtectSystem e demais controles compatíveis documentados no projeto.

## Logging
Registrar eventos administrativos relevantes sem registrar senhas, JWTs, cookies, JWT_SECRET ou GVM_PASSWORD.

## GVM
- Preferir Unix socket quando GVM e dashboard estiverem no mesmo host.
- Para conexão remota, utilizar TLS e firewall restrito entre dashboard e GVM.
- Nunca recomendar exposição pública da porta administrativa GVM.

## Secure SDLC
- Dependency scanning para pip e npm.
- SAST.
- Secret scanning.
- Dependabot.
- CI com permissões mínimas.
- Testes automatizados dos controles de segurança.

## Security Gate v1.1.0
- Critical = 0 aberto.
- High = 0 aberto.
- Medium corrigido, mitigado ou formalmente aceito.
- Nenhum secret válido exposto.
- Build e testes obrigatórios aprovados.
- Risco residual documentado.

## Referências
- OWASP ASVS.
- OWASP API Security Top 10.
- CWE.
- NIST Secure Software Development Framework — SSDF.