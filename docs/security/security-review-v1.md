# Security Review — v1.1.0

## Status
Baseline criada para acompanhar o hardening e registrar evidências antes da liberação da versão 1.1.0.

## Escopo
- autenticação e sessão;
- autorização e RBAC;
- proteção CSRF e rate limiting;
- API e validação de entradas;
- TLS, nginx, CORS e security headers;
- systemd, permissões locais e SQLite;
- integração GVM;
- logging e tratamento de erros;
- dependências e supply chain;
- testes automatizados e CI.

## Findings Iniciais
1. Credenciais e segredos possuem defaults inadequados para produção.
2. Senha administrativa é comparada diretamente e precisa de hashing forte.
3. JWT é armazenado em localStorage e a sessão precisa de hardening.
4. Ausência de rate limiting e proteção CSRF adequada ao novo modelo de sessão.
5. Autenticação existe, mas falta RBAC para operações administrativas GVM.
6. Deployment padrão utiliza HTTP e precisa de TLS/security headers.
7. CORS está permissivo além do necessário.
8. Erros de sincronização podem expor detalhes internos.
9. Hardening systemd pode ser ampliado sem alterar a arquitetura.
10. CI de segurança, dependency scanning, SAST e secret scanning precisam ser formalizados.

## Pontos Positivos da Baseline Atual
- Uvicorn restrito a `127.0.0.1`.
- nginx como reverse proxy.
- serviço executado como usuário dedicado `ovdash`.
- uso de queries parametrizadas nas rotas revisadas.
- allowlist para campos de ordenação.
- NoNewPrivileges, PrivateTmp e ProtectSystem já presentes no systemd.

## Security Gate
A v1.1.0 somente poderá ser liberada quando:
- não houver Critical aberto;
- não houver High aberto;
- Medium estiver corrigido, mitigado ou formalmente aceito;
- nenhum segredo válido estiver exposto;
- testes e builds obrigatórios estiverem aprovados;
- risco residual estiver documentado;
- o Pull Request de hardening tiver revisão explícita.

## Evidências a Registrar
- Pull Requests e commits;
- resultados de testes;
- Bandit/SAST;
- pip-audit e npm audit;
- secret scanning;
- validação nginx/TLS/headers;
- validação systemd e permissões;
- decisões de risco residual.

## Resultado Final
Preencher ao concluir as issues de hardening e antes do release v1.1.0. Este arquivo não deve declarar controles como implementados sem evidência correspondente no código, CI ou configuração.