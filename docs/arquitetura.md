# Arquitetura Técnica

## Visão Atual
OpenVAS/GVM → GMP → FastAPI → SQLite cache → API → React.

O backend é executado por Uvicorn em `127.0.0.1:8000`, publicado por nginx e integrado ao GVM por TLSConnection ou UnixSocketConnection.

## Componentes
- OpenVAS/GVM: origem dos scans, tasks e resultados.
- python-gvm/GMP: integração administrativa com o GVM.
- FastAPI: autenticação, API, sincronização, relatórios e operações administrativas.
- SQLite: cache local de vulnerabilidades, hosts, scans e logs de sincronização.
- React/TypeScript: dashboard e interface administrativa.
- nginx: publicação do frontend, reverse proxy e camada de TLS/security headers.
- systemd: execução e isolamento do backend.

## Trust Boundaries
1. Navegador ↔ nginx: tráfego administrativo; HTTPS obrigatório em produção.
2. nginx ↔ FastAPI: loopback local.
3. FastAPI ↔ GVM: canal administrativo sensível; preferir Unix socket quando local ou TLS restrito por firewall quando remoto.
4. FastAPI ↔ SQLite: dados sensíveis da infraestrutura; permissões locais mínimas.

## Dados Sensíveis
- IPs, hostnames e portas;
- CVEs e resultados de vulnerabilidade;
- tasks e reports do GVM;
- credenciais GVM e segredos da aplicação;
- eventos administrativos e dados de sessão.

## Restrições Arquiteturais da v1.1.0
- Preservar FastAPI, React, SQLite, nginx e systemd.
- Não introduzir Redis, PostgreSQL ou serviço externo obrigatório apenas para hardening.
- Não alterar o modelo funcional de histórico de findings nesta fase.
- Não executar o backend como root.
- Não expor diretamente a porta Uvicorn fora do loopback.

## Segurança Arquitetural
A baseline obrigatória está em `docs/security/security-baseline.md`.

Mudanças materiais em autenticação, autorização, persistência, GVM, infraestrutura ou deployment exigem Issue Linear e ADR quando alterarem uma decisão estrutural.