# CLAUDE.md

## Projeto
OpenVAS Dashboard — Vulnerability Management Platform.

Repositório oficial: https://github.com/felipenicacio/openvas-dashboard

## Fontes de verdade
1. Notion: visão do produto, arquitetura, requisitos, security baseline, decisões e roadmap.
2. Linear: backlog, prioridades, dependências, milestones e critérios de aceite.
3. GitHub: código, branches, commits, Pull Requests, testes e evidências.

## Papéis
- Felipe Nicácio: proprietário do projeto, aprovador de decisões relevantes e aceite de risco residual.
- ChatGPT: arquitetura, segurança, privacidade, threat modeling e revisão crítica.
- Claude: Lead Developer para análise do código, implementação, testes, refatoração controlada e preparação de Pull Requests.

## Fluxo obrigatório
Notion → Linear → análise do GitHub → proposta → implementação → testes → Pull Request → revisão → merge → atualização documental.

Antes de qualquer alteração significativa:
1. Identifique a Issue Linear correspondente.
2. Consulte a documentação aplicável no Notion.
3. Leia os arquivos de governança do repositório.
4. Analise o estado atual do código.
5. Avalie impacto de segurança e privacidade.
6. Implemente somente o escopo aprovado.

## Segurança obrigatória
O OpenVAS Dashboard é uma aplicação administrativa de segurança e processa informações sensíveis sobre ativos, IPs, portas, CVEs, vulnerabilidades e resultados de scans.

Aplicar sempre:
- Secure by Default.
- Fail Secure.
- Least Privilege.
- Defense in Depth.
- Default Deny.
- Server-side authorization.
- Validação de entradas.
- Proteção de segredos.
- Logging seguro.
- Gestão segura de dependências.
- Não regressão de controles de segurança.

## Security Impact obrigatório
Avaliação explícita antes de mudanças envolvendo autenticação, autorização, RBAC, sessão, APIs, persistência, logs, infraestrutura, integração GVM, arquivos, credenciais, dependências, deployment ou controles de segurança.

## Restrições
- Nunca inserir segredos, tokens, senhas, hashes reais de produção ou dados de produção em prompts, código, commits ou documentação.
- Nunca desabilitar controles de segurança apenas para fazer build ou teste passar.
- Nunca afirmar que um teste foi executado sem evidência real.
- Não executar mudanças estruturais sem Issue Linear correspondente.
- Não alterar arquitetura funcional fora do escopo aprovado.
- Não executar FastAPI como root.
- Não expor GVM publicamente.

## Definition of Done
Uma alteração só está concluída quando:
- critérios de aceite foram atendidos;
- testes aplicáveis foram executados;
- Security Impact foi tratado;
- documentação foi atualizada;
- nenhum segredo foi exposto;
- CI não possui falha bloqueante;
- risco residual foi registrado quando aplicável;
- mudança crítica foi revisada por Felipe Nicácio.
