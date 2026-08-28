# OpenVAS Dashboard — Projeto

## Objetivo
Evoluir o OpenVAS Dashboard como uma aplicação administrativa segura para visualização, operação e gestão contínua de vulnerabilidades integrada ao OpenVAS/GVM.

## Governança
- Notion: visão do produto, arquitetura, security baseline, decisões e roadmap.
- Linear: backlog, prioridades, dependências, marcos e critérios de aceite.
- GitHub: código-fonte, branches, Pull Requests, CI/CD e evidências técnicas.

## Escopo Atual
A prioridade é o Security Hardening v1.1.0, preservando as funcionalidades existentes.

Ficam fora deste incremento inicial:
- histórico persistente de findings;
- lifecycle completo de vulnerabilidades;
- SLA e aging avançados;
- remediation workflow;
- EPSS e CISA KEV;
- CMDB e criticidade de ativos;
- SSO corporativo.

## Fases
1. Governança e documentação técnica.
2. Security Hardening v1.1.0.
3. Security Review e release.
4. Vulnerability Management Lifecycle.
5. SLA, aging e remediation workflow.
6. Priorização contextual.
7. Reporting executivo e integrações.

## Princípios
Secure by default, fail secure, least privilege, defense in depth, rastreabilidade e segregação entre conhecimento, gestão do trabalho e código.

## Fluxo
Notion → Linear → análise do GitHub → implementação → testes → Pull Request → revisão → merge → atualização de documentação → release.

## Repositório
https://github.com/felipenicacio/openvas-dashboard
