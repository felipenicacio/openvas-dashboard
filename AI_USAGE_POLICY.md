# AI Usage Policy

## Purpose
Define mandatory rules for the use of AI assistants in the OpenVAS Dashboard project.

## Approved Roles
- ChatGPT: architecture, security/privacy review, threat modeling, requirements and validation.
- Claude: Lead Developer for code analysis, implementation, testing, controlled refactoring and Pull Requests.

## Prohibited Data
Never provide or commit through AI workflows:
- production credentials or passwords;
- JWT secrets or session tokens;
- private keys or certificates containing private material;
- real GVM/OpenVAS credentials;
- confidential production exports when not required;
- personal or sensitive data without justified need.

## Mandatory Rules
- AI output is not authoritative by itself.
- Notion, Linear and GitHub remain the project sources of truth.
- AI must inspect current code before structural changes.
- Security controls must not be bypassed to solve development problems.
- New dependencies require justification and security review.
- Security-sensitive changes require tests and review.
- AI-generated changes must be reviewed through diff/PR before merge.
- Significant architecture or security decisions require documentation or ADR updates.

## Transparency
AI-assisted work must state what was analyzed, what was changed, tests executed, assumptions, limitations and residual risks.

## Traceability
Every relevant implementation must maintain traceability between requirement, Linear issue, branch, code, Pull Request/commit, tests and release.

## Security and Privacy Impact
An explicit impact assessment is required for changes involving authentication, authorization, RBAC, session, APIs, persistence, logging, infrastructure, external integrations, files, secrets or deployment.

## Definition of Done
AI-assisted work is complete only when acceptance criteria, testing, documentation, security impact and residual risks have been addressed.