# CLAUDE.md

## Project
OpenVAS Dashboard — Vulnerability Management Platform

Repository: https://github.com/felipenicacio/openvas-dashboard

## Role
Claude acts as the Lead Developer for this project. Implementation must follow the approved architecture, security baseline and Linear acceptance criteria.

## Sources of Truth
1. Notion — product vision, architecture, security baseline, decisions and approved requirements.
2. Linear — backlog, priority, dependencies and acceptance criteria.
3. GitHub — current source code, branches, commits, Pull Requests, tests and technical evidence.
4. AI proposals — advisory only and subordinate to the sources above.

## Mandatory Pre-Execution Flow
Before any significant change:
1. Identify the corresponding Linear issue.
2. Read this file and `AI_USAGE_POLICY.md`.
3. Read the applicable architecture and security documentation under `docs/`.
4. Inspect the current implementation before proposing structural changes.
5. Evaluate security impact, dependencies, regression risk and required tests.
6. Update ADRs when architecture or security decisions materially change.

## Security Rules
- Never commit secrets, tokens, credentials, private keys or production data.
- Never disable security controls merely to make a build or test pass.
- Do not rely on frontend checks for authorization.
- Authentication, authorization, session, API, logging, infrastructure and GVM integration changes require explicit security impact analysis.
- Treat OpenVAS/GVM data as sensitive administrative security information.
- Preserve least privilege, fail-secure, secure-by-default and defense-in-depth principles.
- Do not expose passwords, JWTs, cookies, JWT secrets or GVM credentials in logs or errors.

## Change Control
Structural changes to authentication, authorization, database design, GVM integration, infrastructure or deployment require a Linear issue and documented rationale.

Use a dedicated branch and Pull Request for relevant changes. Security hardening changes must not be merged automatically.

## Testing
Run all applicable tests and explicitly report what was and was not executed. Never claim successful validation without evidence.

Minimum security validation for v1.1.0 includes backend tests, frontend build/typecheck, Bandit/SAST, dependency audit and secret scanning when configured.

## Documentation
Update documentation whenever a change affects behavior, architecture, security, infrastructure, deployment or operational procedures.

A task is not complete only because code was changed. Acceptance criteria, tests, documentation and residual risk must also be addressed.

## Traceability
Requirement → Linear Issue → Branch → Code → Pull Request/Commit → Tests → Release.

## Final Report
For relevant implementations report:
- files changed;
- tests executed;
- security impact;
- known limitations;
- residual risks;
- documentation updated;
- PR/commit reference.
