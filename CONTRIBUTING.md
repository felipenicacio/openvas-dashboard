# Contributing

## Governance
OpenVAS Dashboard uses three coordinated sources of truth:
- Notion for approved product, architecture, security and decision context;
- Linear for work management, scope and acceptance criteria;
- GitHub for source code, branches, Pull Requests, tests and implementation evidence.

## Before Starting
1. Confirm a Linear issue exists for the change.
2. Read `CLAUDE.md`, `AI_USAGE_POLICY.md` and applicable documentation under `docs/`.
3. Review current code and dependencies.
4. Evaluate security impact for authentication, authorization, session, APIs, persistence, logging, GVM integration, infrastructure or deployment changes.

## Branches and Pull Requests
Use a dedicated branch for relevant changes. Keep changes small, reviewable and tied to one clear objective.

Do not automatically merge security hardening changes. Critical security changes require explicit review before merge.

## Required Quality Checks
Run applicable backend tests, frontend build/typecheck and configured security checks. Report any check that could not be executed.

Do not bypass or suppress security findings without a specific documented reason.

## Secrets and Sensitive Data
Never commit secrets, credentials, private keys, production exports or sensitive logs. Use environment configuration for secrets.

## Documentation
Update README, architecture, security baseline or ADRs whenever the implementation changes operational behavior, architecture, security or deployment.

## Definition of Done
A change is complete when:
- Linear acceptance criteria are satisfied;
- tests are executed and passing as applicable;
- security impact is addressed;
- documentation is consistent with the code;
- no secret is exposed;
- blocking CI findings are resolved;
- residual risk is documented where required.

## Traceability
Requirement → Linear Issue → Branch → Pull Request/Commit → Tests → Release.