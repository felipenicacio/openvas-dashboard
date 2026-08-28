# Security Policy

## Supported Version
The active security hardening target is OpenVAS Dashboard v1.1.0. Until that release passes the project Security Gate, the application should be treated as under active hardening rather than production-security-complete.

## Security Context
This application processes sensitive infrastructure security information, including hosts, ports, CVEs, vulnerability descriptions, scan information and administrative GVM operations.

## Reporting a Vulnerability
Do not publish exploit details, credentials, tokens, sensitive OpenVAS data or infrastructure information in a public GitHub issue.

Report suspected security vulnerabilities privately to the repository owner, Felipe Nicácio, through an available private GitHub communication channel. Include only the minimum evidence required to reproduce and assess the issue.

## Security Baseline
Production releases must satisfy the baseline documented in `docs/security/security-baseline.md`.

Core requirements include:
- no usable default credentials;
- fail-secure configuration;
- strong password hashing;
- protected session cookies;
- explicit JWT validation;
- CSRF protection and authentication rate limiting;
- server-side RBAC;
- HTTPS and restrictive CORS;
- security headers;
- sanitized errors and secure logging;
- restricted `.env` and database permissions;
- hardened systemd service;
- dependency, SAST and secret scanning;
- automated security tests.

## Secrets
Never commit passwords, GVM credentials, JWT secrets, private keys or production tokens. A confirmed exposed secret must be revoked or rotated, not merely removed from the latest commit.

Sensitive runtime credentials (`GVM_PASSWORD`, `JWT_SECRET`) are supplied through systemd credentials (`LoadCredential`), not via plaintext `.env` variables. The legacy `.env` approach for these two secrets is deprecated in v1.2.0 and will be removed in v1.3.0. `APP_PASSWORD_HASH` is an Argon2id hash (irreversible) and may remain in `.env`.

GVM_PASSWORD legacy (`.env`): deprecated — use systemd credential `gvm_password`.
JWT_SECRET legacy (`.env`): deprecated — use systemd credential `jwt_secret`.

## Security Gate
A release is blocked by any unresolved Critical issue, unresolved High issue, confirmed valid secret exposure, failed required security test or failed security build gate unless an exceptional risk decision is explicitly documented and approved.