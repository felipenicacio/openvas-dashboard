# Security Policy

## Supported Version

OpenVAS Dashboard v1.1.0 is the currently supported security baseline and has passed the project Security Gate.

Future releases must pass the Security Gate before being considered security-supported for production use.

## Security Context
This application processes sensitive infrastructure security information, including hosts, ports, CVEs, vulnerability descriptions, scan information and administrative GVM operations.

## Reporting a Vulnerability

Use [GitHub Private Vulnerability Reporting](https://github.com/felipenicacio/openvas-dashboard/security/advisories/new) to report suspected security vulnerabilities.

Do not disclose exploit details, credentials, tokens, infrastructure information, or sensitive OpenVAS data in public issues.

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

## Security Gate
A release is blocked by any unresolved Critical issue, unresolved High issue, confirmed valid secret exposure, failed required security test or failed security build gate unless an exceptional risk decision is explicitly documented and approved.