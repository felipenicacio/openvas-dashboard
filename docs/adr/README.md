# Architecture Decision Records

## Purpose
Use ADRs to preserve significant architecture and security decisions for the OpenVAS Dashboard.

## When an ADR is Required
Create or update an ADR when a change materially affects:
- authentication or session architecture;
- authorization or RBAC;
- persistence model;
- GVM integration;
- deployment or infrastructure;
- trust boundaries;
- security controls with architectural impact;
- introduction of a significant dependency or external service.

Routine bug fixes, styling changes and implementation details that do not alter an architectural decision normally do not require an ADR.

## Naming
Use sequential files such as:

`ADR-001-short-decision-title.md`

## Minimum Structure
Each ADR should contain:
- Status;
- Context;
- Decision;
- Alternatives considered when relevant;
- Security and operational impact;
- Consequences;
- Related Linear issue and Pull Request.

## Governance
Notion remains the strategic source of truth for approved decisions. ADRs provide the version-controlled technical record alongside the code.

If an ADR and an approved Notion decision diverge, resolve the inconsistency before implementation or release.