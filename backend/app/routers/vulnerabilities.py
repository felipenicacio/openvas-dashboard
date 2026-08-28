"""
Endpoints de vulnerabilidades.

Segurança:
- Requer autenticação (VIEWER+)
- Erros internos sanitizados — stack traces nunca expostos ao cliente
- Paginação obrigatória (page/page_size) para evitar dumps completos
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from ..auth import RequireViewer
from ..database import get_db

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])

_MAX_PAGE_SIZE = 200


@router.get("")
async def list_vulnerabilities(
    user: RequireViewer,
    page: int = Query(1, ge=1, description="Página (começa em 1)"),
    page_size: int = Query(50, ge=1, le=_MAX_PAGE_SIZE, description="Itens por página"),
    severity: Optional[str] = Query(None, description="Filtrar por severidade"),
    host: Optional[str] = Query(None, max_length=64, description="Filtrar por host"),
    search: Optional[str] = Query(None, max_length=128, description="Busca por nome"),
):
    """Lista vulnerabilidades com paginação e filtros opcionais."""
    try:
        async with get_db() as db:
            conditions: list[str] = []
            params: list = []

            if severity:
                conditions.append("severity = ?")
                params.append(severity)
            if host:
                conditions.append("host LIKE ?")
                params.append(f"%{host}%")
            if search:
                conditions.append("nvt_name LIKE ?")
                params.append(f"%{search}%")

            where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
            offset = (page - 1) * page_size

            count_rows = await db.execute_fetchall(
                f"SELECT COUNT(*) as n FROM vulnerabilities {where}", params
            )
            total = count_rows[0]["n"] if count_rows else 0

            rows = await db.execute_fetchall(
                f"""SELECT id, host, port, severity, cvss, nvt_name, cves, first_seen, report_id
                    FROM vulnerabilities {where}
                    ORDER BY cvss DESC, severity, host
                    LIMIT ? OFFSET ?""",
                params + [page_size, offset],
            )

            return {
                "total": total,
                "page": page,
                "page_size": page_size,
                "pages": max(1, -(-total // page_size)),
                "items": [dict(r) for r in rows],
            }
    except HTTPException:
        raise
    except Exception:
        log.exception("VULN_LIST_ERROR user=%s", user.username)
        raise HTTPException(status_code=500, detail="Erro ao carregar vulnerabilidades.")


@router.get("/{vuln_id}")
async def get_vulnerability(vuln_id: int, user: RequireViewer):
    """Retorna detalhes de uma vulnerabilidade específica."""
    try:
        async with get_db() as db:
            rows = await db.execute_fetchall(
                "SELECT * FROM vulnerabilities WHERE id = ?", [vuln_id]
            )
            if not rows:
                raise HTTPException(status_code=404, detail="Vulnerabilidade não encontrada.")
            return dict(rows[0])
    except HTTPException:
        raise
    except Exception:
        log.exception("VULN_GET_ERROR id=%s user=%s", vuln_id, user.username)
        raise HTTPException(status_code=500, detail="Erro ao carregar vulnerabilidade.")
