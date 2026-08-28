"""
Endpoints de hosts.

Segurança:
- Requer autenticação (VIEWER+)
- Erros internos sanitizados
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from ..auth import RequireViewer
from ..database import get_db

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/hosts", tags=["hosts"])


@router.get("")
async def list_hosts(
    user: RequireViewer,
    search: Optional[str] = Query(None, max_length=64, description="Filtrar por IP/hostname"),
):
    """Lista hosts com contagem de vulnerabilidades por severidade."""
    try:
        async with get_db() as db:
            conditions: list[str] = []
            params: list = []

            if search:
                conditions.append("host LIKE ?")
                params.append(f"%{search}%")

            where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

            rows = await db.execute_fetchall(
                f"""SELECT
                      host,
                      COUNT(*) as total,
                      SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical,
                      SUM(CASE WHEN severity = 'High'     THEN 1 ELSE 0 END) as high,
                      SUM(CASE WHEN severity = 'Medium'   THEN 1 ELSE 0 END) as medium,
                      SUM(CASE WHEN severity = 'Low'      THEN 1 ELSE 0 END) as low,
                      SUM(CASE WHEN severity = 'Log'      THEN 1 ELSE 0 END) as log,
                      MAX(cvss) as max_cvss,
                      MIN(first_seen) as first_seen
                    FROM vulnerabilities {where}
                    GROUP BY host
                    ORDER BY critical DESC, high DESC, total DESC""",
                params,
            )
            return [dict(r) for r in rows]
    except Exception:
        log.exception("HOSTS_LIST_ERROR user=%s", user.username)
        raise HTTPException(status_code=500, detail="Erro ao carregar hosts.")


@router.get("/{host_id}")
async def get_host(host_id: str, user: RequireViewer):
    """Retorna vulnerabilidades de um host específico."""
    if len(host_id) > 64:
        raise HTTPException(status_code=422, detail="host inválido.")
    try:
        async with get_db() as db:
            rows = await db.execute_fetchall(
                """SELECT id, port, severity, cvss, nvt_name, cves, first_seen
                   FROM vulnerabilities
                   WHERE host = ?
                   ORDER BY cvss DESC, severity""",
                [host_id],
            )
            if not rows:
                raise HTTPException(status_code=404, detail="Host não encontrado.")
            return {
                "host": host_id,
                "vulnerabilities": [dict(r) for r in rows],
            }
    except HTTPException:
        raise
    except Exception:
        log.exception("HOST_GET_ERROR host=%s user=%s", host_id, user.username)
        raise HTTPException(status_code=500, detail="Erro ao carregar host.")
