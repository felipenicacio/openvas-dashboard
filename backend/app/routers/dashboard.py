"""
Dashboard — métricas agregadas de vulnerabilidades.

Segurança:
- Requer autenticação (VIEWER+)
- Erros internos não expostos ao cliente
"""

import logging

from fastapi import APIRouter, HTTPException

from ..auth import RequireViewer
from ..database import get_db

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary")
async def summary(user: RequireViewer):
    """Retorna contagens de vulnerabilidades por severidade."""
    try:
        async with get_db() as db:
            rows = await db.execute_fetchall(
                "SELECT severity, COUNT(*) as n FROM vulnerabilities GROUP BY severity"
            )
            counts = {r["severity"]: r["n"] for r in rows}
            total = sum(counts.values())

            host_count = await db.execute_fetchall(
                "SELECT COUNT(DISTINCT host) as n FROM vulnerabilities"
            )
            hosts = host_count[0]["n"] if host_count else 0

            return {
                "total": total,
                "hosts": hosts,
                "by_severity": counts,
            }
    except Exception:
        log.exception("DASHBOARD_SUMMARY_ERROR user=%s", user.username)
        raise HTTPException(status_code=500, detail="Erro ao carregar resumo.")


@router.get("/trend")
async def trend(user: RequireViewer):
    """Retorna tendência de vulnerabilidades ao longo do tempo."""
    try:
        async with get_db() as db:
            rows = await db.execute_fetchall(
                """SELECT DATE(first_seen) as day, severity, COUNT(*) as n
                   FROM vulnerabilities
                   WHERE first_seen IS NOT NULL
                   GROUP BY day, severity
                   ORDER BY day DESC
                   LIMIT 90"""
            )
            return [dict(r) for r in rows]
    except Exception:
        log.exception("DASHBOARD_TREND_ERROR user=%s", user.username)
        raise HTTPException(status_code=500, detail="Erro ao carregar tendência.")


@router.get("/top-hosts")
async def top_hosts(user: RequireViewer):
    """Retorna hosts com mais vulnerabilidades críticas/altas."""
    try:
        async with get_db() as db:
            rows = await db.execute_fetchall(
                """SELECT host,
                          COUNT(*) as total,
                          SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical,
                          SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high
                   FROM vulnerabilities
                   GROUP BY host
                   ORDER BY critical DESC, high DESC, total DESC
                   LIMIT 10"""
            )
            return [dict(r) for r in rows]
    except Exception:
        log.exception("DASHBOARD_TOP_HOSTS_ERROR user=%s", user.username)
        raise HTTPException(status_code=500, detail="Erro ao carregar top hosts.")
