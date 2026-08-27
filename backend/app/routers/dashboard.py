from fastapi import APIRouter, Depends
from datetime import datetime

from ..auth import CurrentUser
from ..database import get_db
from ..models.schemas import DashboardSummary, SeverityCount, TrendPoint, AgingBucket, TopHost

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

_SEV_WEIGHT = {"Critical": 10.0, "High": 7.0, "Medium": 4.0, "Low": 1.5, "Log": 0.1}

def _calc_risk(counts: dict) -> float:
    """Risk score 0–10 ponderado por severidade."""
    score = sum(_SEV_WEIGHT.get(s,0) * n for s,n in counts.items())
    return round(min(10.0, score / max(sum(counts.values()), 1) * 1.2), 1)


@router.get("/summary", response_model=DashboardSummary)
async def summary(user: CurrentUser):
    async with get_db() as db:
        # ── Contagens por severidade ──────────────────────────────
        rows = await db.execute_fetchall(
            "SELECT severity, COUNT(*) as n FROM vulnerabilities GROUP BY severity"
        )
        sev = {r["severity"]: r["n"] for r in rows}

        # ── SLA vencido (usando prazo fixo aqui; em prod leia de SLA_CONFIG) ──
        sla_map = {"Critical":15,"High":30,"Medium":60,"Low":90}
        overdue = 0
        for sv, days in sla_map.items():
            row = await db.execute_fetchall(f"""
                SELECT COUNT(*) as n FROM vulnerabilities
                WHERE severity=? AND first_seen IS NOT NULL
                AND JULIANDAY('now') - JULIANDAY(first_seen) > ?
            """, (sv, days))
            overdue += row[0]["n"] if row else 0

        # ── Hosts afetados ────────────────────────────────────────
        row = await db.execute_fetchall("SELECT COUNT(DISTINCT host) as n FROM vulnerabilities")
        hosts_affected = row[0]["n"] if row else 0

        # ── Scans ativos ──────────────────────────────────────────
        row = await db.execute_fetchall("SELECT COUNT(*) as n FROM scans WHERE status='Running'")
        scans_active = row[0]["n"] if row else 0

        # ── Última sync ───────────────────────────────────────────
        row = await db.execute_fetchall(
            "SELECT synced_at FROM sync_log WHERE status='ok' ORDER BY id DESC LIMIT 1"
        )
        last_sync = None
        if row and row[0]["synced_at"]:
            try:
                last_sync = datetime.fromisoformat(row[0]["synced_at"])
            except Exception:
                pass

        # ── Trend: contagem por task_name (usado como proxy de mês) ──
        # Em produção, use first_seen agrupado por mês
        trend_rows = await db.execute_fetchall("""
            SELECT
                SUBSTR(first_seen, 1, 7) as ym,
                severity,
                COUNT(*) as n
            FROM vulnerabilities
            WHERE first_seen IS NOT NULL
            GROUP BY ym, severity
            ORDER BY ym
        """)
        trend_map: dict = {}
        for r in trend_rows:
            ym = r["ym"] or "Unknown"
            if ym not in trend_map:
                trend_map[ym] = {"Critical":0,"High":0,"Medium":0,"Low":0,"Log":0}
            trend_map[ym][r["severity"]] = trend_map[ym].get(r["severity"],0) + r["n"]

        trend = []
        for ym, counts in sorted(trend_map.items())[-12:]:
            try:
                y, m = ym.split("-")
                from calendar import month_abbr
                label = f"{month_abbr[int(m)]}/{y}"
            except Exception:
                label = ym
            trend.append(TrendPoint(
                month=label,
                critical=counts.get("Critical",0),
                high=counts.get("High",0),
                medium=counts.get("Medium",0),
                low=counts.get("Low",0),
                total=sum(counts.values()),
            ))

        # ── Top Hosts ─────────────────────────────────────────────
        top_rows = await db.execute_fetchall("""
            SELECT
                host, hostname,
                COUNT(*) as total,
                SUM(CASE WHEN severity='Critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity='High'     THEN 1 ELSE 0 END) as high
            FROM vulnerabilities
            GROUP BY host
            ORDER BY critical DESC, high DESC, total DESC
            LIMIT 10
        """)
        top_hosts = []
        for r in top_rows:
            cnts = {"Critical": r["critical"], "High": r["high"]}
            risk = _calc_risk(cnts)
            top_hosts.append(TopHost(
                ip=r["host"], hostname=r["hostname"] or r["host"],
                risk_score=risk, total=r["total"],
                critical=r["critical"], high=r["high"],
            ))

        # ── Aging ─────────────────────────────────────────────────
        aging_data = []
        for label, min_d, max_d in [
            ("Em Prazo",        0,  None),
            ("Vence ≤7 dias",   0,     7),
            ("Vencido 1-30d",   1,    30),
            ("Vencido 31-60d", 31,    60),
            ("Vencido >60d",   61,  None),
        ]:
            # simplified: count all active for now
            aging_data.append(AgingBucket(label=label, count=0))

        counts_all = {
            "Critical": sev.get("Critical",0),
            "High":     sev.get("High",0),
            "Medium":   sev.get("Medium",0),
            "Low":      sev.get("Low",0),
            "Log":      sev.get("Log",0),
        }

        return DashboardSummary(
            total_open=sum(counts_all.values()),
            severity=SeverityCount(
                critical=counts_all["Critical"],
                high=counts_all["High"],
                medium=counts_all["Medium"],
                low=counts_all["Low"],
                log=counts_all["Log"],
            ),
            risk_score=_calc_risk(counts_all),
            sla_overdue=overdue,
            hosts_affected=hosts_affected,
            scans_active=scans_active,
            last_sync=last_sync,
            trend=trend,
            top_hosts=top_hosts,
            aging=aging_data,
        )
