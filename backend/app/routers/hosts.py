from fastapi import APIRouter, Query, HTTPException
from datetime import datetime
from typing import Optional

from ..auth import CurrentUser
from ..database import get_db
from ..models.schemas import HostSummary, HostDetail, Vulnerability

router = APIRouter(prefix="/api/hosts", tags=["hosts"])

_SEV_W = {"Critical":10.0,"High":7.0,"Medium":4.0,"Low":1.5,"Log":0.1}


def _risk(counts: dict) -> float:
    total = sum(counts.values()) or 1
    raw = sum(_SEV_W.get(s,0)*n for s,n in counts.items())
    return round(min(10.0, raw / total * 1.2), 1)


def _dt(v):
    if not v: return None
    try: return datetime.fromisoformat(v)
    except: return None


@router.get("", response_model=list[HostSummary])
async def list_hosts(
    user: CurrentUser,
    search: Optional[str] = None,
    sort_by: str = "risk_score",
    sort_dir: str = "desc",
):
    async with get_db() as db:
        rows = await db.execute_fetchall("""
            SELECT
                v.host, h.hostname, h.os, h.last_seen,
                SUM(CASE WHEN v.severity='Critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN v.severity='High'     THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN v.severity='Medium'   THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN v.severity='Low'      THEN 1 ELSE 0 END) as low,
                SUM(CASE WHEN v.severity='Log'      THEN 1 ELSE 0 END) as log,
                COUNT(*) as total
            FROM vulnerabilities v
            LEFT JOIN hosts h ON h.ip = v.host
            GROUP BY v.host
        """)

        results = []
        for r in rows:
            cnts = {
                "Critical": r["critical"],
                "High":     r["high"],
                "Medium":   r["medium"],
                "Low":      r["low"],
                "Log":      r["log"],
            }
            ip = r["host"]
            hn = r["hostname"] or ip
            if search and search.lower() not in ip.lower() and search.lower() not in hn.lower():
                continue
            results.append(HostSummary(
                ip=ip, hostname=hn, os=r["os"] or "",
                risk_score=_risk(cnts),
                critical=cnts["Critical"], high=cnts["High"],
                medium=cnts["Medium"], low=cnts["Low"], log=cnts["Log"],
                total=r["total"],
                last_seen=_dt(r["last_seen"]),
            ))

        reverse = sort_dir.lower() == "desc"
        key_map = {
            "risk_score": lambda x: x.risk_score,
            "total":      lambda x: x.total,
            "critical":   lambda x: x.critical,
            "high":       lambda x: x.high,
            "ip":         lambda x: x.ip,
        }
        fn = key_map.get(sort_by, lambda x: x.risk_score)
        results.sort(key=fn, reverse=reverse)
        return results


@router.get("/{ip}", response_model=HostDetail)
async def get_host(ip: str, user: CurrentUser):
    async with get_db() as db:
        hrows = await db.execute_fetchall(
            "SELECT * FROM hosts WHERE ip=? LIMIT 1", (ip,)
        )
        if not hrows:
            raise HTTPException(status_code=404, detail="Host não encontrado.")
        h = hrows[0]

        vrows = await db.execute_fetchall(
            "SELECT * FROM vulnerabilities WHERE host=? ORDER BY cvss DESC", (ip,)
        )

        vulns = []
        cnts = {"Critical":0,"High":0,"Medium":0,"Low":0,"Log":0}
        for r in vrows:
            cnts[r["severity"]] = cnts.get(r["severity"],0) + 1
            vulns.append(Vulnerability(
                id=r["id"], finding_id=r["finding_id"] or "",
                host=r["host"], hostname=r["hostname"] or "",
                port=r["port"] or "", protocol=r["protocol"] or "",
                nvt_oid=r["nvt_oid"] or "", nvt_name=r["nvt_name"] or "",
                cvss=r["cvss"] or 0.0, severity=r["severity"] or "None",
                cves=[c for c in (r["cves"] or "").split(",") if c],
                description=r["description"] or "", solution=r["solution"] or "",
                solution_type=r["solution_type"] or "",
                first_seen=_dt(r["first_seen"]), last_seen=_dt(r["last_seen"]),
                task_name=r["task_name"] or "", report_id=r["report_id"] or "",
            ))

        return HostDetail(
            ip=ip, hostname=h["hostname"] or ip, os=h["os"] or "",
            risk_score=_risk(cnts), vulnerabilities=vulns,
        )
