from fastapi import APIRouter, Query, HTTPException
from datetime import datetime
from typing import Optional

from ..auth import CurrentUser
from ..database import get_db
from ..models.schemas import Vulnerability, VulnerabilityList

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


def _row_to_vuln(r) -> Vulnerability:
    return Vulnerability(
        id=r["id"],
        finding_id=r["finding_id"] or "",
        host=r["host"],
        hostname=r["hostname"] or "",
        port=r["port"] or "",
        protocol=r["protocol"] or "",
        nvt_oid=r["nvt_oid"] or "",
        nvt_name=r["nvt_name"] or "",
        cvss=r["cvss"] or 0.0,
        severity=r["severity"] or "None",
        cves=[c for c in (r["cves"] or "").split(",") if c],
        description=r["description"] or "",
        solution=r["solution"] or "",
        solution_type=r["solution_type"] or "",
        first_seen=_dt(r["first_seen"]),
        last_seen=_dt(r["last_seen"]),
        task_name=r["task_name"] or "",
        report_id=r["report_id"] or "",
    )


def _dt(val) -> datetime | None:
    if not val:
        return None
    try:
        return datetime.fromisoformat(val)
    except Exception:
        return None


@router.get("", response_model=VulnerabilityList)
async def list_vulnerabilities(
    user: CurrentUser,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None,       # Critical,High,Medium,Low,Log
    host: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "cvss",
    sort_dir: str = "desc",
):
    async with get_db() as db:
        conditions = []
        params: list = []

        if severity:
            placeholders = ",".join("?" * len(severity.split(",")))
            conditions.append(f"severity IN ({placeholders})")
            params.extend(severity.split(","))

        if host:
            conditions.append("host LIKE ?")
            params.append(f"%{host}%")

        if search:
            conditions.append("(nvt_name LIKE ? OR host LIKE ? OR cves LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like])

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        allowed_sort = {"cvss","severity","host","nvt_name","first_seen"}
        if sort_by not in allowed_sort:
            sort_by = "cvss"
        sort_dir = "DESC" if sort_dir.lower() == "desc" else "ASC"

        count_row = await db.execute_fetchall(
            f"SELECT COUNT(*) as n FROM vulnerabilities {where}", params
        )
        total = count_row[0]["n"] if count_row else 0

        offset = (page - 1) * page_size
        rows = await db.execute_fetchall(
            f"""SELECT * FROM vulnerabilities {where}
                ORDER BY {sort_by} {sort_dir}
                LIMIT ? OFFSET ?""",
            params + [page_size, offset],
        )

        return VulnerabilityList(
            total=total,
            page=page,
            page_size=page_size,
            items=[_row_to_vuln(r) for r in rows],
        )


@router.get("/{vuln_id}", response_model=Vulnerability)
async def get_vulnerability(vuln_id: str, user: CurrentUser):
    async with get_db() as db:
        rows = await db.execute_fetchall(
            "SELECT * FROM vulnerabilities WHERE id=? LIMIT 1", (vuln_id,)
        )
        if not rows:
            raise HTTPException(status_code=404, detail="Vulnerabilidade não encontrada.")
        return _row_to_vuln(rows[0])
