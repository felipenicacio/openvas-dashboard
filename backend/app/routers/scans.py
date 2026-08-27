import json
from fastapi import APIRouter, HTTPException
from datetime import datetime

from ..auth import CurrentUser
from ..database import get_db
from ..models.schemas import ScanTask, ScanStartResponse, SyncStatus
from ..gvm_client import start_task, stop_task
from ..sync import run_sync

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _dt(v):
    if not v: return None
    try: return datetime.fromisoformat(v)
    except: return None


@router.get("", response_model=list[ScanTask])
async def list_scans(user: CurrentUser):
    async with get_db() as db:
        rows = await db.execute_fetchall(
            "SELECT * FROM scans ORDER BY last_scan_date DESC NULLS LAST"
        )
        result = []
        for r in rows:
            try:
                sev = json.loads(r["severity_json"] or "{}")
            except Exception:
                sev = {}
            result.append(ScanTask(
                id=r["id"], name=r["name"], status=r["status"],
                progress=r["progress"], target_name=r["target_name"] or "",
                last_report_id=r["last_report_id"] or None,
                last_scan_date=_dt(r["last_scan_date"]),
                severity_summary=sev,
            ))
        return result


@router.post("/{task_id}/start", response_model=ScanStartResponse)
async def start_scan(task_id: str, user: CurrentUser):
    import asyncio
    loop = asyncio.get_event_loop()
    ok = await loop.run_in_executor(None, start_task, task_id)
    if not ok:
        raise HTTPException(status_code=500, detail="Falha ao iniciar scan no GVM.")
    return ScanStartResponse(task_id=task_id, message="Scan iniciado com sucesso.")


@router.post("/{task_id}/stop", response_model=ScanStartResponse)
async def stop_scan(task_id: str, user: CurrentUser):
    import asyncio
    loop = asyncio.get_event_loop()
    ok = await loop.run_in_executor(None, stop_task, task_id)
    if not ok:
        raise HTTPException(status_code=500, detail="Falha ao parar scan no GVM.")
    return ScanStartResponse(task_id=task_id, message="Scan parado.")


@router.post("/sync", response_model=SyncStatus)
async def trigger_sync(user: CurrentUser):
    result = await run_sync()
    return SyncStatus(**result)
