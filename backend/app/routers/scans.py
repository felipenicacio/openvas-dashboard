"""
Endpoints de scans/tasks GVM — com RBAC e validação de input.

Permissões:
- GET  /api/scans          → VIEWER
- POST /api/scans/sync     → ANALYST
- POST /api/scans/{id}/start → ADMIN
- POST /api/scans/{id}/stop  → ADMIN

Validação:
- task_id validado como UUID antes de encaminhar ao GVM.
  GVM utiliza UUIDs no formato padrão (RFC 4122).
"""

import json
import logging
import re
import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request

from ..auth import CurrentUser, RequireAdmin, RequireAnalyst, RequireViewer
from ..database import get_db
from ..models.schemas import ScanStartResponse, ScanTask, SyncStatus
from ..gvm_client import start_task, stop_task
from ..sync import run_sync

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scans", tags=["scans"])

# UUID formato padrão RFC 4122
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _validate_task_id(task_id: str) -> str:
    """
    Valida que task_id é UUID válido (RFC 4122).
    GVM utiliza UUIDs — qualquer outro formato é rejeitado antes de chegar ao GVM.
    Referência: CWE-20 Improper Input Validation.
    """
    if not task_id or not _UUID_RE.match(task_id):
        raise HTTPException(
            status_code=422,
            detail="task_id inválido. Deve ser UUID no formato RFC 4122.",
        )
    return task_id.lower()


def _dt(v):
    if not v:
        return None
    try:
        return datetime.fromisoformat(v)
    except Exception:
        return None


@router.get("", response_model=list[ScanTask])
async def list_scans(user: RequireViewer):
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
                id=r["id"],
                name=r["name"],
                status=r["status"],
                progress=r["progress"],
                target_name=r["target_name"] or "",
                last_report_id=r["last_report_id"] or None,
                last_scan_date=_dt(r["last_scan_date"]),
                severity_summary=sev,
            ))
        return result


@router.post("/{task_id}/start", response_model=ScanStartResponse)
async def start_scan(task_id: str, request: Request, user: RequireAdmin):
    """Inicia scan no GVM. Exige papel ADMIN."""
    task_id = _validate_task_id(task_id)

    import asyncio
    loop = asyncio.get_event_loop()
    ok = await loop.run_in_executor(None, start_task, task_id)

    if not ok:
        log.error("SCAN_START_FAILED task_id=%s user=%s", task_id, user.username)
        raise HTTPException(status_code=500, detail="Falha ao iniciar scan.")

    log.info(
        "SCAN_STARTED task_id=%s user=%s ip=%s",
        task_id,
        user.username,
        request.client.host if request.client else "unknown",
    )
    return ScanStartResponse(task_id=task_id, message="Scan iniciado com sucesso.")


@router.post("/{task_id}/stop", response_model=ScanStartResponse)
async def stop_scan(task_id: str, request: Request, user: RequireAdmin):
    """Para scan no GVM. Exige papel ADMIN."""
    task_id = _validate_task_id(task_id)

    import asyncio
    loop = asyncio.get_event_loop()
    ok = await loop.run_in_executor(None, stop_task, task_id)

    if not ok:
        log.error("SCAN_STOP_FAILED task_id=%s user=%s", task_id, user.username)
        raise HTTPException(status_code=500, detail="Falha ao parar scan.")

    log.info(
        "SCAN_STOPPED task_id=%s user=%s ip=%s",
        task_id,
        user.username,
        request.client.host if request.client else "unknown",
    )
    return ScanStartResponse(task_id=task_id, message="Scan parado.")


@router.post("/sync", response_model=SyncStatus)
async def trigger_sync(request: Request, user: RequireAnalyst):
    """Sincronização manual com GVM. Exige papel ANALYST ou superior."""
    log.info(
        "SYNC_MANUAL_TRIGGERED user=%s ip=%s",
        user.username,
        request.client.host if request.client else "unknown",
    )
    result = await run_sync()
    return SyncStatus(**result)
