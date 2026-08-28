"""
Schemas Pydantic — OpenVAS Dashboard v1.1.0

LoginRequest: recebe username/password no body (JSON).
Token não é retornado no body — entregue apenas via cookie HttpOnly.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, field_validator


class LoginRequest(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def username_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("username não pode ser vazio")
        return v[:128]  # trunca para evitar payloads excessivos

    @field_validator("password")
    @classmethod
    def password_not_empty(cls, v: str) -> str:
        if not v:
            raise ValueError("password não pode ser vazio")
        return v[:1024]  # limite razoável


class ScanTask(BaseModel):
    id: str
    name: str
    status: str
    progress: Optional[int] = None
    target_name: str
    last_report_id: Optional[str] = None
    last_scan_date: Optional[datetime] = None
    severity_summary: dict = {}


class ScanStartResponse(BaseModel):
    task_id: str
    message: str


class SyncStatus(BaseModel):
    synced_tasks: int = 0
    synced_vulns: int = 0
    errors: int = 0
    last_sync: Optional[str] = None
