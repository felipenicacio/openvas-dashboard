from pydantic import BaseModel
from datetime import datetime
from typing import Optional


# ── Auth ──────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ── Vulnerability ─────────────────────────────────────────────────

class Vulnerability(BaseModel):
    id: str
    host: str
    hostname: str
    port: str
    protocol: str
    nvt_oid: str
    nvt_name: str
    cvss: float
    severity: str          # Critical | High | Medium | Low | Log | None
    cves: list[str]
    description: str
    solution: str
    solution_type: str
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    task_name: str
    report_id: str
    finding_id: str

class VulnerabilityList(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[Vulnerability]


# ── Host ──────────────────────────────────────────────────────────

class HostSummary(BaseModel):
    ip: str
    hostname: str
    os: str
    risk_score: float       # 0–10 calculado
    critical: int
    high: int
    medium: int
    low: int
    log: int
    total: int
    last_seen: Optional[datetime]

class HostDetail(BaseModel):
    ip: str
    hostname: str
    os: str
    risk_score: float
    vulnerabilities: list[Vulnerability]


# ── Scan (Task) ───────────────────────────────────────────────────

class ScanTask(BaseModel):
    id: str
    name: str
    status: str             # Running | Done | Stopped | New | …
    progress: int           # 0–100
    target_name: str
    last_report_id: Optional[str]
    last_scan_date: Optional[datetime]
    severity_summary: dict  # {Critical:n, High:n, …}

class ScanStartResponse(BaseModel):
    task_id: str
    message: str


# ── Dashboard ─────────────────────────────────────────────────────

class SeverityCount(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    log: int

class TrendPoint(BaseModel):
    month: str              # "Jul/2026"
    critical: int
    high: int
    medium: int
    low: int
    total: int

class AgingBucket(BaseModel):
    label: str
    count: int

class TopHost(BaseModel):
    ip: str
    hostname: str
    risk_score: float
    total: int
    critical: int
    high: int

class DashboardSummary(BaseModel):
    total_open: int
    severity: SeverityCount
    risk_score: float       # 0–10
    sla_overdue: int
    hosts_affected: int
    scans_active: int
    last_sync: Optional[datetime]
    trend: list[TrendPoint]
    top_hosts: list[TopHost]
    aging: list[AgingBucket]


# ── Sync ─────────────────────────────────────────────────────────

class SyncStatus(BaseModel):
    status: str
    message: str
    synced_at: Optional[datetime]
