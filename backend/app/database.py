"""
SQLite cache — mantém os dados do GVM localmente para respostas rápidas.
O script de sync popula essas tabelas; as rotas apenas leem daqui.
"""
import aiosqlite
import hashlib
import os
from contextlib import asynccontextmanager
from pathlib import Path

_data_dir = os.environ.get("DATA_DIR", "/opt/openvas-dashboard/data")
DB_PATH = Path(_data_dir) / "openvas_cache.db"


@asynccontextmanager
async def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(str(DB_PATH))
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
    finally:
        await conn.close()


async def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(str(DB_PATH)) as db:
        db.row_factory = aiosqlite.Row
        await db.executescript("""
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id            TEXT PRIMARY KEY,
            finding_id    TEXT,
            host          TEXT,
            hostname      TEXT DEFAULT '',
            port          TEXT DEFAULT '',
            protocol      TEXT DEFAULT '',
            nvt_oid       TEXT DEFAULT '',
            nvt_name      TEXT DEFAULT '',
            cvss          REAL DEFAULT 0,
            severity      TEXT DEFAULT 'None',
            cves          TEXT DEFAULT '',       -- comma-separated
            description   TEXT DEFAULT '',
            solution      TEXT DEFAULT '',
            solution_type TEXT DEFAULT '',
            first_seen    TEXT,
            last_seen     TEXT,
            task_name     TEXT DEFAULT '',
            report_id     TEXT DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_vuln_host     ON vulnerabilities(host);
        CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
        CREATE INDEX IF NOT EXISTS idx_vuln_finding  ON vulnerabilities(finding_id);

        CREATE TABLE IF NOT EXISTS hosts (
            ip          TEXT PRIMARY KEY,
            hostname    TEXT DEFAULT '',
            os          TEXT DEFAULT '',
            last_seen   TEXT
        );

        CREATE TABLE IF NOT EXISTS scans (
            id              TEXT PRIMARY KEY,
            name            TEXT DEFAULT '',
            status          TEXT DEFAULT '',
            progress        INTEGER DEFAULT 0,
            target_name     TEXT DEFAULT '',
            last_report_id  TEXT DEFAULT '',
            last_scan_date  TEXT,
            severity_json   TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS sync_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            synced_at   TEXT,
            status      TEXT,
            message     TEXT,
            vulns_count INTEGER DEFAULT 0
        );
        """)
        await db.commit()


def make_finding_id(host: str, port: str, protocol: str, nvt_oid: str, nvt_name: str) -> str:
    key = f"{host.strip()}:{port}:{protocol.lower()}:{nvt_oid or nvt_name[:120].lower()}"
    return "FND-" + hashlib.md5(key.encode()).hexdigest()[:8].upper()
