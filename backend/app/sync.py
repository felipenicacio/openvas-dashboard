"""
Sincronização GVM → SQLite cache.
Pode ser chamado manualmente (endpoint /api/sync) ou pelo scheduler automático.
"""
import json
import logging
from datetime import datetime

import aiosqlite

from .database import get_db, init_db
from .gvm_client import fetch_all_results, fetch_tasks

log = logging.getLogger(__name__)

_sync_running = False


async def run_sync() -> dict:
    global _sync_running
    if _sync_running:
        return {"status": "running", "message": "Sincronização já em andamento."}

    _sync_running = True
    started = datetime.utcnow()
    try:
        log.info("Sync: iniciando coleta do GVM…")

        # Coleta via GVM (síncrono — rode em thread pool no chamador se necessário)
        import asyncio
        loop = asyncio.get_event_loop()
        results, tasks = await asyncio.gather(
            loop.run_in_executor(None, fetch_all_results),
            loop.run_in_executor(None, fetch_tasks),
        )

        log.info("Sync: %d resultados, %d tasks", len(results), len(tasks))

        async with get_db() as db:
            # ── Limpa e reinsere vulnerabilidades ──────────────────────
            await db.execute("DELETE FROM vulnerabilities")
            await db.execute("DELETE FROM hosts")
            await db.execute("DELETE FROM scans")

            host_set = {}

            for r in results:
                first = r["first_seen"].isoformat() if r["first_seen"] else None
                last  = r["last_seen"].isoformat()  if r["last_seen"]  else None
                await db.execute("""
                    INSERT OR REPLACE INTO vulnerabilities
                    (id, finding_id, host, hostname, port, protocol, nvt_oid, nvt_name,
                     cvss, severity, cves, description, solution, solution_type,
                     first_seen, last_seen, task_name, report_id)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    r["id"], r["finding_id"], r["host"], r["hostname"],
                    r["port"], r["protocol"], r["nvt_oid"], r["nvt_name"],
                    r["cvss"], r["severity"], r["cves"],
                    r["description"], r["solution"], r["solution_type"],
                    first, last, r["task_name"], r["report_id"],
                ))

                if r["host"] not in host_set or r["last_seen"]:
                    host_set[r["host"]] = {
                        "ip":       r["host"],
                        "hostname": r["hostname"] or host_set.get(r["host"],{}).get("hostname",""),
                        "os":       "",
                        "last_seen": last,
                    }

            for h in host_set.values():
                await db.execute("""
                    INSERT OR REPLACE INTO hosts (ip, hostname, os, last_seen)
                    VALUES (?,?,?,?)
                """, (h["ip"], h["hostname"], h["os"], h["last_seen"]))

            for t in tasks:
                scan_dt = t["last_scan_date"]
                await db.execute("""
                    INSERT OR REPLACE INTO scans
                    (id, name, status, progress, target_name, last_report_id, last_scan_date, severity_json)
                    VALUES (?,?,?,?,?,?,?,?)
                """, (
                    t["id"], t["name"], t["status"], t["progress"],
                    t["target_name"], t["last_report_id"],
                    scan_dt.isoformat() if scan_dt else None,
                    t["severity_json"],
                ))

            await db.execute("""
                INSERT INTO sync_log (synced_at, status, message, vulns_count)
                VALUES (?,?,?,?)
            """, (started.isoformat(), "ok", f"{len(results)} vulns sincronizadas", len(results)))

            await db.commit()

        elapsed = (datetime.utcnow() - started).total_seconds()
        log.info("Sync: concluída em %.1fs — %d vulns, %d hosts, %d scans",
                 elapsed, len(results), len(host_set), len(tasks))
        return {
            "status": "ok",
            "message": f"{len(results)} vulnerabilidades sincronizadas em {elapsed:.1f}s.",
            "synced_at": started,
        }

    except Exception as e:
        log.error("Sync falhou: %s", e)
        try:
            async with get_db() as db:
                await db.execute(
                    "INSERT INTO sync_log (synced_at, status, message) VALUES (?,?,?)",
                    (started.isoformat(), "error", str(e))
                )
                await db.commit()
        except Exception:
            pass
        return {"status": "error", "message": str(e), "synced_at": started}
    finally:
        _sync_running = False
