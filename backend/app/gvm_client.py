"""
GVM client — wraps python-gvm para buscar dados do OpenVAS/GVM.
Suporta TLS (host:porta) e Unix socket (Docker volume ou path nativo).
"""
import re
import json
import logging
from datetime import datetime
from contextlib import contextmanager
from typing import Generator

from gvm.connections import TLSConnection, UnixSocketConnection
from gvm.protocols.gmp import GMPv224 as Gmp
from gvm.transforms import EtreeTransform
from lxml import etree

from .config import get_settings

log = logging.getLogger(__name__)
settings = get_settings()

_SEV_MAP = {
    "Critical": 10.0,
    "High": 8.5,
    "Medium": 5.0,
    "Low": 2.5,
    "Log": 0.1,
    "None": 0.0,
}


@contextmanager
def _gmp_session() -> Generator[Gmp, None, None]:
    """Abre uma sessão autenticada com o GVM e fecha ao sair."""
    if settings.gvm_socket_path:
        conn = UnixSocketConnection(path=settings.gvm_socket_path, timeout=300)
    else:
        conn = TLSConnection(
            hostname=settings.gvm_host,
            port=settings.gvm_port,
            timeout=300,
        )
    with Gmp(connection=conn, transform=EtreeTransform()) as gmp:
        gmp.authenticate(settings.gvm_username, settings.gvm_password)
        yield gmp


# ── Helpers ───────────────────────────────────────────────────────

def _txt(el, xpath: str, default="") -> str:
    node = el.find(xpath)
    return (node.text or "").strip() if node is not None and node.text else default


def _flt(el, xpath: str, default=0.0) -> float:
    try:
        return float(_txt(el, xpath) or default)
    except (ValueError, TypeError):
        return default


def _parse_datetime(raw: str) -> datetime | None:
    if not raw:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
    return None


def _cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0.0:
        return "Low"
    return "Log"


def _parse_result(result_el: etree._Element, task_name: str, report_id: str) -> dict | None:
    """Converte um elemento <result> do GVM em dict."""
    result_id = result_el.get("id", "")
    host_el    = result_el.find("host")
    host_ip    = (host_el.text or "").strip() if host_el is not None else ""
    if not host_ip or not re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host_ip):
        return None

    hostname   = _txt(host_el, "hostname") if host_el is not None else ""
    port_raw   = _txt(result_el, "port")
    port_parts = port_raw.split("/")
    port       = re.sub(r"\D", "", port_parts[0]) if port_parts else ""
    proto      = port_parts[1].lower() if len(port_parts) > 1 else ""

    nvt_el     = result_el.find("nvt")
    nvt_oid    = nvt_el.get("oid", "") if nvt_el is not None else ""
    nvt_name   = _txt(nvt_el, "name") if nvt_el is not None else ""

    severity_el = result_el.find("severity")
    severity_val = result_el.find(".//original_severity")
    cvss_raw   = (severity_val.text if severity_val is not None else
                  (severity_el.text if severity_el is not None else "0"))
    try:
        cvss = float(cvss_raw or 0)
    except ValueError:
        cvss = 0.0

    threat_el  = result_el.find("threat")
    severity   = (threat_el.text or "").strip() if threat_el is not None else ""
    if severity not in ("Critical","High","Medium","Low","Log","None"):
        severity = _cvss_to_severity(cvss)

    cves = [ref.get("id","") for ref in (nvt_el.findall("refs/ref") if nvt_el is not None else [])
            if ref.get("type","") == "cve"][:5]

    desc_el    = result_el.find("description")
    description = (desc_el.text or "").strip() if desc_el is not None else ""

    sol_el     = nvt_el.find("solution") if nvt_el is not None else None
    solution   = (sol_el.text or "").strip() if sol_el is not None else ""
    sol_type   = sol_el.get("type","") if sol_el is not None else ""

    created_raw  = _txt(result_el, "creation_time")
    modified_raw = _txt(result_el, "modification_time")

    from .database import make_finding_id
    finding_id = make_finding_id(host_ip, port, proto, nvt_oid, nvt_name)

    return {
        "id":           result_id,
        "finding_id":   finding_id,
        "host":         host_ip,
        "hostname":     hostname,
        "port":         port,
        "protocol":     proto,
        "nvt_oid":      nvt_oid,
        "nvt_name":     nvt_name[:255],
        "cvss":         cvss,
        "severity":     severity,
        "cves":         ",".join(cves),
        "description":  description[:4000],
        "solution":     solution[:4000],
        "solution_type":sol_type,
        "first_seen":   _parse_datetime(created_raw),
        "last_seen":    _parse_datetime(modified_raw),
        "task_name":    task_name,
        "report_id":    report_id,
    }


# ── Public API ────────────────────────────────────────────────────

def fetch_all_results() -> list[dict]:
    """
    Busca todos os resultados de todos os reports concluídos.
    Retorna lista de dicts prontos para inserção no SQLite.
    """
    results = []
    try:
        with _gmp_session() as gmp:
            tasks_xml = gmp.get_tasks(filter_string="status=Done rows=-1")
            tasks = tasks_xml.findall("task")
            log.info("GVM: %d tasks concluídas encontradas", len(tasks))

            for task in tasks:
                task_name = _txt(task, "name")
                last_rpt  = task.find("last_report/report")
                if last_rpt is None:
                    continue
                report_id = last_rpt.get("id","")

                try:
                    page = 1
                    page_size = 200
                    while True:
                        filter_str = f"rows={page_size} first={(page-1)*page_size+1} levels=hmlg"
                        report_xml = gmp.get_report(
                            report_id=report_id,
                            filter_string=filter_str,
                            details=True,
                        )
                        batch = report_xml.findall(".//result")
                        if not batch:
                            break
                        for res_el in batch:
                            parsed = _parse_result(res_el, task_name, report_id)
                            if parsed:
                                results.append(parsed)
                        if len(batch) < page_size:
                            break
                        page += 1
                except Exception as e:
                    log.warning("Erro ao buscar report %s: %s", report_id, e)

    except Exception as e:
        log.error("GVM connection error: %s", e)
        raise

    log.info("GVM: %d resultados coletados", len(results))
    return results


def fetch_tasks() -> list[dict]:
    """Retorna lista de tasks/scans do GVM."""
    tasks = []
    try:
        with _gmp_session() as gmp:
            tasks_xml = gmp.get_tasks(filter_string="rows=-1")
            for task in tasks_xml.findall("task"):
                task_name   = _txt(task, "name")
                status      = _txt(task, "status")
                progress    = int(_flt(task, "progress"))
                target_el   = task.find("target")
                target_name = _txt(target_el, "name") if target_el is not None else ""
                last_rpt    = task.find("last_report/report")
                last_report_id = last_rpt.get("id","") if last_rpt is not None else ""
                scan_end    = _txt(last_rpt, "timestamp") if last_rpt is not None else ""
                sev_counts  = {}
                for sev in ("Critical","High","Medium","Low","Log"):
                    cnt = int(_flt(task, f"result_count/{sev.lower()}"))
                    sev_counts[sev] = cnt

                tasks.append({
                    "id":             task.get("id",""),
                    "name":           task_name,
                    "status":         status,
                    "progress":       max(0, min(100, progress)),
                    "target_name":    target_name,
                    "last_report_id": last_report_id,
                    "last_scan_date": _parse_datetime(scan_end),
                    "severity_json":  json.dumps(sev_counts),
                })
    except Exception as e:
        log.error("GVM fetch_tasks error: %s", e)
        raise
    return tasks


def start_task(task_id: str) -> bool:
    try:
        with _gmp_session() as gmp:
            resp = gmp.start_task(task_id)
            return resp.get("status","") == "202"
    except Exception as e:
        log.error("GVM start_task error: %s", e)
        return False


def stop_task(task_id: str) -> bool:
    try:
        with _gmp_session() as gmp:
            resp = gmp.stop_task(task_id)
            return resp.get("status","") == "200"
    except Exception as e:
        log.error("GVM stop_task error: %s", e)
        return False
