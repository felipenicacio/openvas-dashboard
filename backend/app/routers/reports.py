"""
Exportação de relatório PDF.

Segurança:
- Endpoint protegido por autenticação (VIEWER+)
- scan_id validado como UUID quando fornecido
- Dados do OpenVAS tratados como não confiáveis (_safe sanitiza para latin-1)
- Limite de linhas no relatório para evitar DoS
- Nome do arquivo gerado pela aplicação (sem input do usuário)
- Sem path traversal possível (sem acesso a filesystem baseado em input)
"""

import io
import logging
import re
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from ..auth import RequireViewer
from ..database import get_db

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reports", tags=["reports"])

# UUID RFC 4122
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Limite máximo de linhas no PDF (proteção contra DoS)
_MAX_ROWS = 5000

_SEV_COLORS = {
    "Critical": (220, 38, 38),
    "High":     (234, 88, 12),
    "Medium":   (217, 119, 6),
    "Low":      (22, 163, 74),
    "Log":      (107, 114, 128),
}
_SEV_WEIGHTS = {"Critical": 10.0, "High": 7.0, "Medium": 4.0, "Low": 1.5, "Log": 0.1}


def _safe(text: str) -> str:
    """
    Sanitiza texto para latin-1 (Helvetica fpdf2).
    Dados do OpenVAS são tratados como não confiáveis.
    """
    if not text:
        return ""
    return str(text).encode("latin-1", errors="replace").decode("latin-1")


def _validate_scan_id(scan_id: Optional[str]) -> Optional[str]:
    """Valida scan_id como UUID RFC 4122 se fornecido."""
    if scan_id is None:
        return None
    if not _UUID_RE.match(scan_id):
        raise HTTPException(
            status_code=422,
            detail="scan_id inválido. Deve ser UUID no formato RFC 4122.",
        )
    return scan_id.lower()


@router.get("/pdf")
async def export_pdf(
    user: RequireViewer,
    scan_id: Optional[str] = Query(
        None,
        description="Filtrar por scan/report UUID",
        max_length=36,
    ),
):
    """
    Exporta vulnerabilidades como PDF.
    Requer autenticação (VIEWER+).
    """
    from fpdf import FPDF

    scan_id = _validate_scan_id(scan_id)

    async with get_db() as db:
        conditions: list[str] = []
        params: list = []
        if scan_id:
            conditions.append("report_id = ?")
            params.append(scan_id)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        count_rows = await db.execute_fetchall(
            f"SELECT severity, COUNT(*) as n FROM vulnerabilities {where} GROUP BY severity",
            params,
        )
        counts = {r["severity"]: r["n"] for r in count_rows}
        total = sum(counts.values())

        rows = await db.execute_fetchall(
            f"""SELECT host, port, severity, cvss, nvt_name, cves, first_seen
                FROM vulnerabilities {where}
                ORDER BY cvss DESC, severity, host
                LIMIT {_MAX_ROWS}""",
            params,
        )

    if len(rows) == _MAX_ROWS:
        log.warning(
            "PDF_EXPORT_TRUNCATED user=%s scan_id=%s limit=%d",
            user.username, scan_id, _MAX_ROWS,
        )

    raw_score = sum(_SEV_WEIGHTS.get(r["severity"], 0) for r in rows)
    risk_score = round(min(10.0, raw_score / max(total, 1) * 1.2), 1) if rows else 0.0

    gen_date = datetime.utcnow()

    # ── Build PDF ──────────────────────────────────────────────────────
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Header band
    pdf.set_fill_color(15, 23, 42)
    pdf.rect(0, 0, 210, 30, "F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_xy(10, 8)
    pdf.cell(0, 10, "OpenVAS Security Report", ln=False)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_xy(10, 20)
    pdf.cell(90, 5, f"Generated: {gen_date.strftime('%Y-%m-%d %H:%M UTC')}", ln=False)
    if scan_id:
        pdf.set_xy(105, 20)
        pdf.cell(0, 5, f"Scan: {_safe(scan_id[:36])}", ln=False)
    pdf.ln(22)

    # Executive Summary
    pdf.set_text_color(30, 30, 30)
    box_y = pdf.get_y()
    pdf.set_fill_color(241, 245, 249)
    pdf.set_draw_color(203, 213, 225)
    pdf.set_line_width(0.3)
    box_h = 36
    pdf.rect(10, box_y, 190, box_h, "FD")

    pdf.set_xy(14, box_y + 4)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 6, "Executive Summary", ln=True)

    metrics = [
        ("Total Vulns", str(total),                         None),
        ("Risk Score",  f"{risk_score}/10",                 None),
        ("Critical",    str(counts.get("Critical", 0)), "Critical"),
        ("High",        str(counts.get("High", 0)),     "High"),
        ("Medium",      str(counts.get("Medium", 0)),   "Medium"),
        ("Low",         str(counts.get("Low", 0)),      "Low"),
        ("Log",         str(counts.get("Log", 0)),      "Log"),
    ]
    col_w = 190.0 / len(metrics)
    for idx, (label, value, sev_key) in enumerate(metrics):
        x = 10 + idx * col_w
        pdf.set_xy(x + 1, box_y + 14)
        pdf.set_font("Helvetica", "", 6)
        pdf.set_text_color(110, 110, 110)
        pdf.cell(col_w - 2, 4, label, align="C", ln=False)
        pdf.set_xy(x + 1, box_y + 19)
        if sev_key and sev_key in _SEV_COLORS:
            r, g, b = _SEV_COLORS[sev_key]
            pdf.set_text_color(r, g, b)
        else:
            pdf.set_text_color(15, 23, 42)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(col_w - 2, 8, value, align="C", ln=False)

    pdf.set_text_color(30, 30, 30)
    pdf.set_y(box_y + box_h + 4)

    # Table
    headers    = ["Host",  "Port", "Severity", "CVSS", "Vulnerability Name", "CVEs",  "First Seen"]
    col_widths = [28,       13,     19,          11,     68,                   28,       23]

    def draw_table_header():
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_fill_color(15, 23, 42)
        pdf.set_text_color(255, 255, 255)
        pdf.set_draw_color(30, 41, 59)
        pdf.set_line_width(0.2)
        for hdr, w in zip(headers, col_widths):
            pdf.cell(w, 7, hdr, border=1, fill=True, align="C")
        pdf.ln()

    draw_table_header()
    pdf.set_line_width(0.1)
    pdf.set_draw_color(226, 232, 240)

    for i, row in enumerate(rows):
        if pdf.get_y() > 272:
            pdf.add_page()
            draw_table_header()

        if i % 2 == 0:
            pdf.set_fill_color(248, 250, 252)
        else:
            pdf.set_fill_color(255, 255, 255)

        sev      = _safe(row["severity"] or "Log")
        sev_rgb  = _SEV_COLORS.get(sev, (107, 114, 128))
        cvss     = row["cvss"] or 0.0
        host     = _safe((row["host"] or "")[:22])
        port     = _safe((row["port"] or "-")[:8])
        name     = _safe((row["nvt_name"] or "")[:72])
        cves_raw = row["cves"] or ""
        cves_str = _safe(", ".join(c for c in cves_raw.split(",") if c)[:26] if cves_raw else "-")
        first    = ""
        if row["first_seen"]:
            try:
                first = datetime.fromisoformat(str(row["first_seen"])).strftime("%Y-%m-%d")
            except Exception:
                first = _safe(str(row["first_seen"])[:10])

        row_h = 5
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(40, 40, 40)

        pdf.cell(col_widths[0], row_h, host,          border="LBR", fill=True, align="L")
        pdf.cell(col_widths[1], row_h, port,          border="LBR", fill=True, align="C")

        r2, g2, b2 = sev_rgb
        pdf.set_text_color(r2, g2, b2)
        pdf.set_font("Helvetica", "B", 7)
        pdf.cell(col_widths[2], row_h, sev,           border="LBR", fill=True, align="C")
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(40, 40, 40)

        pdf.cell(col_widths[3], row_h, f"{cvss:.1f}", border="LBR", fill=True, align="C")
        pdf.cell(col_widths[4], row_h, name,          border="LBR", fill=True, align="L")
        pdf.cell(col_widths[5], row_h, cves_str,      border="LBR", fill=True, align="L")
        pdf.cell(col_widths[6], row_h, first,         border="LBR", fill=True, align="C")
        pdf.ln()

    # Footer
    total_pages = pdf.page
    pdf.set_auto_page_break(False)
    for pn in range(1, total_pages + 1):
        pdf.page = pn
        pdf.set_y(-12)
        pdf.set_font("Helvetica", "I", 7)
        pdf.set_text_color(150, 150, 150)
        pdf.set_draw_color(203, 213, 225)
        pdf.set_line_width(0.2)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(1)
        pdf.cell(
            0, 5,
            f"OpenVAS Security Report  |  Page {pn} of {total_pages}"
            f"  |  {gen_date.strftime('%Y-%m-%d')}",
            align="C",
        )

    pdf_bytes = bytes(pdf.output())
    # Nome do arquivo gerado pela aplicação — sem input do usuário
    filename = f"openvas-report-{gen_date.strftime('%Y%m%d-%H%M')}.pdf"

    log.info("PDF_EXPORTED user=%s scan_id=%s rows=%d", user.username, scan_id, len(rows))

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
