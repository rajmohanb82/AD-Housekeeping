"""Printable housekeeping report. The PDF never includes a password."""

from __future__ import annotations

from datetime import datetime

from fpdf import FPDF

NAVY = (14, 28, 47)
BLUE = (15, 108, 189)
INK = (18, 32, 51)
MUTED = (92, 107, 124)
PAPER = (255, 255, 255)
RULE = (219, 227, 236)


def _safe(text: str) -> str:
    cleaned = (
        str(text)
        .replace("\u2014", " - ")
        .replace("\u2013", "-")
        .replace("\u2018", "'")
        .replace("\u2019", "'")
        .replace("\u201c", '"')
        .replace("\u201d", '"')
    )
    return cleaned.encode("latin-1", "replace").decode("latin-1")


class Report(FPDF):
    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 8, _safe(f"Directory Keep  ·  page {self.page_no()}  ·  directory passwords are not included"), align="L")


def _band(pdf: Report, title: str, subtitle: str) -> None:
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, 210, 34, "F")
    pdf.set_xy(14, 8)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 8, _safe(title))
    pdf.set_xy(14, 18)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(190, 210, 230)
    pdf.cell(0, 6, _safe(subtitle))
    pdf.set_text_color(*INK)
    pdf.set_y(42)


def build_pdf(state: dict, hardening: list[dict], signed_in: str) -> bytes:
    summary = state.get("published_summary") or {}
    domain = (state.get("domain") or {}).get("dns", "fabrikam.corp")
    connection = state.get("connection") or {}
    when = datetime.now().strftime("%d %b %Y, %H:%M")
    pdf = Report(format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_left_margin(14)
    pdf.set_right_margin(14)
    pdf.add_page()
    _band(pdf, "Directory Keep", f"Housekeeping report  ·  {domain}")

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*MUTED)
    pdf.cell(0, 6, _safe(f"Published {when}"))
    pdf.ln(6)
    pdf.set_text_color(*INK)
    who = signed_in or "Not signed in - this copy is a preview of the lab dataset"
    pdf.multi_cell(0, 6, _safe(who), new_x="LMARGIN", new_y="NEXT")
    if connection.get("host"):
        pdf.set_x(14)
        pdf.set_text_color(*MUTED)
        pdf.cell(0, 6, _safe(f"Directory target {connection.get('username', '')} @ {connection.get('host')}"))
        pdf.ln(6)
    pdf.ln(2)

    pdf.set_fill_color(238, 242, 246)
    pdf.set_draw_color(*RULE)
    y = pdf.get_y()
    pdf.rect(14, y, 182, 28, "DF")
    pdf.set_xy(18, y + 4)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*BLUE)
    pdf.cell(28, 12, str(summary.get("score", "-")))
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*INK)
    pdf.cell(0, 12, _safe(f"{summary.get('band', '')}   ·   {summary.get('total', 0)} findings"))
    pdf.set_xy(18, y + 16)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*MUTED)
    pdf.cell(0, 6, _safe(summary.get("briefing", "")))
    pdf.set_y(y + 34)

    pdf.set_text_color(*INK)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Categorized findings")
    pdf.ln(8)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(*NAVY)
    pdf.set_text_color(255, 255, 255)
    for label, width in (("Severity", 28), ("Category", 42), ("Finding", 112)):
        pdf.cell(width, 7, label, fill=True)
    pdf.ln(7)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*INK)
    alerts = state.get("published_alerts") or []
    if not alerts:
        pdf.cell(0, 8, "No published findings.")
        pdf.ln(8)
    for index, alert in enumerate(alerts):
        if pdf.get_y() > 270:
            pdf.add_page()
            _band(pdf, "Directory Keep", "Findings, continued")
        fill = index % 2 == 0
        if fill:
            pdf.set_fill_color(244, 247, 251)
        title = _safe(alert["title"])[:78]
        pdf.cell(28, 7, _safe(alert["severity"]), fill=fill)
        pdf.cell(42, 7, _safe(alert["category"])[:26], fill=fill)
        pdf.cell(112, 7, title, fill=fill)
        pdf.ln(7)

    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*INK)
    pdf.cell(0, 8, "Server hardening")
    pdf.ln(8)
    pdf.set_font("Helvetica", "", 9)
    shown = [row for row in hardening if row["status"] != "pass"]
    if not shown:
        pdf.cell(0, 6, "No open hardening items.")
        pdf.ln(6)
    for row in shown:
        if pdf.get_y() > 255:
            pdf.add_page()
            _band(pdf, "Directory Keep", "Hardening, continued")
        pdf.set_x(14)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*INK)
        pdf.multi_cell(182, 5, _safe(f"{row['server']}  ·  {row['title']}  ({row['status']})"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*MUTED)
        pdf.multi_cell(182, 5, _safe(row["summary"]), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(*BLUE)
        pdf.multi_cell(182, 5, _safe(row["doc_title"]), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*INK)
    pdf.cell(0, 8, "Servers in scope")
    pdf.ln(8)
    pdf.set_font("Helvetica", "", 9)
    names = [dc["name"] + "  domain controller" for dc in state.get("domain_controllers", [])]
    names += [item["name"] + "  " + item.get("role", "server").replace("-", " ") for item in state.get("managed_servers", [])]
    for name in names:
        pdf.set_text_color(*INK)
        pdf.cell(0, 6, _safe(name))
        pdf.ln(6)

    return bytes(pdf.output())
