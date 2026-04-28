from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.finding import Severity
# Import all models to register with SQLAlchemy metadata
from app.models import target as _target_module  # noqa: F401
from app.models import user as _user_module  # noqa: F401

SEVERITY_COLORS_MAP = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#f97316"),
    "medium": colors.HexColor("#eab308"),
    "low": colors.HexColor("#3b82f6"),
    "informational": colors.HexColor("#6b7280"),
}

def generate_project_report(project_id: int, output_path: str) -> str:
    db = SessionLocal()
    from app.models.project import Project
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise ValueError(f"Project {project_id} not found")

    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=20, spaceAfter=12)
    heading_style = ParagraphStyle('CustomH1', parent=styles['Heading1'], fontSize=14, spaceAfter=8, spaceBefore=16)

    story = []

    # Cover
    story.append(Paragraph("VAPT REPORT", styles['Title']))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(f"Project: {project.name}", title_style))
    story.append(Spacer(1, 0.5*cm))
    if project.vendor_name:
        story.append(Paragraph(f"<b>Vendor:</b> {project.vendor_name}", styles['Normal']))
    story.append(Paragraph(f"<b>Periode:</b> {project.start_date} s/d {project.end_date}", styles['Normal']))
    story.append(Paragraph(f"<b>Status:</b> {project.status.value.replace('_', ' ').title()}", styles['Normal']))
    if project.scope:
        story.append(Paragraph(f"<b>Scope:</b> {project.scope}", styles['Normal']))
    if project.description:
        story.append(Paragraph(f"<b>Deskripsi:</b> {project.description}", styles['Normal']))
    story.append(Spacer(1, 1*cm))

    # Findings Summary
    findings = sorted(project.findings, key=lambda f: ["critical", "high", "medium", "low", "informational"].index(f.severity))

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for f in project.findings:
        severity_counts[f.severity] += 1

    story.append(Paragraph("Ringkasan Temuan", heading_style))
    summary_data = [["Severity", "Jumlah"]]
    for sev, count in severity_counts.items():
        summary_data.append([sev.upper().replace("INFORMATIONAL", "INFO"), str(count)])

    t = Table(summary_data, colWidths=[8*cm, 4*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#374151")),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (0, 1), SEVERITY_COLORS_MAP.get("critical", colors.red)),
        ('BACKGROUND', (0, 2), (0, 2), SEVERITY_COLORS_MAP.get("high", colors.orange)),
        ('BACKGROUND', (0, 3), (0, 3), SEVERITY_COLORS_MAP.get("medium", colors.yellow)),
        ('BACKGROUND', (0, 4), (0, 4), SEVERITY_COLORS_MAP.get("low", colors.blue)),
        ('BACKGROUND', (0, 5), (0, 5), SEVERITY_COLORS_MAP.get("informational", colors.grey)),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.white),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
    ]))
    story.append(t)
    story.append(Spacer(1, 1*cm))

    # Detailed Findings
    if findings:
        story.append(Paragraph("Detail Temuan", heading_style))
        for i, f in enumerate(findings):
            story.append(PageBreak())
            sev_color = SEVERITY_COLORS_MAP.get(f.severity, colors.grey)

            header_data = [[
                Paragraph(f"<b>Finding #{i+1}: {f.title}</b>", styles['Normal']),
                Paragraph(f"<b>[{f.severity.upper()}]</b>", styles['Normal'])
            ]]
            ht = Table(header_data, colWidths=[12*cm, 4*cm])
            ht.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), sev_color),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
            ]))
            story.append(ht)
            story.append(Spacer(1, 0.3*cm))

            meta_text = f"Status: {f.status.replace('_', ' ').title()}"
            if f.cve_id:
                meta_text += f" | CVE: {f.cve_id}"
            if f.cvss_score is not None:
                meta_text += f" | CVSS: {f.cvss_score}"
            if f.owasp_category:
                meta_text += f" | {f.owasp_category}"
            story.append(Paragraph(meta_text, styles['Normal']))
            story.append(Spacer(1, 0.3*cm))

            for label, field in [
                ("Deskripsi", f.description),
                ("Langkah Reproduksi", f.steps_to_reproduce),
                ("Dampak", f.impact),
                ("Remediasi", f.remediation)
            ]:
                if field:
                    story.append(Paragraph(f"<b>{label}:</b>", styles['Normal']))
                    story.append(Paragraph(field, styles['Normal']))
                    story.append(Spacer(1, 0.2*cm))

    db.close()
    doc.build(story)
    return output_path
