# ─────────────────────────────────────────────
#  modules/report_generator.py  —  MODULE 13
#  Forensic PDF Report Generation
#
#  WHY THIS EXISTS:
#  After completing the analysis, investigators need
#  a formal document they can save, share, print, or
#  submit as part of an investigation. This module
#  uses ReportLab to generate a structured multi-page
#  PDF containing every finding from every module.
#
#  WHY REPORTLAB:
#  ReportLab is a Python library that creates PDFs
#  programmatically — you define exactly what goes
#  on each page: headings, tables, paragraphs, lines.
#  No Word/LibreOffice needed — pure Python.
# ─────────────────────────────────────────────
import io
from datetime import datetime, timezone
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

# ── Colour palette ────────────────────────────
_DARK_BG    = colors.HexColor('#1e293b')
_BLUE       = colors.HexColor('#3b82f6')
_RED        = colors.HexColor('#ef4444')
_ORANGE     = colors.HexColor('#f97316')
_YELLOW     = colors.HexColor('#eab308')
_GREEN      = colors.HexColor('#22c55e')
_SLATE_400  = colors.HexColor('#94a3b8')
_SLATE_600  = colors.HexColor('#475569')
_WHITE      = colors.white
_BLACK      = colors.HexColor('#0f172a')

# ── Risk level colours ────────────────────────
_LEVEL_COLORS = {
    'CRITICAL': _RED,
    'HIGH':     _ORANGE,
    'MEDIUM':   _YELLOW,
    'LOW':      _GREEN,
}


def _make_styles():
    """Build a set of paragraph styles for the report."""
    base = getSampleStyleSheet()

    styles = {
        'title': ParagraphStyle(
            'ReportTitle',
            fontName='Helvetica-Bold',
            fontSize=20,
            textColor=_BLUE,
            spaceAfter=4,
            alignment=TA_CENTER,
        ),
        'subtitle': ParagraphStyle(
            'Subtitle',
            fontName='Helvetica',
            fontSize=10,
            textColor=_SLATE_400,
            spaceAfter=2,
            alignment=TA_CENTER,
        ),
        'section': ParagraphStyle(
            'SectionHeading',
            fontName='Helvetica-Bold',
            fontSize=12,
            textColor=_BLUE,
            spaceBefore=14,
            spaceAfter=6,
            borderPadding=(0, 0, 4, 0),
        ),
        'subsection': ParagraphStyle(
            'SubHeading',
            fontName='Helvetica-Bold',
            fontSize=10,
            textColor=_SLATE_400,
            spaceBefore=8,
            spaceAfter=4,
        ),
        'body': ParagraphStyle(
            'BodyText',
            fontName='Helvetica',
            fontSize=9,
            textColor=_BLACK,
            spaceAfter=4,
            leading=14,
        ),
        'mono': ParagraphStyle(
            'MonoText',
            fontName='Courier',
            fontSize=8,
            textColor=_BLACK,
            spaceAfter=3,
        ),
        'disclaimer': ParagraphStyle(
            'Disclaimer',
            fontName='Helvetica-Oblique',
            fontSize=8,
            textColor=_SLATE_600,
            spaceAfter=4,
            leading=12,
        ),
        'footer': ParagraphStyle(
            'Footer',
            fontName='Helvetica',
            fontSize=7,
            textColor=_SLATE_600,
            alignment=TA_CENTER,
        ),
    }
    return styles


def _hr(color=_SLATE_600):
    return HRFlowable(width='100%', thickness=0.5, color=color, spaceAfter=6, spaceBefore=2)


def _kv_table(rows: list[tuple[str, str]], styles) -> Table:
    """Creates a two-column key-value table."""
    data = [[Paragraph(f'<b>{k}</b>', styles['body']),
             Paragraph(str(v) if v else '—', styles['body'])]
            for k, v in rows]
    t = Table(data, colWidths=[4.5 * cm, 13 * cm])
    t.setStyle(TableStyle([
        ('VALIGN',      (0, 0), (-1, -1), 'TOP'),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#f8fafc'), _WHITE]),
        ('FONTSIZE',    (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING',    (0, 0), (-1, -1), 4),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('GRID',        (0, 0), (-1, -1), 0.3, _SLATE_600),
    ]))
    return t


def _flag_table(flags: list[dict], styles) -> Table:
    """Creates a table of flags/indicators.
    FIX 2: wider Description column, Flag column wraps instead of overflowing.
    """
    if not flags:
        return Paragraph('No flags detected.', styles['body'])

    # Use Paragraph in every cell so text wraps properly instead of overflowing
    hdr_s = ParagraphStyle('FlagHdr', fontName='Helvetica-Bold', fontSize=8, textColor=_WHITE)
    cel_s = ParagraphStyle('FlagCell', fontName='Helvetica', fontSize=8, textColor=_BLACK, leading=11)

    data = [[
        Paragraph('Severity',    hdr_s),
        Paragraph('Flag',        hdr_s),
        Paragraph('Description', hdr_s),
    ]]
    for f in flags:
        sev = f.get('severity', 'INFO')
        data.append([
            Paragraph(sev,                       cel_s),
            Paragraph(f.get('flag', ''),         cel_s),
            Paragraph(f.get('description', ''),  cel_s),
        ])

    # Total usable width ≈ 17.5 cm (A4 210mm − 30mm margins)
    t = Table(data, colWidths=[2 * cm, 4.5 * cm, 11 * cm])
    # row[0] is now a Paragraph — extract its text via .text attribute
    row_colors = []
    for i, row in enumerate(data[1:], 1):
        sev_text = row[0].text if hasattr(row[0], 'text') else str(row[0])
        c = (_RED    if sev_text == 'HIGH'   else
             _ORANGE if sev_text == 'MEDIUM' else
             _YELLOW if sev_text == 'LOW'    else colors.HexColor('#e0f2fe'))
        row_colors.append(('BACKGROUND', (0, i), (0, i), c))

    t.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0), (-1, 0), _DARK_BG),
        ('TEXTCOLOR',   (0, 0), (-1, 0), _WHITE),
        ('FONTNAME',    (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',    (0, 0), (-1, -1), 8),
        ('GRID',        (0, 0), (-1, -1), 0.3, _SLATE_600),
        ('VALIGN',      (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        *row_colors,
    ]))
    return t


# ── Page header / footer callbacks ───────────

def _make_page_header_footer(case_id: str, total_pages_ref: list):
    """Returns an onFirstPage / onLaterPages callback for header+footer."""
    def draw(canvas, doc):
        w, h = A4
        # Header bar
        canvas.saveState()
        canvas.setFillColor(_DARK_BG)
        canvas.rect(0, h - 1.2 * cm, w, 1.2 * cm, fill=1, stroke=0)
        canvas.setFillColor(_BLUE)
        canvas.setFont('Helvetica-Bold', 9)
        canvas.drawString(1.5 * cm, h - 0.8 * cm, 'AI Email Threat Detection Platform')
        canvas.setFillColor(_SLATE_400)
        canvas.setFont('Helvetica', 8)
        canvas.drawRightString(w - 1.5 * cm, h - 0.8 * cm, f'Case: {case_id}')

        # Footer
        canvas.setFillColor(_SLATE_600)
        canvas.setFont('Helvetica', 7)
        canvas.drawCentredString(w / 2, 0.7 * cm,
            f'FORENSIC INVESTIGATION REPORT  |  Page {doc.page}  |  '
            'CONFIDENTIAL — FOR INVESTIGATIVE USE ONLY')
        canvas.restoreState()

    return draw, draw


# ── Main report generation ────────────────────

def generate_pdf_report(analysis: dict[str, Any]) -> bytes:
    """
    Main entry point for Module 13.

    INPUT : full analysis document from MongoDB
    OUTPUT: PDF file as bytes (sent directly to the browser)
    """
    buf    = io.BytesIO()
    styles = _make_styles()

    case_id  = analysis.get('case_id', 'UNKNOWN')
    filename = analysis.get('filename', 'unknown.eml')

    on_first, on_later = _make_page_header_footer(case_id, [0])

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.5 * cm,
        title=f'Forensic Report — {case_id}',
        author='AI Email Threat Detection Platform',
    )

    story = []

    # ─────────────────────────────────────────
    # COVER / TITLE
    # ─────────────────────────────────────────
    story.append(Spacer(1, 1.5 * cm))
    story.append(Paragraph('FORENSIC INVESTIGATION REPORT', styles['title']))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph('AI-Powered Email Threat Detection Platform', styles['subtitle']))
    story.append(Spacer(1, 0.5 * cm))
    story.append(_hr(_BLUE))

    risk    = analysis.get('risk_score', {}) or {}
    level   = risk.get('risk_level', 'UNKNOWN')
    score   = risk.get('score', 0)
    cls     = risk.get('classification', 'UNKNOWN')
    lvl_color = _LEVEL_COLORS.get(level, _SLATE_400)

    # Risk summary box
    # FIX 1: header labels use a white-text style so they show on the dark background
    hdr_style = ParagraphStyle(
        'RiskHdr', fontName='Helvetica-Bold', fontSize=9,
        textColor=_WHITE, alignment=TA_CENTER,
    )
    val_style = ParagraphStyle(
        'RiskVal', fontName='Helvetica-Bold', fontSize=9,
        textColor=_BLACK, alignment=TA_CENTER,
    )
    risk_data = [[
        Paragraph('Risk Score',     hdr_style),
        Paragraph('Risk Level',     hdr_style),
        Paragraph('Classification', hdr_style),
        Paragraph('AI Confidence',  hdr_style),
    ],[
        Paragraph(f'<font size="18"><b>{score}/100</b></font>', val_style),
        Paragraph(f'<b>{level}</b>', val_style),
        Paragraph(f'<b>{cls}</b>',   val_style),
        Paragraph(f'{risk.get("ai_confidence", 0)}%', val_style),
    ]]
    risk_table = Table(risk_data, colWidths=[4.5 * cm, 4.5 * cm, 4.5 * cm, 4 * cm])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0), _DARK_BG),
        ('BACKGROUND',    (0, 1), (0, 1), lvl_color),
        ('TEXTCOLOR',     (0, 1), (0, 1), _WHITE),
        ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTSIZE',      (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('GRID',          (0, 0), (-1, -1), 0.5, _SLATE_600),
        ('BOX',           (0, 0), (-1, -1), 1, lvl_color),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 0.4 * cm))

    # ─────────────────────────────────────────
    # SECTION 1 — Case Information
    # ─────────────────────────────────────────
    story.append(Paragraph('1. Case Information', styles['section']))
    story.append(_hr())
    evidence = analysis.get('evidence', {}) or {}
    story.append(_kv_table([
        ('Case ID',           case_id),
        ('Evidence File',     filename),
        ('SHA-256 Hash',      evidence.get('sha256', '—')),
        ('File Size',         f"{evidence.get('file_size_bytes', 0)} bytes"),
        ('Upload Timestamp',  evidence.get('upload_timestamp_readable', '—')),
        ('Analysis Version',  analysis.get('analysis_version', '—')),
        ('Status',            analysis.get('status', '—')),
    ], styles))

    # ─────────────────────────────────────────
    # SECTION 2 — Email Information
    # ─────────────────────────────────────────
    story.append(Paragraph('2. Email Information', styles['section']))
    story.append(_hr())
    ei = analysis.get('email_info', {}) or {}
    story.append(_kv_table([
        ('From',         ei.get('from_raw', '—')),
        ('To',           ei.get('to', '—')),
        ('Subject',      ei.get('subject', '—')),
        ('Date',         ei.get('date', '—')),
        ('Reply-To',     ei.get('reply_to', '—') or '—'),
        ('Return-Path',  ei.get('return_path', '—') or '—'),
        ('Message-ID',   ei.get('message_id', '—')),
        ('X-Originating-IP', ei.get('x_originating_ip', '—') or '—'),
    ], styles))

    # ─────────────────────────────────────────
    # SECTION 3 — Authentication Analysis
    # ─────────────────────────────────────────
    story.append(Paragraph('3. Authentication Analysis (SPF / DKIM / DMARC)', styles['section']))
    story.append(_hr())
    auth = analysis.get('authentication', {}) or {}
    story.append(_kv_table([
        ('SPF Result',   auth.get('spf', '—')),
        ('DKIM Result',  auth.get('dkim', '—')),
        ('DMARC Result', auth.get('dmarc', '—')),
        ('DKIM Signature Present', str(auth.get('dkim_signature_present', False))),
        ('Summary',      auth.get('summary', '—')),
    ], styles))
    if auth.get('flags'):
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph('Authentication Flags:', styles['subsection']))
        story.append(_flag_table(auth['flags'], styles))

    # ─────────────────────────────────────────
    # SECTION 4 — Header Forensics
    # ─────────────────────────────────────────
    story.append(Paragraph('4. Header Forensics', styles['section']))
    story.append(_hr())
    hf = analysis.get('header_forensics', {}) or {}
    story.append(_kv_table([
        ('Received Headers',  str(hf.get('received_count', 0))),
        ('Routing IPs',       ', '.join(hf.get('routing_ips', [])) or '—'),
        ('Summary',           hf.get('summary', '—')),
    ], styles))
    if hf.get('flags'):
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph('Header Flags:', styles['subsection']))
        story.append(_flag_table(hf['flags'], styles))

    story.append(Spacer(1, 0.3 * cm))

    # ─────────────────────────────────────────
    # SECTION 5 — AI/ML Analysis
    # ─────────────────────────────────────────
    story.append(Paragraph('5. AI/ML Threat Detection', styles['section']))
    story.append(_hr())
    ai = analysis.get('ai_detection', {}) or {}
    story.append(_kv_table([
        ('Classification',    ai.get('classification', '—')),
        ('Confidence',        f"{ai.get('confidence', 0)}%"),
        ('Model Used',        ai.get('model_used', '—')),
        ('Keyword Score',     str(ai.get('keyword_score', 0))),
        ('Score Contribution', str(ai.get('score_contribution', 0))),
    ], styles))
    if ai.get('explanation'):
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph('Explanation:', styles['subsection']))
        story.append(Paragraph(ai['explanation'], styles['body']))
    if ai.get('detected_patterns'):
        story.append(Paragraph(
            'Detected patterns: ' + ', '.join(ai['detected_patterns']),
            styles['body']
        ))

    # ─────────────────────────────────────────
    # SECTION 6 — URL Analysis
    # ─────────────────────────────────────────
    story.append(Paragraph('6. URL Analysis', styles['section']))
    story.append(_hr())
    ua = analysis.get('url_analysis', {}) or {}
    story.append(_kv_table([
        ('URLs Found',     str(ua.get('urls_found', 0))),
        ('High Risk URLs', str(len(ua.get('high_risk_urls', [])))),
        ('Summary',        ua.get('summary', '—')),
    ], styles))

    for url_res in (ua.get('url_results') or [])[:8]:
        flags = url_res.get('flags', [])
        risk_str = url_res.get('risk', 'UNKNOWN')
        story.append(Spacer(1, 0.15 * cm))
        url_data = [[
            Paragraph(f'<b>URL</b>', styles['body']),
            Paragraph(url_res.get('url', ''), styles['mono']),
        ],[
            Paragraph('<b>Risk</b>', styles['body']),
            Paragraph(risk_str, styles['body']),
        ]]
        if flags:
            flag_texts = '; '.join(f.get('description', '') for f in flags[:3])
            url_data.append([
                Paragraph('<b>Flags</b>', styles['body']),
                Paragraph(flag_texts, styles['body']),
            ])
        t = Table(url_data, colWidths=[2.5 * cm, 15 * cm])
        t.setStyle(TableStyle([
            ('GRID',     (0, 0), (-1, -1), 0.3, _SLATE_600),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('VALIGN',   (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING',    (0, 0), (-1, -1), 4),
            ('LEFTPADDING',   (0, 0), (-1, -1), 6),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f1f5f9')),
        ]))
        story.append(t)

    # ─────────────────────────────────────────
    # SECTION 7 — IP Intelligence
    # ─────────────────────────────────────────
    story.append(Paragraph('7. IP & Infrastructure Intelligence', styles['section']))
    story.append(_hr())
    ip_intel = analysis.get('ip_intel', {}) or {}
    story.append(_kv_table([
        ('IPs Investigated', str(ip_intel.get('ips_investigated', 0))),
        ('Countries',        ', '.join(ip_intel.get('countries', [])) or '—'),
        ('ISPs',             ', '.join(ip_intel.get('isps', [])) or '—'),
        ('Hosting IPs',      ', '.join(ip_intel.get('hosting_ips', [])) or '—'),
        ('Summary',          ip_intel.get('summary', '—')),
    ], styles))

    ip_results = ip_intel.get('ip_results', []) or []
    if ip_results:
        story.append(Spacer(1, 0.2 * cm))
        ip_data = [['IP Address', 'Country', 'Region', 'ISP', 'ASN', 'Hosting']]
        for ipr in ip_results:
            ip_data.append([
                ipr.get('ip', ''),
                ipr.get('country', ''),
                ipr.get('region', ''),
                ipr.get('isp', '')[:25],
                ipr.get('asn', '')[:20],
                'Yes' if ipr.get('is_hosting') else 'No',
            ])
        ip_table = Table(ip_data, colWidths=[3*cm, 3*cm, 3*cm, 4*cm, 3*cm, 1.5*cm])
        ip_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), _DARK_BG),
            ('TEXTCOLOR',  (0, 0), (-1, 0), _WHITE),
            ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE',   (0, 0), (-1, -1), 7.5),
            ('GRID',       (0, 0), (-1, -1), 0.3, _SLATE_600),
            ('VALIGN',     (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN',      (0, 0), (-1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING',    (0, 0), (-1, -1), 5),
            ('LEFTPADDING',   (0, 0), (-1, -1), 5),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f8fafc'), _WHITE]),
        ]))
        story.append(ip_table)

    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(
        'DISCLAIMER: IP geolocation data represents the approximate location of the observed '
        'mail server infrastructure. It does NOT represent the physical location or identity '
        'of the sender. Attackers frequently use VPNs, proxies, cloud servers, and compromised '
        'machines to obscure their true location.',
        styles['disclaimer']
    ))

    story.append(Spacer(1, 0.3 * cm))

    # ─────────────────────────────────────────
    # SECTION 8 — Threat Indicators
    # ─────────────────────────────────────────
    story.append(Paragraph('8. Correlated Threat Indicators', styles['section']))
    story.append(_hr())
    corr = analysis.get('correlation', {}) or {}
    story.append(_kv_table([
        ('Total Indicators',     str(corr.get('total_indicator_count', 0))),
        ('High Severity',        str(corr.get('high_indicator_count', 0))),
        ('Infrastructure Overlap', str(corr.get('infrastructure_overlap', False))),
        ('Shared IPs',           ', '.join(corr.get('shared_ips', [])) or 'None'),
        ('Summary',              corr.get('summary', '—')),
    ], styles))

    all_indicators = corr.get('all_indicators', []) or []
    if all_indicators:
        story.append(Spacer(1, 0.2 * cm))
        story.append(_flag_table(all_indicators[:20], styles))

    # ─────────────────────────────────────────
    # SECTION 9 — Score Breakdown
    # ─────────────────────────────────────────
    story.append(Paragraph('9. Risk Score Breakdown', styles['section']))
    story.append(_hr())
    breakdown = risk.get('breakdown', {}) or {}
    bd_data = [['Module', 'Score', 'Max', 'Percentage']]
    for key, val in breakdown.items():
        pct = round((val['score'] / val['max']) * 100) if val['max'] else 0
        bd_data.append([val['label'], str(val['score']), str(val['max']), f'{pct}%'])
    bd_data.append(['TOTAL', str(score), '100', f'{score}%'])

    bd_table = Table(bd_data, colWidths=[9*cm, 2.5*cm, 2.5*cm, 3.5*cm])
    bd_table.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0),  (-1, 0),  _DARK_BG),
        ('TEXTCOLOR',   (0, 0),  (-1, 0),  _WHITE),
        ('FONTNAME',    (0, 0),  (-1, 0),  'Helvetica-Bold'),
        ('BACKGROUND',  (0, -1), (-1, -1), lvl_color),
        ('TEXTCOLOR',   (0, -1), (-1, -1), _WHITE),
        ('FONTNAME',    (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE',    (0, 0),  (-1, -1), 9),
        ('ALIGN',       (1, 0),  (-1, -1), 'CENTER'),
        ('GRID',        (0, 0),  (-1, -1), 0.3, _SLATE_600),
        ('VALIGN',      (0, 0),  (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING',    (0, 0), (-1, -1), 6),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('ROWBACKGROUNDS', (0, 1), (-1, -2), [colors.HexColor('#f8fafc'), _WHITE]),
    ]))
    story.append(bd_table)

    # Major reasons
    major_reasons = risk.get('major_reasons', []) or []
    if major_reasons:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph('Major Risk Factors:', styles['subsection']))
        for i, reason in enumerate(major_reasons, 1):
            story.append(Paragraph(f'{i}. {reason}', styles['body']))

    # ─────────────────────────────────────────
    # SECTION 10 — Conclusion
    # ─────────────────────────────────────────
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph('10. Conclusion', styles['section']))
    story.append(_hr())
    conclusion = risk.get('conclusion', '')
    if conclusion:
        story.append(Paragraph(conclusion, styles['body']))

    story.append(Spacer(1, 0.5 * cm))
    story.append(_hr(_BLUE))
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    story.append(Paragraph(
        f'Report generated: {now}  |  Case ID: {case_id}  |  '
        'AI Email Threat Detection Platform v3.0',
        styles['footer']
    ))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(
        'This report is generated automatically by an AI-assisted forensic analysis system. '
        'All findings are indicative and should be verified by a qualified security analyst before '
        'being used as definitive evidence in any legal or disciplinary proceeding.',
        styles['disclaimer']
    ))

    # ─────────────────────────────────────────
    # Build PDF
    # ─────────────────────────────────────────
    doc.build(story, onFirstPage=on_first, onLaterPages=on_later)
    return buf.getvalue()
