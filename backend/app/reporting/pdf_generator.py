"""Server-Side Forensic PDF Report Generator using ReportLab."""

import html
import io
from typing import Any, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.reporting.models import ForensicReport


def safe_text(val: Any) -> str:
    """Escapes HTML entities for ReportLab XML/HTML-like text rendering."""
    if val is None:
        return "N/A"
    return html.escape(str(val))


def generate_pdf_report(report: ForensicReport) -> bytes:
    """Compiles a complete, multi-page Forensic PDF Report from structured ForensicReport model."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    base_styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=base_styles["Title"],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#1f2328"),
        alignment=0,
        spaceAfter=2,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=base_styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#57606a"),
        spaceAfter=12,
    )
    h1_style = ParagraphStyle(
        "ReportH1",
        parent=base_styles["Heading2"],
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#0969da"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=base_styles["Normal"],
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#24292f"),
    )
    mono_style = ParagraphStyle(
        "ReportMono",
        parent=base_styles["Code"],
        fontSize=7.5,
        leading=9,
        textColor=colors.HexColor("#24292f"),
        wordWrap="CJK",
    )
    bold_style = ParagraphStyle(
        "ReportBold",
        parent=body_style,
        fontName="Helvetica-Bold",
    )
    disclaimer_style = ParagraphStyle(
        "ReportDisclaimer",
        parent=base_styles["Normal"],
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#57606a"),
    )

    elements: List[Any] = []

    # Title Banner
    elements.append(Paragraph("FORENSIC INVESTIGATION REPORT", title_style))
    elements.append(
        Paragraph(
            f"Case: <b>{safe_text(report.case_info.case_id)}</b> • Report ID: {safe_text(report.metadata.report_id)} • Generated: {safe_text(report.metadata.generated_timestamp)}",
            subtitle_style,
        )
    )
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0969da"), spaceAfter=10))

    # Executive Summary Box
    exec_data = [
        [
            Paragraph("<b>FINAL ASSESSMENT</b>", body_style),
            Paragraph("<b>RISK RATING</b>", body_style),
            Paragraph("<b>CONFIDENCE</b>", body_style),
            Paragraph("<b>COVERAGE</b>", body_style),
        ],
        [
            Paragraph(f"<b>{safe_text(report.executive_summary.final_assessment)}</b>", h1_style),
            Paragraph(f"<b>{report.executive_summary.risk_score} / 100</b>", h1_style),
            Paragraph(f"<b>{safe_text(report.executive_summary.confidence)}</b>", body_style),
            Paragraph(f"<b>{report.executive_summary.evidence_coverage_percent}%</b>", body_style),
        ],
        [
            Paragraph(f"<b>Investigative Summary:</b> {safe_text(report.executive_summary.concise_summary)}", body_style),
            "",
            "",
            "",
        ],
    ]
    t_exec = Table(exec_data, colWidths=[130, 130, 130, 150])
    t_exec.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f6f8fa")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#d0d7de")),
                ("SPAN", (0, 2), (3, 2)),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    elements.append(t_exec)
    elements.append(Spacer(1, 10))

    # Case Info & Evidence Integrity
    elements.append(Paragraph("Case & Evidence Integrity", h1_style))
    case_table_data = [
        [
            Paragraph("<b>Case ID:</b>", body_style),
            Paragraph(safe_text(report.case_info.case_id), body_style),
            Paragraph("<b>Integrity Status:</b>", body_style),
            Paragraph(f"<b>{safe_text(report.evidence_integrity.integrity_status)}</b>", body_style),
        ],
        [
            Paragraph("<b>Original File:</b>", body_style),
            Paragraph(safe_text(report.case_info.original_filename), body_style),
            Paragraph("<b>Bytes Altered:</b>", body_style),
            Paragraph(str(report.evidence_integrity.bytes_altered), body_style),
        ],
        [
            Paragraph("<b>File Size:</b>", body_style),
            Paragraph(f"{report.case_info.file_size_bytes} bytes", body_style),
            Paragraph("<b>Evidence SHA-256:</b>", body_style),
            Paragraph(safe_text(report.case_info.evidence_sha256[:24]) + "...", mono_style),
        ],
        [
            Paragraph("<b>Uploaded:</b>", body_style),
            Paragraph(safe_text(report.case_info.upload_timestamp), body_style),
            Paragraph("<b>Report SHA-256:</b>", body_style),
            Paragraph(safe_text(report.metadata.report_sha256[:24]) + "...", mono_style),
        ],
    ]
    t_case = Table(case_table_data, colWidths=[90, 180, 110, 160])
    t_case.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#eaeef2")),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    elements.append(t_case)
    elements.append(Spacer(1, 10))

    # Email Overview
    if report.email_overview:
        elements.append(Paragraph("Email Overview", h1_style))
        email_data = [
            [Paragraph("<b>From:</b>", body_style), Paragraph(safe_text(report.email_overview.sender_from), body_style)],
            [Paragraph("<b>To:</b>", body_style), Paragraph(safe_text(", ".join(report.email_overview.to) if report.email_overview.to else "N/A"), body_style)],
            [Paragraph("<b>Subject:</b>", body_style), Paragraph(f"<b>{safe_text(report.email_overview.subject)}</b>", body_style)],
            [Paragraph("<b>Date:</b>", body_style), Paragraph(safe_text(report.email_overview.date), body_style)],
            [Paragraph("<b>Message-ID:</b>", body_style), Paragraph(safe_text(report.email_overview.message_id), mono_style)],
        ]
        if report.email_overview.body_plain_snippet:
            snippet = report.email_overview.body_plain_snippet[:250] + ("..." if len(report.email_overview.body_plain_snippet) > 250 else "")
            email_data.append([Paragraph("<b>Body Snippet:</b>", body_style), Paragraph(safe_text(snippet), body_style)])

        t_email = Table(email_data, colWidths=[90, 450])
        t_email.setStyle(
            TableStyle(
                [
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#eaeef2")),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        elements.append(t_email)
        elements.append(Spacer(1, 10))

    # Rules Engine Findings
    if report.rules_findings:
        elements.append(Paragraph(f"Rules Engine Findings (Score: {report.rules_findings.total_score} / 100 — {safe_text(report.rules_findings.verdict)})", h1_style))
        if report.rules_findings.matched_rules:
            rules_table_data = [
                [Paragraph("<b>Rule ID</b>", bold_style), Paragraph("<b>Category</b>", bold_style), Paragraph("<b>Points</b>", bold_style), Paragraph("<b>Description</b>", bold_style)]
            ]
            for r in report.rules_findings.matched_rules[:8]:  # Limit to 8 rows for clean page budget
                rules_table_data.append([
                    Paragraph(safe_text(r.rule_id), mono_style),
                    Paragraph(safe_text(r.category), body_style),
                    Paragraph(f"+{r.points}", body_style),
                    Paragraph(safe_text(r.description), body_style),
                ])
            t_rules = Table(rules_table_data, colWidths=[90, 80, 50, 320])
            t_rules.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f6f8fa")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#eaeef2")),
                        ("PADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            elements.append(t_rules)
        else:
            elements.append(Paragraph("No deterministic security rules triggered.", body_style))
        elements.append(Spacer(1, 10))

    # ML Classifier Findings
    if report.ml_findings:
        elements.append(Paragraph(f"Machine Learning Phishing Classifier (v{safe_text(report.ml_findings.model_version)})", h1_style))
        ml_data = [
            [
                Paragraph(f"<b>Prediction:</b> {safe_text(report.ml_findings.prediction)}", body_style),
                Paragraph(f"<b>Phishing Probability:</b> {report.ml_findings.phishing_probability}", body_style),
                Paragraph(f"<b>Confidence:</b> {safe_text(report.ml_findings.confidence)}", body_style),
                Paragraph(f"<b>Status:</b> {safe_text(report.ml_findings.model_status)}", body_style),
            ]
        ]
        t_ml = Table(ml_data, colWidths=[135, 135, 135, 135])
        t_ml.setStyle(
            TableStyle(
                [
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f6f8fa")),
                ]
            )
        )
        elements.append(t_ml)
        elements.append(Paragraph(f"<i>Notice: {safe_text(report.ml_findings.interpretation_note)}</i>", disclaimer_style))
        elements.append(Spacer(1, 10))

    # IOC Threat Intelligence
    if report.ioc_findings:
        elements.append(Paragraph(f"IOC Threat Intelligence (Malicious: {report.ioc_findings.malicious_iocs}, Total: {report.ioc_findings.total_iocs})", h1_style))
        if report.ioc_findings.indicators:
            ioc_table_data = [
                [Paragraph("<b>Type</b>", bold_style), Paragraph("<b>Indicator Value</b>", bold_style), Paragraph("<b>Status</b>", bold_style), Paragraph("<b>Confidence</b>", bold_style), Paragraph("<b>Reason</b>", bold_style)]
            ]
            for ioc in report.ioc_findings.indicators[:10]:
                ioc_table_data.append([
                    Paragraph(safe_text(ioc.ioc_type), body_style),
                    Paragraph(safe_text(ioc.value), mono_style),
                    Paragraph(safe_text(ioc.status), bold_style),
                    Paragraph(f"{ioc.confidence}%", body_style),
                    Paragraph(safe_text(ioc.reason), body_style),
                ])
            t_ioc = Table(ioc_table_data, colWidths=[60, 160, 90, 60, 170])
            t_ioc.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f6f8fa")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#eaeef2")),
                        ("PADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            elements.append(t_ioc)
        elements.append(Spacer(1, 10))

    # Geo / Origin Forensics
    if report.geo_findings:
        elements.append(Paragraph("Network Origin Forensics", h1_style))
        loc_str = f"{report.geo_findings.city or 'Unknown City'}, {report.geo_findings.country or 'Unknown Country'}"
        geo_data = [
            [
                Paragraph(f"<b>Origin IP:</b> {safe_text(report.geo_findings.selected_origin_ip)}", body_style),
                Paragraph(f"<b>Confidence:</b> {safe_text(report.geo_findings.confidence)}", body_style),
            ],
            [
                Paragraph(f"<b>Location:</b> {safe_text(loc_str)}", body_style),
                Paragraph(f"<b>ASN:</b> {safe_text(report.geo_findings.asn_org or 'N/A')}", body_style),
            ],
            [
                Paragraph(
                    f"<b>Tor:</b> {'YES' if report.geo_findings.is_tor else 'No'} • "
                    f"<b>VPN:</b> {'YES' if report.geo_findings.is_vpn else 'No'} • "
                    f"<b>Proxy:</b> {'YES' if report.geo_findings.is_proxy else 'No'} • "
                    f"<b>Hosting:</b> {'YES' if report.geo_findings.is_hosting else 'No'}",
                    body_style,
                ),
                Paragraph(f"<b>Range:</b> {'TEST / DOC RANGE' if report.geo_findings.is_documentation_range else 'Public Internet'}", body_style),
            ],
        ]
        t_geo = Table(geo_data, colWidths=[270, 270])
        t_geo.setStyle(
            TableStyle(
                [
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#eaeef2")),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        elements.append(t_geo)
        elements.append(Paragraph(f"<i>{safe_text(report.geo_findings.disclaimer)}</i>", disclaimer_style))
        elements.append(Spacer(1, 10))

    # Correlation Synthesis
    if report.correlation:
        elements.append(Paragraph("Correlation Synthesis & Top Evidence", h1_style))
        elements.append(Paragraph(f"<b>Multi-Signal Risk Score:</b> {report.correlation.final_score} / 100 • <b>Assessment:</b> {safe_text(report.correlation.final_assessment)}", bold_style))
        elements.append(Paragraph(f"<i>{safe_text(report.correlation.score_explanation)}</i>", disclaimer_style))
        elements.append(Spacer(1, 4))

        if report.correlation.top_evidence:
            ev_table_data = [
                [Paragraph("<b>Rank</b>", bold_style), Paragraph("<b>Engine</b>", bold_style), Paragraph("<b>Impact</b>", bold_style), Paragraph("<b>Evidence Description</b>", bold_style)]
            ]
            for ev in report.correlation.top_evidence[:5]:
                ev_table_data.append([
                    Paragraph(f"#{ev.rank}", body_style),
                    Paragraph(safe_text(ev.engine), mono_style),
                    Paragraph(safe_text(ev.impact.upper()), bold_style),
                    Paragraph(safe_text(ev.description), body_style),
                ])
            t_ev = Table(ev_table_data, colWidths=[40, 70, 60, 370])
            t_ev.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f6f8fa")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#eaeef2")),
                        ("PADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            elements.append(t_ev)
        elements.append(Spacer(1, 10))

    # Audit & Provenance Summary
    if report.audit_timeline or report.provenance:
        elements.append(Paragraph("Audit Trail & Software Provenance", h1_style))
        chain_text = "VALID" if (report.audit_timeline and report.audit_timeline.audit_chain_valid) else "INVALID / ANOMALOUS"
        events_count = report.audit_timeline.total_events if report.audit_timeline else 0
        m_sha = (report.evidence_manifest.manifest_sha256[:16] + "...") if (report.evidence_manifest and report.evidence_manifest.manifest_sha256) else "N/A"
        prov_summary = [
            [
                Paragraph(f"<b>Audit Hash Chain:</b> {chain_text} ({events_count} blocks)", body_style),
                Paragraph(f"<b>Manifest SHA:</b> {safe_text(m_sha)}", mono_style),
            ],
            [
                Paragraph(
                    f"<b>Software Versions:</b> Parser v{safe_text(report.provenance.parser_version if report.provenance else '1.0.0')} • "
                    f"Rules v{safe_text(report.provenance.rules_engine_version if report.provenance else '1.0.0')} • "
                    f"ML v{safe_text(report.provenance.ml_model_version if report.provenance else '1.0.0')}",
                    body_style,
                ),
                Paragraph(
                    f"<b>Policy/Feeds:</b> Policy v{safe_text(report.provenance.correlation_policy_version if report.provenance else '1.0.0')} • "
                    f"IOC Feed v{safe_text(report.provenance.ioc_feed_version if report.provenance else 'unknown')}",
                    body_style,
                ),
            ],
        ]
        t_prov = Table(prov_summary, colWidths=[270, 270])
        t_prov.setStyle(
            TableStyle(
                [
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#eaeef2")),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        elements.append(t_prov)
        elements.append(Spacer(1, 10))

    # Forensic Disclaimer
    elements.append(
        Paragraph(
            f"<b>Forensic Disclaimer:</b> {safe_text(report.forensic_disclaimer)}",
            disclaimer_style,
        )
    )

    doc.build(elements)
    return buffer.getvalue()
