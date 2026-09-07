"""Attachment inspection rules for Email Fraud Detection.

Deterministic inspection of parsed email attachments:
- RULE-ATTACH-001: Attachment present in email
- RULE-ATTACH-002: Suspicious executable or script extension
- RULE-ATTACH-003: Double extension attack pattern
- RULE-ATTACH-004: Suspicious financial or urgency filename pattern
"""

import os
import re
from typing import Any, Dict, List

from app.rules.models import RuleCategory, RuleDefinition, RuleResult, RuleSeverity
from app.rules.registry import BaseRule


class AttachmentPresentRule(BaseRule):
    """RULE-ATTACH-001: Attachment Present."""

    def __init__(self):
        super().__init__(
            RuleDefinition(
                rule_id="RULE-ATTACH-001",
                name="Attachment Present",
                category=RuleCategory.ATTACHMENT,
                severity=RuleSeverity.INFO,
                default_score=2,
                description="Fires when one or more file attachments are present in the email.",
                false_positive_context="Standard business documents, PDFs, presentations, and images sent during regular legitimate workflows.",
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        attachments = parsed_context.get("attachments") or []
        matched = len(attachments) > 0
        names = [att.get("filename") if isinstance(att, dict) else str(att) for att in attachments]
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=f"Detected {len(attachments)} attachments." if matched else "No attachments present.",
            evidence={
                "attachment_count": len(attachments),
                "attachment_names": names,
            },
            rule_version=self.definition.version,
        )


class DangerousExtensionRule(BaseRule):
    """RULE-ATTACH-002: Suspicious Executable / Script Extension."""

    DANGEROUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".hta", ".docm", ".xlsm",
        ".pif", ".application", ".gadget", ".msi", ".msp", ".com", ".cpl", ".jar", ".wsf", ".wsh"
    }

    def __init__(self):
        super().__init__(
            RuleDefinition(
                rule_id="RULE-ATTACH-002",
                name="Suspicious Executable or Script Extension",
                category=RuleCategory.ATTACHMENT,
                severity=RuleSeverity.HIGH,
                default_score=30,
                description="Fires when an attachment has an executable, script, or macro-enabled extension.",
                false_positive_context="Software developers sharing deployment scripts, patches, or macro-enabled administrative spreadsheets internally.",
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        attachments = parsed_context.get("attachments") or []
        dangerous_attachments = []

        for att in attachments:
            fname = att.get("filename", "") if isinstance(att, dict) else str(att)
            if not fname:
                continue
            ext = os.path.splitext(fname)[1].lower()
            if ext in self.DANGEROUS_EXTENSIONS:
                dangerous_attachments.append({
                    "filename": fname,
                    "extension": ext,
                    "sha256": att.get("sha256") if isinstance(att, dict) else None,
                })

        matched = len(dangerous_attachments) > 0
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=f"Found {len(dangerous_attachments)} executable or script attachments." if matched else "No dangerous executable extensions found.",
            evidence={
                "dangerous_count": len(dangerous_attachments),
                "dangerous_attachments": dangerous_attachments,
            },
            rule_version=self.definition.version,
        )


class DoubleExtensionRule(BaseRule):
    """RULE-ATTACH-003: Double Extension Attack Pattern."""

    HIDDEN_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1", ".hta", ".jar", ".pif", ".cpl"
    }

    def __init__(self):
        super().__init__(
            RuleDefinition(
                rule_id="RULE-ATTACH-003",
                name="Double Extension Attack Pattern",
                category=RuleCategory.ATTACHMENT,
                severity=RuleSeverity.HIGH,
                default_score=35,
                description="Fires when an attachment filename contains multiple extensions ending with an executable type (e.g., 'invoice.pdf.exe').",
                false_positive_context="Extremely rare; occasionally seen in backup archives with multiple dots like 'data.tar.gz' or versioned artifacts, but those do not end in executable extensions.",
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        attachments = parsed_context.get("attachments") or []
        double_ext_matches = []

        for att in attachments:
            fname = att.get("filename", "") if isinstance(att, dict) else str(att)
            if not fname:
                continue

            parts = fname.split(".")
            if len(parts) >= 3:
                last_ext = f".{parts[-1].lower()}"
                if last_ext in self.HIDDEN_EXTENSIONS:
                    decoy_ext = f".{parts[-2].lower()}"
                    double_ext_matches.append({
                        "filename": fname,
                        "decoy_extension": decoy_ext,
                        "actual_extension": last_ext,
                    })

        matched = len(double_ext_matches) > 0
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=f"Found {len(double_ext_matches)} attachments using deceptive double extensions." if matched else "No double extension camouflage detected.",
            evidence={
                "double_ext_count": len(double_ext_matches),
                "matches": double_ext_matches,
            },
            rule_version=self.definition.version,
        )


class FinancialAttachmentNameRule(BaseRule):
    """RULE-ATTACH-004: Suspicious Financial / Urgency Filename Pattern."""

    FINANCIAL_PATTERNS = [
        r"(?:^|[\W_])invoice(?:[\W_]|$)",
        r"(?:^|[\W_])payment(?:[\W_]|$)",
        r"(?:^|[\W_])receipt(?:[\W_]|$)",
        r"(?:^|[\W_])remittance(?:[\W_]|$)",
        r"(?:^|[\W_])wire(?:[\W_]|$)",
        r"(?:^|[\W_])bill(?:[\W_]|$)",
        r"(?:^|[\W_])statement(?:[\W_]|$)",
        r"(?:^|[\W_])order(?:[\W_]|$)",
        r"(?:^|[\W_])po[_-]?\d+(?:[\W_]|$)",
        r"(?:^|[\W_])refund(?:[\W_]|$)",
    ]


    def __init__(self):
        super().__init__(
            RuleDefinition(
                rule_id="RULE-ATTACH-004",
                name="Suspicious Financial or Urgency Filename Pattern",
                category=RuleCategory.ATTACHMENT,
                severity=RuleSeverity.MEDIUM,
                default_score=15,
                description="Fires when an attachment filename matches common financial lures such as 'invoice', 'payment', 'receipt', 'wire', or 'remittance'.",
                false_positive_context="Routine accounting workflows, vendor billing, legitimate customer invoices, and SaaS expense receipts.",
            )
        )

    def evaluate(self, parsed_context: Dict[str, Any]) -> RuleResult:
        attachments = parsed_context.get("attachments") or []
        matched_filenames = []

        combined_regex = re.compile("|".join(self.FINANCIAL_PATTERNS), re.IGNORECASE)

        for att in attachments:
            fname = att.get("filename", "") if isinstance(att, dict) else str(att)
            if not fname:
                continue
            if combined_regex.search(fname):
                matched_filenames.append(fname)

        matched = len(matched_filenames) > 0
        return RuleResult(
            rule_id=self.definition.rule_id,
            rule_name=self.definition.name,
            category=self.definition.category,
            severity=self.definition.severity,
            score=self.definition.default_score if matched else 0,
            matched=matched,
            message=f"Found {len(matched_filenames)} attachments with financial lure names." if matched else "No financial lure attachment filenames detected.",
            evidence={
                "financial_attachment_count": len(matched_filenames),
                "matched_filenames": matched_filenames,
            },
            rule_version=self.definition.version,
        )


# Aliases for flexibility
RuleAttach001 = AttachmentPresentRule
RuleAttach002 = DangerousExtensionRule
RuleAttach003 = DoubleExtensionRule
RuleAttach004 = FinancialAttachmentNameRule

__all__ = [
    "AttachmentPresentRule",
    "DangerousExtensionRule",
    "DoubleExtensionRule",
    "FinancialAttachmentNameRule",
    "RuleAttach001",
    "RuleAttach002",
    "RuleAttach003",
    "RuleAttach004",
]

