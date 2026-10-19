"""Report generator module for the Control Tower Controls Generator."""

import html
import json
from typing import Optional

from control_tower_controls_generator.models import (
    EnabledControl,
    MappedControl,
    Report,
    ReportEntry,
    ReportSummary,
)


def generate_report(
    mapped_controls: list[MappedControl],
    enabled_controls: list[EnabledControl],
    account_mapping: Optional[dict[str, list[str]]] = None,
    output_format: str = "json",
    include_framework_attribution: bool = False,
    no_match_message: str = "No matching controls found",
) -> str:
    """Generate the output report in the specified format (json or markdown).

    Args:
        mapped_controls: List of controls matched to resource types.
        enabled_controls: List of controls already enabled on the OU.
        account_mapping: Optional mapping of resource type to account IDs.
        output_format: Output format, either "json" or "markdown".
        include_framework_attribution: When True, each report entry carries the
            framework associations of its source control so that framework
            attribution is rendered. When False, attribution is omitted and the
            output is identical to the pre-framework-filter behavior.
        no_match_message: Message used in the empty-result report. Allows the
            caller to supply a framework-specific message.

    Returns:
        The formatted report as a string.
    """
    if not mapped_controls:
        report = Report(
            summary=ReportSummary(total_recommended=0, already_enabled=0, gaps=0),
            controls=[],
            message=no_match_message,
        )
        if output_format == "markdown":
            return _render_markdown(report)
        return _render_json(report)

    # Sort controls alphabetically by control name
    sorted_controls = sorted(mapped_controls, key=lambda mc: mc.control.name)

    # Build a set of enabled control ARNs for fast lookup
    enabled_arns: set[str] = {ec.control_arn for ec in enabled_controls}

    # Build report entries
    entries: list[ReportEntry] = []
    for mc in sorted_controls:
        # Determine enablement status
        enablement_status = (
            "already enabled" if mc.control.arn in enabled_arns else "not enabled"
        )

        # Determine accounts from account_mapping if available
        accounts: Optional[list[str]] = None
        if account_mapping is not None:
            account_set: set[str] = set()
            for rt in mc.matched_resource_types:
                if rt in account_mapping:
                    account_set.update(account_mapping[rt])
            accounts = sorted(account_set) if account_set else []

        entries.append(
            ReportEntry(
                control_name=mc.control.name,
                control_arn=mc.control.arn,
                behavior=mc.control.behavior,
                severity=mc.control.severity,
                matched_resource_types=mc.matched_resource_types,
                accounts=accounts,
                enablement_status=enablement_status,
                framework_associations=(
                    list(mc.framework_associations)
                    if include_framework_attribution
                    else None
                ),
            )
        )

    # Calculate summary
    already_enabled_count = sum(
        1 for e in entries if e.enablement_status == "already enabled"
    )
    total_recommended = len(entries)
    gaps = total_recommended - already_enabled_count

    report = Report(
        summary=ReportSummary(
            total_recommended=total_recommended,
            already_enabled=already_enabled_count,
            gaps=gaps,
        ),
        controls=entries,
        message=None,
    )

    if output_format == "markdown":
        return _render_markdown(report)
    return _render_json(report)


def _control_to_json(entry: ReportEntry) -> dict:
    """Serialize a single report entry to a JSON-ready dict.

    The ``frameworks`` key is added only when framework attribution is present
    (``framework_associations`` is not None). When attribution is absent the
    dict is identical to the pre-framework-filter output, key-for-key.
    """
    control_dict: dict = {
        "controlName": entry.control_name,
        "controlArn": entry.control_arn,
        "behavior": entry.behavior,
        "severity": entry.severity,
        "matchedResourceTypes": entry.matched_resource_types,
        "accounts": entry.accounts,
        "enablementStatus": entry.enablement_status,
    }
    if entry.framework_associations is not None:
        control_dict["frameworks"] = [
            {"name": assoc.name, "item": assoc.item}
            for assoc in entry.framework_associations
        ]
    return control_dict


def _render_json(report: Report) -> str:
    """Serialize the report to JSON with camelCase keys."""
    output = {
        "summary": {
            "totalRecommended": report.summary.total_recommended,
            "alreadyEnabled": report.summary.already_enabled,
            "gaps": report.summary.gaps,
        },
        "controls": [_control_to_json(entry) for entry in report.controls],
        "message": report.message,
    }
    return json.dumps(output, indent=2)


def _escape_markdown_cell(value: str) -> str:
    r"""Neutralize characters that break Markdown table cells or inject markup.

    Applied to every externally-sourced value before it is interpolated into a
    Markdown table cell. For a value containing none of the affected characters
    this is the identity function, so legitimate output is unchanged (identity
    on any string containing none of ``& < > | \r \n``).

    Order of operations (see design.md "Escaping order decision"; the transforms
    operate on disjoint character sets, so the order is fixed for readability):
      1. html.escape(value, quote=False)  -> escapes & < >
      2. replace "|" with "\|"            -> prevents column/row forgery
      3. remove "\r" and "\n"             -> keeps the cell on one line
    """
    escaped = html.escape(value, quote=False)
    escaped = escaped.replace("|", "\\|")
    escaped = escaped.replace("\r", "").replace("\n", "")
    return escaped


def _render_markdown(report: Report) -> str:
    """Render the report as Markdown with a summary section and table."""
    lines: list[str] = []

    lines.append("# Control Tower Controls Report")
    lines.append("")

    # Summary section
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Total Recommended**: {report.summary.total_recommended}")
    lines.append(f"- **Already Enabled**: {report.summary.already_enabled}")
    lines.append(f"- **Gaps**: {report.summary.gaps}")
    lines.append("")

    if report.message:
        lines.append(report.message)
        lines.append("")
        return "\n".join(lines)

    # Render the Frameworks column only when attribution is present. Since
    # attribution is all-or-nothing per report, this keeps the table identical
    # to the pre-framework-filter output when attribution is absent.
    show_frameworks = any(
        entry.framework_associations is not None for entry in report.controls
    )

    # Controls table
    lines.append("## Controls")
    lines.append("")
    if show_frameworks:
        lines.append(
            "| Control Name | ARN | Behavior | Severity | Matched Resource Types "
            "| Accounts | Status | Frameworks |"
        )
        lines.append("|---|---|---|---|---|---|---|---|")
    else:
        lines.append(
            "| Control Name | ARN | Behavior | Severity | Matched Resource Types | Accounts | Status |"
        )
        lines.append(
            "|---|---|---|---|---|---|---|"
        )

    for entry in report.controls:
        control_name = _escape_markdown_cell(entry.control_name)
        control_arn = _escape_markdown_cell(entry.control_arn)
        resource_types = ", ".join(
            _escape_markdown_cell(rt) for rt in entry.matched_resource_types
        )
        accounts = (
            ", ".join(_escape_markdown_cell(acct) for acct in entry.accounts)
            if entry.accounts
            else "N/A"
        )
        row = (
            f"| {control_name} | {control_arn} | {entry.behavior} "
            f"| {entry.severity} | {resource_types} | {accounts} | {entry.enablement_status} |"
        )
        if show_frameworks:
            # Escape name and item individually, THEN join with a literal <br/> so
            # the intentional separator is not itself escaped.
            frameworks = "<br/>".join(
                f"{_escape_markdown_cell(assoc.name)}: {_escape_markdown_cell(assoc.item)}"
                for assoc in (entry.framework_associations or [])
            )
            row += f" {frameworks} |"
        lines.append(row)

    lines.append("")
    return "\n".join(lines)
