"""Unit tests for Layer 2 sink-level Markdown cell escaping.

These tests exercise the
Markdown renderer's escaping of every externally-sourced value and pin the exact
crafted inputs so the escaping is proven correct and guarded against regression.

Cases:
- HTML injection: an ``<img ... onerror=...>`` payload in a rendered
  field emits no raw ``<``/``>`` (only their ``html.escape`` entity form).
- Pipe forgery: a ``|`` in a field cannot forge extra columns; the
  count of unescaped ``|`` delimiters matches a clean row.
- Newline injection: a ``\r``/``\n`` in a field renders as exactly one
  line (no forged extra rows).
- Field coverage: control name, ARN, a resource type, an account, and a
  framework name/item are each escaped in turn; the ``<br/>`` separator between
  framework associations survives un-escaped.
- Preservation: an all-safe report renders byte-for-byte to the expected
  pre-remediation string; the Accounts cell reads ``"N/A"`` with no account data.
- Character-level rules for ``_escape_markdown_cell`` directly.

These are plain example-based pytest tests (no Hypothesis).
"""

from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    EnabledControl,
    FrameworkAssociation,
    MappedControl,
)
from control_tower_controls_generator.report_generator import (
    _escape_markdown_cell,
    generate_report,
)


# --- builders ----------------------------------------------------------------

def _make_control(
    arn: str = "arn:aws:controlcatalog:::control/abc123",
    name: str = "Example Control",
    behavior: str = "PREVENTIVE",
    severity: str = "HIGH",
) -> Control:
    """Build a minimal Control for report generation."""
    return Control(
        arn=arn,
        name=name,
        description="An example control.",
        behavior=behavior,
        severity=severity,
        implementation=ControlImplementation(type="SERVICE_CONTROL_POLICY"),
        governed_resources=["AWS::EC2::Instance"],
    )


def _make_mapped_control(
    matched_resource_types: list[str] | None = None,
    associations: list[FrameworkAssociation] | None = None,
    **control_kwargs,
) -> MappedControl:
    """Build a MappedControl with the given resource types and associations."""
    return MappedControl(
        control=_make_control(**control_kwargs),
        matched_resource_types=(
            list(matched_resource_types)
            if matched_resource_types is not None
            else ["AWS::EC2::Instance"]
        ),
        framework_associations=list(associations) if associations else [],
    )


def _render(
    mapped: MappedControl,
    account_mapping: dict[str, list[str]] | None = None,
    include_framework_attribution: bool = False,
    enabled_controls: list[EnabledControl] | None = None,
) -> str:
    """Render a single-control report as Markdown."""
    return generate_report(
        [mapped],
        enabled_controls=enabled_controls or [],
        account_mapping=account_mapping,
        output_format="markdown",
        include_framework_attribution=include_framework_attribution,
    )


# --- table-parsing helpers ---------------------------------------------------

def _table_body_lines(output: str) -> list[str]:
    """Return the rendered data rows: every line after the separator row, with
    trailing blank lines removed. A forged extra row would appear here as an
    extra element, so ``len(...)`` is the "one line per entry" check."""
    lines = output.split("\n")
    sep_idx = next(i for i, line in enumerate(lines) if line.startswith("|---"))
    body = lines[sep_idx + 1:]
    while body and body[-1] == "":
        body.pop()
    return body


def _count_unescaped_pipes(line: str) -> int:
    """Count ``|`` characters that are NOT immediately preceded by a backslash.

    The renderer escapes a data ``|`` as ``\\|``, so only the structural column
    delimiters remain unescaped. A payload that forged an extra column would add
    an unescaped ``|`` here.
    """
    return sum(
        1
        for i, ch in enumerate(line)
        if ch == "|" and (i == 0 or line[i - 1] != "\\")
    )


# --- crafted input: HTML injection -------------------------------

class TestHtmlInjection:
    """The HTML-injection payload is neutralized to its entity form."""

    PAYLOAD = "<img src=x onerror=alert(document.domain)>"
    ESCAPED = "&lt;img src=x onerror=alert(document.domain)&gt;"

    def test_html_payload_in_account_is_escaped(self):
        mapped = _make_mapped_control(matched_resource_types=["AWS::EC2::Instance"])
        output = _render(
            mapped, account_mapping={"AWS::EC2::Instance": [self.PAYLOAD]}
        )

        assert self.ESCAPED in output
        assert self.PAYLOAD not in output
        # This report has no Frameworks column, so nothing legitimately emits
        # angle brackets: any raw < or > would be injected markup.
        assert "<" not in output
        assert ">" not in output

    def test_html_payload_in_control_name_is_escaped(self):
        mapped = _make_mapped_control(name=self.PAYLOAD)
        output = _render(mapped)

        assert self.ESCAPED in output
        assert self.PAYLOAD not in output
        assert "<" not in output
        assert ">" not in output


# --- crafted input: pipe forgery ---------------------------------

class TestPipeForgery:
    """A pipe in a field cannot forge additional table columns."""

    def test_pipe_in_account_does_not_forge_columns(self):
        clean = _make_mapped_control(matched_resource_types=["AWS::EC2::Instance"])
        clean_out = _render(
            clean, account_mapping={"AWS::EC2::Instance": ["123456789012"]}
        )
        clean_body = _table_body_lines(clean_out)
        assert len(clean_body) == 1
        clean_delimiters = _count_unescaped_pipes(clean_body[0])

        forged = _make_mapped_control(matched_resource_types=["AWS::EC2::Instance"])
        forged_out = _render(
            forged, account_mapping={"AWS::EC2::Instance": ["12|34|56"]}
        )
        forged_body = _table_body_lines(forged_out)
        assert len(forged_body) == 1
        forged_delimiters = _count_unescaped_pipes(forged_body[0])

        # No extra columns forged: same number of real delimiters as a clean row.
        assert forged_delimiters == clean_delimiters
        # The payload's pipes are preserved but escaped, not dropped.
        assert "12\\|34\\|56" in forged_out


# --- crafted input: newline injection ----------------------------

class TestNewlineInjection:
    """A carriage return / line feed cannot forge an extra row."""

    def test_newline_in_account_stays_single_line(self):
        mapped = _make_mapped_control(matched_resource_types=["AWS::EC2::Instance"])
        output = _render(
            mapped, account_mapping={"AWS::EC2::Instance": ["12\r\n34\n56"]}
        )

        body = _table_body_lines(output)
        # Exactly one rendered line for the single entry.
        assert len(body) == 1
        # The CR/LF are removed, so the digits collapse contiguously onto that
        # one line. If a newline had survived, "3456" would spill to a next line.
        assert "123456" in body[0]


# --- field coverage ------------------------------------------------

class TestFieldCoverage:
    """Every externally-sourced field is routed through the escaper."""

    # A payload carrying both a structural char (|) and markup (< >).
    PAYLOAD = "PAY|LOAD<script>"
    ESCAPED = "PAY\\|LOAD&lt;script&gt;"

    def test_control_name_is_escaped(self):
        output = _render(_make_mapped_control(name=self.PAYLOAD))
        assert self.ESCAPED in output
        assert self.PAYLOAD not in output

    def test_control_arn_is_escaped(self):
        output = _render(_make_mapped_control(arn=self.PAYLOAD))
        assert self.ESCAPED in output
        assert self.PAYLOAD not in output

    def test_resource_type_is_escaped(self):
        output = _render(_make_mapped_control(matched_resource_types=[self.PAYLOAD]))
        assert self.ESCAPED in output
        assert self.PAYLOAD not in output

    def test_account_is_escaped(self):
        mapped = _make_mapped_control(matched_resource_types=["AWS::EC2::Instance"])
        output = _render(
            mapped, account_mapping={"AWS::EC2::Instance": [self.PAYLOAD]}
        )
        assert self.ESCAPED in output
        assert self.PAYLOAD not in output

    def test_framework_name_and_item_are_escaped(self):
        mapped = _make_mapped_control(
            associations=[FrameworkAssociation(name=self.PAYLOAD, item=self.PAYLOAD)]
        )
        output = _render(mapped, include_framework_attribution=True)
        # Rendered as "{name}: {item}", both escaped.
        assert f"{self.ESCAPED}: {self.ESCAPED}" in output
        assert self.PAYLOAD not in output

    def test_framework_br_separator_survives_unescaped(self):
        mapped = _make_mapped_control(
            associations=[
                FrameworkAssociation(name="PCI-DSS-v4.0", item="7.2.2"),
                FrameworkAssociation(name="NIST-SP-800-53-r5", item="CM-5"),
            ]
        )
        output = _render(mapped, include_framework_attribution=True)

        # The literal <br/> between associations is not passed through the
        # escaper, so the intended line break is preserved verbatim.
        assert "PCI-DSS-v4.0: 7.2.2<br/>NIST-SP-800-53-r5: CM-5" in output
        assert "&lt;br/&gt;" not in output


# --- preservation of legitimate output --------------------

# The exact Markdown a legitimate, all-safe report renders. Built explicitly so
# the test fails if escaping ever alters normal output.
EXPECTED_SAFE_MARKDOWN = "\n".join(
    [
        "# Control Tower Controls Report",
        "",
        "## Summary",
        "",
        "- **Total Recommended**: 1",
        "- **Already Enabled**: 0",
        "- **Gaps**: 1",
        "",
        "## Controls",
        "",
        "| Control Name | ARN | Behavior | Severity | Matched Resource Types "
        "| Accounts | Status |",
        "|---|---|---|---|---|---|---|",
        "| Example Control | arn:aws:controlcatalog:::control/abc123 | PREVENTIVE "
        "| HIGH | AWS::EC2::Instance | 123456789012, 234567890123 | not enabled |",
        "",
    ]
)


class TestPreservation:
    """Legitimate data renders exactly as it did before the remediation."""

    def test_all_safe_report_matches_pre_remediation_string(self):
        mapped = _make_mapped_control(
            name="Example Control",
            arn="arn:aws:controlcatalog:::control/abc123",
            matched_resource_types=["AWS::EC2::Instance"],
        )
        output = _render(
            mapped,
            account_mapping={
                "AWS::EC2::Instance": ["123456789012", "234567890123"]
            },
        )

        assert output == EXPECTED_SAFE_MARKDOWN

    def test_accounts_cell_is_na_without_account_data(self):
        mapped = _make_mapped_control(
            name="Example Control",
            arn="arn:aws:controlcatalog:::control/abc123",
            matched_resource_types=["AWS::EC2::Instance"],
        )
        output = _render(mapped, account_mapping=None)

        body = _table_body_lines(output)
        assert len(body) == 1
        assert body[0] == (
            "| Example Control | arn:aws:controlcatalog:::control/abc123 "
            "| PREVENTIVE | HIGH | AWS::EC2::Instance | N/A | not enabled |"
        )


# --- character-level rules for the escaper -----------

class TestEscapeMarkdownCellHelper:
    """Direct character-level assertions on ``_escape_markdown_cell``."""

    def test_pipe_is_backslash_escaped(self):
        assert _escape_markdown_cell("a|b") == "a\\|b"

    def test_angle_brackets_and_ampersand_use_html_entities(self):
        assert _escape_markdown_cell("<b>&") == "&lt;b&gt;&amp;"

    def test_carriage_return_and_line_feed_are_removed(self):
        assert _escape_markdown_cell("a\r\nb") == "ab"

    def test_safe_value_is_returned_unchanged(self):
        # No & < > | \r \n -> identity.
        assert _escape_markdown_cell("Example Control 123") == "Example Control 123"

    def test_quotes_are_preserved(self):
        # quote=False leaves single and double quotes untouched.
        assert _escape_markdown_cell("a\"b'c") == "a\"b'c"

    def test_combined_payload_applies_all_rules(self):
        assert _escape_markdown_cell("a|b<c>\nd") == "a\\|b&lt;c&gt;d"
