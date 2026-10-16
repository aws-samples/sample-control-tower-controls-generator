"""Unit tests for framework attribution and the no-match message in the report generator.

Covers the framework filter:
- Framework-specific empty message when zero controls remain.
- JSON report shape with and without framework attribution.
- Markdown report shape with and without framework attribution.

These are plain example-based pytest tests (no Hypothesis).
"""

import json

from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    EnabledControl,
    FrameworkAssociation,
    MappedControl,
)
from control_tower_controls_generator.report_generator import generate_report


# The exact set of JSON keys emitted per control before the framework feature.
ORIGINAL_CONTROL_KEYS = {
    "controlName",
    "controlArn",
    "behavior",
    "severity",
    "matchedResourceTypes",
    "accounts",
    "enablementStatus",
}

# The Markdown table header rendered when framework attribution is absent
# (identical to the pre-framework-filter output).
HEADER_WITHOUT_FRAMEWORKS = (
    "| Control Name | ARN | Behavior | Severity | Matched Resource Types "
    "| Accounts | Status |"
)
# The Markdown table header rendered when framework attribution is present.
HEADER_WITH_FRAMEWORKS = (
    "| Control Name | ARN | Behavior | Severity | Matched Resource Types "
    "| Accounts | Status | Frameworks |"
)


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
    associations: list[FrameworkAssociation] | None = None,
    **control_kwargs,
) -> MappedControl:
    """Build a MappedControl carrying the given framework associations."""
    return MappedControl(
        control=_make_control(**control_kwargs),
        matched_resource_types=["AWS::EC2::Instance"],
        framework_associations=list(associations) if associations else [],
    )


class TestNoMatchMessage:
    """Empty-result report uses the caller-supplied no-match message."""

    def test_json_uses_framework_specific_message(self):
        output = generate_report(
            [],
            enabled_controls=[],
            include_framework_attribution=True,
            no_match_message="No controls matched the requested frameworks",
        )

        data = json.loads(output)
        assert data["message"] == "No controls matched the requested frameworks"
        assert data["controls"] == []
        assert data["summary"]["totalRecommended"] == 0

    def test_markdown_body_contains_framework_specific_message(self):
        output = generate_report(
            [],
            enabled_controls=[],
            output_format="markdown",
            include_framework_attribution=True,
            no_match_message="No controls matched the requested frameworks",
        )

        assert "No controls matched the requested frameworks" in output

    def test_json_defaults_to_generic_message_when_not_provided(self):
        output = generate_report([], enabled_controls=[])

        data = json.loads(output)
        assert data["message"] == "No matching controls found"

    def test_markdown_defaults_to_generic_message_when_not_provided(self):
        output = generate_report([], enabled_controls=[], output_format="markdown")

        assert "No matching controls found" in output


class TestJsonAttribution:
    """JSON report shape with and without framework attribution."""

    def test_frameworks_list_present_with_multiple_associations(self):
        associations = [
            FrameworkAssociation(name="PCI-DSS-v4.0", item="7.2.2"),
            FrameworkAssociation(name="NIST-SP-800-53-r5", item="CM-5"),
        ]
        mapped = _make_mapped_control(associations=associations)

        output = generate_report(
            [mapped],
            enabled_controls=[],
            include_framework_attribution=True,
        )

        data = json.loads(output)
        control = data["controls"][0]
        assert control["frameworks"] == [
            {"name": "PCI-DSS-v4.0", "item": "7.2.2"},
            {"name": "NIST-SP-800-53-r5", "item": "CM-5"},
        ]

    def test_frameworks_list_present_with_single_association(self):
        mapped = _make_mapped_control(
            associations=[FrameworkAssociation(name="PCI-DSS-v4.0", item="7.2.2")]
        )

        output = generate_report(
            [mapped],
            enabled_controls=[],
            include_framework_attribution=True,
        )

        data = json.loads(output)
        control = data["controls"][0]
        assert control["frameworks"] == [{"name": "PCI-DSS-v4.0", "item": "7.2.2"}]

    def test_no_frameworks_key_when_attribution_disabled(self):
        # Even though the mapped control carries associations, disabling
        # attribution must omit the frameworks key entirely.
        mapped = _make_mapped_control(
            associations=[FrameworkAssociation(name="PCI-DSS-v4.0", item="7.2.2")]
        )

        output = generate_report(
            [mapped],
            enabled_controls=[],
            include_framework_attribution=False,
        )

        data = json.loads(output)
        control = data["controls"][0]
        assert "frameworks" not in control
        assert set(control.keys()) == ORIGINAL_CONTROL_KEYS

    def test_attribution_disabled_by_default(self):
        mapped = _make_mapped_control(
            associations=[FrameworkAssociation(name="PCI-DSS-v4.0", item="7.2.2")]
        )

        output = generate_report([mapped], enabled_controls=[])

        data = json.loads(output)
        control = data["controls"][0]
        assert "frameworks" not in control
        assert set(control.keys()) == ORIGINAL_CONTROL_KEYS


class TestMarkdownAttribution:
    """Markdown report shape with and without framework attribution."""

    def test_frameworks_column_header_present_with_attribution(self):
        mapped = _make_mapped_control(
            associations=[FrameworkAssociation(name="PCI-DSS-v4.0", item="7.2.2")]
        )

        output = generate_report(
            [mapped],
            enabled_controls=[],
            output_format="markdown",
            include_framework_attribution=True,
        )

        assert HEADER_WITH_FRAMEWORKS in output.split("\n")

    def test_associations_rendered_as_name_item_joined_by_br(self):
        associations = [
            FrameworkAssociation(name="PCI-DSS-v4.0", item="7.2.2"),
            FrameworkAssociation(name="NIST-SP-800-53-r5", item="CM-5"),
        ]
        mapped = _make_mapped_control(associations=associations)

        output = generate_report(
            [mapped],
            enabled_controls=[],
            output_format="markdown",
            include_framework_attribution=True,
        )

        assert "PCI-DSS-v4.0: 7.2.2<br/>NIST-SP-800-53-r5: CM-5" in output

    def test_no_frameworks_column_without_attribution(self):
        mapped = _make_mapped_control(
            associations=[FrameworkAssociation(name="PCI-DSS-v4.0", item="7.2.2")]
        )

        output = generate_report(
            [mapped],
            enabled_controls=[],
            output_format="markdown",
            include_framework_attribution=False,
        )

        lines = output.split("\n")
        assert HEADER_WITHOUT_FRAMEWORKS in lines
        assert "Frameworks" not in output

    def test_markdown_header_identical_to_today_by_default(self):
        mapped = _make_mapped_control(
            associations=[FrameworkAssociation(name="PCI-DSS-v4.0", item="7.2.2")]
        )

        output = generate_report(
            [mapped],
            enabled_controls=[],
            output_format="markdown",
        )

        lines = output.split("\n")
        assert HEADER_WITHOUT_FRAMEWORKS in lines
        assert "Frameworks" not in output


def test_enabled_control_marks_status_with_attribution():
    """Attribution does not disturb enablement status computation."""
    mapped = _make_mapped_control(
        associations=[FrameworkAssociation(name="PCI-DSS-v4.0", item="7.2.2")]
    )

    output = generate_report(
        [mapped],
        enabled_controls=[EnabledControl(control_arn=mapped.control.arn)],
        include_framework_attribution=True,
    )

    data = json.loads(output)
    control = data["controls"][0]
    assert control["enablementStatus"] == "already enabled"
    assert control["frameworks"] == [{"name": "PCI-DSS-v4.0", "item": "7.2.2"}]
