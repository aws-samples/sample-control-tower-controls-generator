"""Unit tests for the core report generator behavior.

Covers ``generate_report`` in ``control_tower_controls_generator.report_generator``:
JSON and Markdown structure, the empty-result message, per-account attribution
(present and omitted), alphabetical ordering, enablement status, and summary
counts. Markdown escaping and framework attribution are covered separately in
``test_report_generator_escaping.py`` and ``test_report_generator_frameworks.py``.

"""

import json

import pytest

from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    EnabledControl,
    MappedControl,
)
from control_tower_controls_generator.report_generator import generate_report


def _make_mapped(
    name: str,
    resource_types: list[str],
    behavior: str = "PREVENTIVE",
    severity: str = "HIGH",
) -> MappedControl:
    """Build a MappedControl with an ARN derived from its name."""
    return MappedControl(
        control=Control(
            arn=f"arn:aws:controlcatalog:::control/{name.lower()}",
            name=name,
            description="desc",
            behavior=behavior,
            severity=severity,
            implementation=ControlImplementation(type="SERVICE_CONTROL_POLICY"),
            governed_resources=list(resource_types),
        ),
        matched_resource_types=list(resource_types),
    )


def _arn(name: str) -> str:
    return f"arn:aws:controlcatalog:::control/{name.lower()}"


@pytest.fixture
def controls() -> list[MappedControl]:
    """Three controls deliberately supplied out of alphabetical order."""
    return [
        _make_mapped("Charlie", ["AWS::S3::Bucket"], "DETECTIVE", "MEDIUM"),
        _make_mapped("Alpha", ["AWS::EC2::Instance"], "PREVENTIVE", "CRITICAL"),
        _make_mapped(
            "Bravo", ["AWS::S3::Bucket", "AWS::EC2::Instance"], "PROACTIVE", "LOW"
        ),
    ]


@pytest.fixture
def account_mapping() -> dict[str, list[str]]:
    return {
        "AWS::S3::Bucket": ["222222222222", "111111111111"],
        "AWS::EC2::Instance": ["333333333333", "111111111111"],
    }


def _json(mapped, enabled=None, account_mapping=None) -> dict:
    return json.loads(
        generate_report(mapped, enabled or [], account_mapping, output_format="json")
    )


def _markdown(mapped, enabled=None, account_mapping=None) -> str:
    return generate_report(
        mapped, enabled or [], account_mapping, output_format="markdown"
    )


def _table_rows(markdown: str) -> list[str]:
    """Return the control data rows (excluding header and separator)."""
    rows = [line for line in markdown.splitlines() if line.startswith("| ")]
    return rows[1:]


class TestJsonOutputStructure:
    """JSON is the default format with camelCase keys."""

    def test_top_level_keys(self, controls):
        result = _json(controls)

        assert set(result) == {"summary", "controls", "message"}
        assert set(result["summary"]) == {"totalRecommended", "alreadyEnabled", "gaps"}
        assert result["message"] is None

    def test_control_entry_fields(self, controls):
        entry = _json(controls)["controls"][0]

        assert entry == {
            "controlName": "Alpha",
            "controlArn": _arn("Alpha"),
            "behavior": "PREVENTIVE",
            "severity": "CRITICAL",
            "matchedResourceTypes": ["AWS::EC2::Instance"],
            "accounts": None,
            "enablementStatus": "not enabled",
        }

    def test_matched_resource_types_are_preserved(self, controls):
        by_name = {c["controlName"]: c for c in _json(controls)["controls"]}

        assert by_name["Bravo"]["matchedResourceTypes"] == [
            "AWS::S3::Bucket",
            "AWS::EC2::Instance",
        ]

    def test_default_format_is_json(self, controls):
        default = generate_report(controls, [])
        explicit = generate_report(controls, [], None, output_format="json")

        assert default == explicit
        assert "controls" in json.loads(default)

    def test_output_is_indented(self, controls):
        output = generate_report(controls, [], output_format="json")

        assert output == json.dumps(json.loads(output), indent=2)


class TestMarkdownOutputStructure:
    """Markdown has a title, summary section, and controls table."""

    def test_sections_and_summary(self, controls):
        output = _markdown(controls)
        lines = output.splitlines()

        assert lines[0] == "# Control Tower Controls Report"
        assert "## Summary" in lines
        assert "- **Total Recommended**: 3" in lines
        assert "- **Already Enabled**: 0" in lines
        assert "- **Gaps**: 3" in lines
        assert "## Controls" in lines
        assert lines.index("## Summary") < lines.index("## Controls")

    def test_table_header_and_separator(self, controls):
        lines = _markdown(controls).splitlines()
        header_index = lines.index(
            "| Control Name | ARN | Behavior | Severity "
            "| Matched Resource Types | Accounts | Status |"
        )

        assert lines[header_index + 1] == "|---|---|---|---|---|---|---|"

    def test_one_row_per_control(self, controls):
        assert len(_table_rows(_markdown(controls))) == len(controls)

    def test_row_contents(self, controls):
        rows = _table_rows(_markdown(controls))

        assert rows[1] == (
            f"| Bravo | {_arn('Bravo')} | PROACTIVE | LOW "
            "| AWS::S3::Bucket, AWS::EC2::Instance | N/A | not enabled |"
        )

    def test_markdown_is_not_json(self, controls):
        with pytest.raises(json.JSONDecodeError):
            json.loads(_markdown(controls))


class TestEmptyControls:
    """No matches yields zero entries and a message."""

    def test_json_has_zero_entries_and_message(self):
        result = _json([])

        assert result["controls"] == []
        assert result["summary"] == {
            "totalRecommended": 0,
            "alreadyEnabled": 0,
            "gaps": 0,
        }
        assert result["message"] == "No matching controls found"

    def test_markdown_has_message_and_no_table(self):
        output = _markdown([])

        assert "No matching controls found" in output
        assert "- **Total Recommended**: 0" in output
        assert "## Controls" not in output
        assert "| Control Name" not in output

    def test_enabled_controls_ignored_when_nothing_matches(self):
        result = _json([], enabled=[EnabledControl(control_arn=_arn("Alpha"))])

        assert result["summary"]["alreadyEnabled"] == 0
        assert result["controls"] == []


class TestAccountAttribution:
    """Accounts shown when available, omitted otherwise."""

    def test_accounts_are_union_of_matched_resource_types_sorted(
        self, controls, account_mapping
    ):
        by_name = {
            c["controlName"]: c
            for c in _json(controls, account_mapping=account_mapping)["controls"]
        }

        assert by_name["Alpha"]["accounts"] == ["111111111111", "333333333333"]
        assert by_name["Charlie"]["accounts"] == ["111111111111", "222222222222"]
        # Bravo spans both resource types; duplicate account appears once.
        assert by_name["Bravo"]["accounts"] == [
            "111111111111",
            "222222222222",
            "333333333333",
        ]

    def test_accounts_null_without_account_mapping(self, controls):
        for entry in _json(controls)["controls"]:
            assert entry["accounts"] is None

    def test_accounts_empty_when_resource_type_not_in_mapping(self, controls):
        mapping = {"AWS::Lambda::Function": ["444444444444"]}

        for entry in _json(controls, account_mapping=mapping)["controls"]:
            assert entry["accounts"] == []

    def test_markdown_lists_accounts(self, controls, account_mapping):
        rows = _table_rows(_markdown(controls, account_mapping=account_mapping))

        assert "| 111111111111, 333333333333 |" in rows[0]

    def test_markdown_shows_na_without_account_mapping(self, controls):
        for row in _table_rows(_markdown(controls)):
            assert "| N/A |" in row


class TestAlphabeticalOrdering:
    """Controls are ordered alphabetically by name."""

    def test_json_controls_sorted_by_name(self, controls):
        names = [c["controlName"] for c in _json(controls)["controls"]]

        assert names == ["Alpha", "Bravo", "Charlie"]

    def test_markdown_rows_sorted_by_name(self, controls):
        rows = _table_rows(_markdown(controls))

        assert [row.split(" | ")[0].lstrip("| ") for row in rows] == [
            "Alpha",
            "Bravo",
            "Charlie",
        ]

    def test_input_list_is_not_mutated(self, controls):
        original = [mc.control.name for mc in controls]

        generate_report(controls, [])

        assert [mc.control.name for mc in controls] == original


class TestEnablementStatusAndSummary:
    """Summary counts and enablement status per control."""

    def test_all_not_enabled_without_enabled_controls(self, controls):
        result = _json(controls)

        assert {c["enablementStatus"] for c in result["controls"]} == {"not enabled"}
        assert result["summary"] == {
            "totalRecommended": 3,
            "alreadyEnabled": 0,
            "gaps": 3,
        }

    def test_enabled_controls_marked_already_enabled(self, controls):
        enabled = [
            EnabledControl(control_arn=_arn("Bravo")),
            EnabledControl(control_arn="arn:aws:controlcatalog:::control/unrelated"),
        ]
        result = _json(controls, enabled=enabled)
        status = {c["controlName"]: c["enablementStatus"] for c in result["controls"]}

        assert status == {
            "Alpha": "not enabled",
            "Bravo": "already enabled",
            "Charlie": "not enabled",
        }
        # The unrelated enabled control does not count toward the summary.
        assert result["summary"] == {
            "totalRecommended": 3,
            "alreadyEnabled": 1,
            "gaps": 2,
        }

    def test_all_enabled_leaves_no_gaps(self, controls):
        enabled = [EnabledControl(control_arn=mc.control.arn) for mc in controls]

        assert _json(controls, enabled=enabled)["summary"] == {
            "totalRecommended": 3,
            "alreadyEnabled": 3,
            "gaps": 0,
        }

    def test_markdown_reflects_status_and_summary(self, controls):
        enabled = [EnabledControl(control_arn=_arn("Alpha"))]
        output = _markdown(controls, enabled=enabled)
        rows = _table_rows(output)

        assert "- **Already Enabled**: 1" in output
        assert "- **Gaps**: 2" in output
        assert rows[0].endswith("| already enabled |")
        assert rows[1].endswith("| not enabled |")
