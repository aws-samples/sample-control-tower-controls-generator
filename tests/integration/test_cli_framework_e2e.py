"""End-to-end integration tests for framework-based filtering in the CLI.

Exercises the full pipeline (input file -> catalog -> mapping -> framework
filter -> severity/behavior filters -> report) through
``click.testing.CliRunner``, mirroring ``test_cli_e2e.py``.

The CLI is always invoked in NON-INTERACTIVE mode (``--no-interactive`` plus
``--input-file``) so the interactive ``click.prompt`` path is never hit, and
report content is written to a temp ``--output-file`` that the tests parse with
``json.loads`` for deterministic assertions (stderr never contaminates it).

Retriever functions are patched in the ``control_tower_controls_generator.cli``
namespace (``retrieve_control_catalog`` returns Control objects,
``retrieve_control_mappings`` returns a framework-association index, and
``retrieve_enabled_controls`` returns ``[]``) because ``moto`` does not support
the ``controlcatalog`` service.
"""

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from control_tower_controls_generator.cli import main
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    FrameworkAssociation,
)


# --- Fixtures / helpers ---

# Control ARNs (kept short and stable for lookups in the mapping index).
ARN_ALPHA = "arn:aws:controlcatalog:::control/aaa"
ARN_BETA = "arn:aws:controlcatalog:::control/bbb"
ARN_GAMMA = "arn:aws:controlcatalog:::control/ccc"
ARN_DELTA = "arn:aws:controlcatalog:::control/ddd"


def _make_control(
    arn: str,
    name: str,
    behavior: str,
    severity: str,
    governed_resources: list[str],
) -> Control:
    """Build a Control object for tests."""
    return Control(
        arn=arn,
        name=name,
        description=f"Description for {name}",
        behavior=behavior,
        severity=severity,
        implementation=ControlImplementation(type="AWS::CloudFormation::Type::HOOK"),
        governed_resources=governed_resources,
    )


# Four controls, each governing a distinct resource type present in the input
# file so all four map. Spread across behaviors and severities to exercise the
# AND composition of the framework, severity, and behavior filters.
SAMPLE_CONTROLS = [
    _make_control(ARN_ALPHA, "Alpha Control", "PREVENTIVE", "HIGH", ["AWS::EC2::Instance"]),
    _make_control(ARN_BETA, "Beta Control", "DETECTIVE", "MEDIUM", ["AWS::S3::Bucket"]),
    _make_control(ARN_GAMMA, "Gamma Control", "PROACTIVE", "CRITICAL", ["AWS::Lambda::Function"]),
    _make_control(ARN_DELTA, "Delta Control", "DETECTIVE", "LOW", ["AWS::RDS::DBInstance"]),
]

# Framework-association index keyed by control ARN (what retrieve_control_mappings
# would return). Gamma is associated with BOTH frameworks (many-to-many); Delta
# is associated with neither of the requested frameworks.
SAMPLE_MAPPING_INDEX = {
    ARN_ALPHA: [FrameworkAssociation(name="PCI-DSS-v4.0", item="7.2.2")],
    ARN_BETA: [FrameworkAssociation(name="NIST-SP-800-53-r5", item="CM-5")],
    ARN_GAMMA: [
        FrameworkAssociation(name="PCI-DSS-v4.0", item="1.1.1"),
        FrameworkAssociation(name="NIST-SP-800-53-r5", item="AC-2"),
    ],
    ARN_DELTA: [FrameworkAssociation(name="CIS-v8.0", item="4.1")],
}

CLASSIC_CONTROL_KEYS = {
    "controlName",
    "controlArn",
    "behavior",
    "severity",
    "matchedResourceTypes",
    "accounts",
    "enablementStatus",
}


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def input_file(tmp_path):
    """A simple JSON-array input file covering every control's resource type."""
    content = json.dumps(
        [
            "AWS::EC2::Instance",
            "AWS::S3::Bucket",
            "AWS::Lambda::Function",
            "AWS::RDS::DBInstance",
        ]
    )
    path = tmp_path / "input.json"
    path.write_text(content)
    return str(path)


def _run_json(runner, tmp_path, input_file, extra_args):
    """Invoke the CLI non-interactively, writing JSON to a temp file.

    Returns (result, report_dict). ``report_dict`` is None when the run failed
    before producing output.
    """
    out_path = tmp_path / "report.json"
    result = runner.invoke(
        main,
        [
            "--no-interactive",
            "--input-file",
            input_file,
            "--output-file",
            str(out_path),
            *extra_args,
        ],
    )
    report = json.loads(out_path.read_text()) if out_path.exists() else None
    return result, report


def _by_name(report):
    """Index report controls by controlName for easy lookup."""
    return {c["controlName"]: c for c in report["controls"]}


# --- Opt-in: no --framework behaves exactly as today ---


@patch("control_tower_controls_generator.cli.retrieve_enabled_controls")
@patch("control_tower_controls_generator.cli.retrieve_control_mappings")
@patch("control_tower_controls_generator.cli.retrieve_control_catalog")
class TestFrameworkOptIn:
    """Without --framework the mappings API is never touched and no attribution appears."""

    def test_without_framework_mappings_never_retrieved(
        self, mock_catalog, mock_mappings, mock_enabled, runner, tmp_path, input_file
    ):
        """No --framework => retrieve_control_mappings not called."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_mappings.return_value = SAMPLE_MAPPING_INDEX
        mock_enabled.return_value = []

        result, report = _run_json(runner, tmp_path, input_file, [])

        assert result.exit_code == 0
        # Opt-in short-circuit: the ListControlMappings path is never entered.
        mock_mappings.assert_not_called()
        # All four controls map and are recommended, exactly as today.
        assert report["summary"]["totalRecommended"] == 4

    def test_without_framework_output_has_no_attribution(
        self, mock_catalog, mock_mappings, mock_enabled, runner, tmp_path, input_file
    ):
        """Without a framework filter, JSON omits the frameworks key."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_mappings.return_value = SAMPLE_MAPPING_INDEX
        mock_enabled.return_value = []

        result, report = _run_json(runner, tmp_path, input_file, [])

        assert result.exit_code == 0
        assert report["controls"], "expected recommended controls"
        for control in report["controls"]:
            # Output matches today's behavior: classic keys only, no attribution.
            assert "frameworks" not in control
            assert set(control.keys()) == CLASSIC_CONTROL_KEYS


# --- Framework filtering narrows the report and adds attribution ---


@patch("control_tower_controls_generator.cli.retrieve_enabled_controls")
@patch("control_tower_controls_generator.cli.retrieve_control_mappings")
@patch("control_tower_controls_generator.cli.retrieve_control_catalog")
class TestFrameworkFiltering:
    """--framework retains only associated controls and annotates them."""

    def test_single_framework_narrows_and_attributes(
        self, mock_catalog, mock_mappings, mock_enabled, runner, tmp_path, input_file
    ):
        """PCI-DSS-v4.0 keeps only its controls, with attribution."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_mappings.return_value = SAMPLE_MAPPING_INDEX
        mock_enabled.return_value = []

        result, report = _run_json(
            runner, tmp_path, input_file, ["--framework", "PCI-DSS-v4.0"]
        )

        assert result.exit_code == 0
        # Framework requested => mappings are retrieved exactly once.
        mock_mappings.assert_called_once()

        # Only Alpha (PCI) and Gamma (PCI + NIST) are associated with PCI-DSS-v4.0.
        controls = _by_name(report)
        assert set(controls) == {"Alpha Control", "Gamma Control"}
        assert report["summary"]["totalRecommended"] == 2

        # Attribution present on every retained control.
        assert controls["Alpha Control"]["frameworks"] == [
            {"name": "PCI-DSS-v4.0", "item": "7.2.2"}
        ]
        # Gamma keeps only the matched (PCI) association, not its NIST one.
        assert controls["Gamma Control"]["frameworks"] == [
            {"name": "PCI-DSS-v4.0", "item": "1.1.1"}
        ]

    def test_multiple_frameworks_apply_any_of(
        self, mock_catalog, mock_mappings, mock_enabled, runner, tmp_path, input_file
    ):
        """A control associated with EITHER requested framework is kept."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_mappings.return_value = SAMPLE_MAPPING_INDEX
        mock_enabled.return_value = []

        result, report = _run_json(
            runner,
            tmp_path,
            input_file,
            ["--framework", "PCI-DSS-v4.0,NIST-SP-800-53-r5"],
        )

        assert result.exit_code == 0
        controls = _by_name(report)
        # Alpha (PCI), Beta (NIST), Gamma (both) kept; Delta (CIS only) dropped.
        assert set(controls) == {"Alpha Control", "Beta Control", "Gamma Control"}
        assert report["summary"]["totalRecommended"] == 3
        assert "Delta Control" not in controls

        # Gamma matches both requested frameworks, so both associations attach.
        assert controls["Gamma Control"]["frameworks"] == [
            {"name": "PCI-DSS-v4.0", "item": "1.1.1"},
            {"name": "NIST-SP-800-53-r5", "item": "AC-2"},
        ]
        assert controls["Beta Control"]["frameworks"] == [
            {"name": "NIST-SP-800-53-r5", "item": "CM-5"}
        ]

    def test_framework_and_severity_apply_and(
        self, mock_catalog, mock_mappings, mock_enabled, runner, tmp_path, input_file
    ):
        """Framework AND severity intersect."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_mappings.return_value = SAMPLE_MAPPING_INDEX
        mock_enabled.return_value = []

        # Framework {Alpha, Beta, Gamma} intersect severity>=CRITICAL {Gamma} => {Gamma}.
        result, report = _run_json(
            runner,
            tmp_path,
            input_file,
            [
                "--framework",
                "PCI-DSS-v4.0,NIST-SP-800-53-r5",
                "--severity-filter",
                "CRITICAL",
            ],
        )

        assert result.exit_code == 0
        controls = _by_name(report)
        assert set(controls) == {"Gamma Control"}
        assert report["summary"]["totalRecommended"] == 1
        assert controls["Gamma Control"]["severity"] == "CRITICAL"
        # Attribution still present under combined filtering.
        assert controls["Gamma Control"]["frameworks"] == [
            {"name": "PCI-DSS-v4.0", "item": "1.1.1"},
            {"name": "NIST-SP-800-53-r5", "item": "AC-2"},
        ]

    def test_framework_severity_and_behavior_apply_and(
        self, mock_catalog, mock_mappings, mock_enabled, runner, tmp_path, input_file
    ):
        """Framework AND severity AND behavior all intersect."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_mappings.return_value = SAMPLE_MAPPING_INDEX
        mock_enabled.return_value = []

        # Framework {Alpha, Beta, Gamma}
        #   intersect severity>=HIGH {Alpha(HIGH), Gamma(CRITICAL)}
        #   intersect behavior PREVENTIVE {Alpha} => {Alpha}.
        result, report = _run_json(
            runner,
            tmp_path,
            input_file,
            [
                "--framework",
                "PCI-DSS-v4.0,NIST-SP-800-53-r5",
                "--severity-filter",
                "HIGH",
                "--behavior-filter",
                "PREVENTIVE",
            ],
        )

        assert result.exit_code == 0
        controls = _by_name(report)
        assert set(controls) == {"Alpha Control"}
        assert report["summary"]["totalRecommended"] == 1
        assert controls["Alpha Control"]["severity"] == "HIGH"
        assert controls["Alpha Control"]["behavior"] == "PREVENTIVE"
        assert controls["Alpha Control"]["frameworks"] == [
            {"name": "PCI-DSS-v4.0", "item": "7.2.2"}
        ]
