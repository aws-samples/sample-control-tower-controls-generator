"""Integration tests for framework-filter warnings and error exit codes.

Exercises the CLI end-to-end (via ``click.testing.CliRunner``) for the paths that
are only reached when ``--framework`` is active:

- Unrecognized framework -> warning on stderr, zero matches, exit 0
- Mappings API failure -> exit 2
- Auth failure (RuntimeError whose __cause__ is a botocore ClientError) -> exit 3

The retriever functions are patched in the ``control_tower_controls_generator.cli``
namespace because ``moto`` does not support the ``controlcatalog`` service. All
invocations use ``--no-interactive`` and ``--input-file`` to avoid the interactive
prompt path.

Note: this project depends on click 8.4.x, where ``CliRunner`` captures stdout and
stderr separately (there is no ``mix_stderr`` parameter). ``result.stdout`` holds the
JSON report and ``result.stderr`` holds warnings/errors, so the two never interleave.
"""

import json
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError
from click.testing import CliRunner

from control_tower_controls_generator.cli import main
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    FrameworkAssociation,
)


# --- Fixtures / sample data ---


def _make_control(
    arn: str,
    name: str,
    behavior: str = "DETECTIVE",
    severity: str = "HIGH",
    governed_resources: list[str] | None = None,
) -> Control:
    """Helper to build a Control object for tests."""
    return Control(
        arn=arn,
        name=name,
        description=f"Description for {name}",
        behavior=behavior,
        severity=severity,
        implementation=ControlImplementation(type="AWS::CloudFormation::Type::HOOK"),
        governed_resources=governed_resources or [],
    )


ALPHA_ARN = "arn:aws:controlcatalog:::control/aaa"
BETA_ARN = "arn:aws:controlcatalog:::control/bbb"

SAMPLE_CONTROLS = [
    _make_control(
        arn=ALPHA_ARN,
        name="Alpha Control",
        behavior="PREVENTIVE",
        severity="HIGH",
        governed_resources=["AWS::EC2::Instance"],
    ),
    _make_control(
        arn=BETA_ARN,
        name="Beta Control",
        behavior="DETECTIVE",
        severity="MEDIUM",
        governed_resources=["AWS::S3::Bucket"],
    ),
]

# A framework the mappings index knows about, so a *different* requested name
# (e.g. BOGUS-FRAMEWORK) is unrecognized and matches zero controls.
KNOWN_FRAMEWORK = "PCI-DSS-v4.0"

# Framework-association index returned by the (patched) mappings retriever.
# Both sample controls map to KNOWN_FRAMEWORK only.
MAPPING_INDEX = {
    ALPHA_ARN: [FrameworkAssociation(name=KNOWN_FRAMEWORK, item="1.1")],
    BETA_ARN: [FrameworkAssociation(name=KNOWN_FRAMEWORK, item="2.2")],
}


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def input_file(tmp_path):
    """A simple JSON-array input file matching the sample controls."""
    content = json.dumps(["AWS::EC2::Instance", "AWS::S3::Bucket"])
    file_path = tmp_path / "input.json"
    file_path.write_text(content)
    return str(file_path)


# --- Tests ---


@patch("control_tower_controls_generator.cli.retrieve_enabled_controls")
@patch("control_tower_controls_generator.cli.retrieve_control_mappings")
@patch("control_tower_controls_generator.cli.retrieve_control_catalog")
class TestFrameworkErrors:
    """CLI-level warnings and error exit codes for --framework."""

    def test_unrecognized_framework_warns_and_produces_zero_match_report(
        self, mock_catalog, mock_mappings, mock_enabled, runner, input_file
    ):
        """An unrecognized framework warns on stderr and
        still exits 0 with a zero-control report carrying the framework-specific
        no-match message."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_mappings.return_value = MAPPING_INDEX
        mock_enabled.return_value = []

        result = runner.invoke(
            main,
            [
                "--no-interactive",
                "--input-file",
                input_file,
                "--framework",
                "BOGUS-FRAMEWORK",
            ],
        )

        # Unrecognized framework is a warning, not an error.
        assert result.exit_code == 0
        mock_mappings.assert_called_once()

        # Warning is written to stderr, naming the unrecognized framework.
        assert "matched no control mappings" in result.stderr
        assert "BOGUS-FRAMEWORK" in result.stderr

        # The report (stdout) has zero controls and the framework-specific
        # empty message. stdout is JSON only; the warning is on stderr.
        report = json.loads(result.stdout)
        assert report["summary"]["totalRecommended"] == 0
        assert report["controls"] == []
        assert report["message"] == "No controls matched the requested frameworks"

    def test_mappings_api_failure_exits_with_code_2(
        self, mock_catalog, mock_mappings, mock_enabled, runner, input_file
    ):
        """A mappings-API failure (RuntimeError with no auth
        cause) terminates with exit code 2 and an API error on stderr."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = []
        mock_mappings.side_effect = RuntimeError(
            "AWS Control Catalog API error (ThrottlingException): rate exceeded"
        )

        result = runner.invoke(
            main,
            [
                "--no-interactive",
                "--input-file",
                input_file,
                "--framework",
                KNOWN_FRAMEWORK,
            ],
        )

        assert result.exit_code == 2
        assert "API error" in result.stderr

    def test_mappings_auth_failure_exits_with_code_3(
        self, mock_catalog, mock_mappings, mock_enabled, runner, input_file
    ):
        """A mappings-API auth failure (RuntimeError whose
        __cause__ is an AccessDeniedException ClientError) is routed to the
        distinct auth exit code 3."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = []

        client_error = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "ListControlMappings",
        )

        def _raise_auth(*args, **kwargs):
            # Mirror the retriever: wrap the ClientError as __cause__ so the
            # CLI's _is_auth_error can unwrap it.
            raise RuntimeError(
                "AWS Control Catalog API error (AccessDeniedException): denied"
            ) from client_error

        mock_mappings.side_effect = _raise_auth

        result = runner.invoke(
            main,
            [
                "--no-interactive",
                "--input-file",
                input_file,
                "--framework",
                KNOWN_FRAMEWORK,
            ],
        )

        assert result.exit_code == 3
        assert "Authentication error" in result.stderr
