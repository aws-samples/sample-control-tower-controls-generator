"""Unit tests for CLI options and argument parsing.

Exercises ``control_tower_controls_generator.cli.main`` through
``click.testing.CliRunner``. Only the AWS-facing retrievers are replaced; the
parser, mapper, filters and report generator run for real. ``write_output``,
``generate_report`` and ``filter_by_severity`` are wrapped (``wraps=``) rather
than stubbed, so the assertions are about what the CLI hands them while the
pipeline still produces a real report.

Severity string parsing and the validator callback itself are covered in
``test_severity_filter.py``; here the focus is the CLI-level behavior.

"""

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from control_tower_controls_generator import cli
from control_tower_controls_generator.cli import main
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    SeverityFilterConfig,
)


CLI = "control_tower_controls_generator.cli"


def _make_control(arn: str, name: str, severity: str, resource: str) -> Control:
    return Control(
        arn=arn,
        name=name,
        description=f"Description for {name}",
        behavior="DETECTIVE",
        severity=severity,
        implementation=ControlImplementation(type="AWS::Config::ConfigRule"),
        governed_resources=[resource],
    )


#: One control per severity level, all matching the input file below, so a
#: default run (no severity filter) must report all four.
CATALOG = [
    _make_control("arn:aws:controlcatalog:::control/low", "Low Control", "LOW", "AWS::S3::Bucket"),
    _make_control("arn:aws:controlcatalog:::control/med", "Medium Control", "MEDIUM", "AWS::S3::Bucket"),
    _make_control("arn:aws:controlcatalog:::control/high", "High Control", "HIGH", "AWS::EC2::Instance"),
    _make_control("arn:aws:controlcatalog:::control/crit", "Critical Control", "CRITICAL", "AWS::EC2::Instance"),
]


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def input_file(tmp_path):
    path = tmp_path / "input.json"
    path.write_text(json.dumps(["AWS::S3::Bucket", "AWS::EC2::Instance"]))
    return str(path)


@pytest.fixture
def pipeline():
    """Patch the AWS retrievers and spy on the downstream stages.

    The retrievers are the only true stubs. The spies wrap the real functions
    so a run still produces (and, for ``write_output``, emits) a real report.
    """
    with patch(f"{CLI}.retrieve_control_catalog", return_value=list(CATALOG)) as catalog, \
         patch(f"{CLI}.retrieve_enabled_controls", return_value=[]) as enabled, \
         patch(f"{CLI}.retrieve_control_mappings", return_value={}) as mappings, \
         patch(f"{CLI}.filter_by_severity", wraps=cli.filter_by_severity) as severity, \
         patch(f"{CLI}.generate_report", wraps=cli.generate_report) as report, \
         patch(f"{CLI}.write_output", wraps=cli.write_output) as writer:
        yield SimpleNamespace(
            catalog=catalog,
            enabled=enabled,
            mappings=mappings,
            severity=severity,
            report=report,
            writer=writer,
        )


def _assert_no_pipeline_activity(pipeline) -> None:
    """Nothing past argument handling ran: no API call, no report, no write."""
    pipeline.catalog.assert_not_called()
    pipeline.enabled.assert_not_called()
    pipeline.mappings.assert_not_called()
    pipeline.report.assert_not_called()
    pipeline.writer.assert_not_called()


class TestRequiredInputFile:
    """The resource type input file is required."""

    @pytest.mark.parametrize("extra_args", [[], ["--input-file", ""]])
    def test_missing_input_file_in_non_interactive_mode_exits_1(
        self, runner, pipeline, extra_args
    ):
        result = runner.invoke(main, ["--no-interactive", *extra_args])

        assert result.exit_code == 1
        assert "--input-file is required" in result.stderr
        assert result.stdout == ""
        _assert_no_pipeline_activity(pipeline)

    def test_missing_input_file_in_interactive_mode_is_prompted_for(
        self, runner, pipeline, input_file
    ):
        # Every other option except --framework is supplied up front, so the
        # only prompts are the input file and the framework filter (answered
        # with an empty line). An empty --output-file means stdout.
        args = [
            "--output-format", "json",
            "--output-file", "",
            "--severity-filter", "LOW",
            "--behavior-filter", "DETECTIVE",
            "--region", "us-east-1",
            "--organizational-unit", "",
        ]

        result = runner.invoke(main, args, input=f"{input_file}\n\n")

        assert result.exit_code == 0, result.output
        assert "Path to resource type input file" in result.output
        pipeline.catalog.assert_called_once_with(region="us-east-1")
        pipeline.writer.assert_called_once()


class TestDefaults:
    """Defaults in non-interactive mode: json, no severity filter, stdout."""

    def test_output_format_defaults_to_json(self, runner, pipeline, input_file):
        result = runner.invoke(main, ["--no-interactive", "--input-file", input_file])

        assert result.exit_code == 0, result.output
        assert pipeline.report.call_args.kwargs["output_format"] == "json"
        json.loads(result.stdout)  # the emitted report is JSON

    def test_no_severity_filter_by_default_includes_all_severities(
        self, runner, pipeline, input_file
    ):
        result = runner.invoke(main, ["--no-interactive", "--input-file", input_file])

        assert result.exit_code == 0, result.output
        pipeline.severity.assert_called_once()
        assert pipeline.severity.call_args.args[1] == SeverityFilterConfig()

        report = json.loads(result.stdout)
        assert {c["severity"] for c in report["controls"]} == {
            "LOW", "MEDIUM", "HIGH", "CRITICAL"
        }

    def test_output_defaults_to_stdout(self, runner, pipeline, input_file):
        # No --output-file means stdout.
        result = runner.invoke(main, ["--no-interactive", "--input-file", input_file])

        assert result.exit_code == 0, result.output
        pipeline.writer.assert_called_once()
        content, output_file = pipeline.writer.call_args.args
        assert output_file is None
        assert result.stdout == content
        assert "Report saved to" not in result.stderr

    def test_region_defaults_to_none(self, runner, pipeline, input_file):
        # None lets boto3 use the credential chain's region.
        result = runner.invoke(main, ["--no-interactive", "--input-file", input_file])

        assert result.exit_code == 0, result.output
        pipeline.catalog.assert_called_once_with(region=None)


class TestSeverityFilterOption:
    """Only LOW, MEDIUM, HIGH, CRITICAL are accepted."""

    @pytest.mark.parametrize(
        "value, bad_part",
        [("INVALID", "INVALID"), ("HIGH,BOGUS", "BOGUS"), ("", "")],
    )
    def test_invalid_severity_filter_rejected_before_any_api_call(
        self, runner, pipeline, input_file, value, bad_part
    ):
        result = runner.invoke(
            main,
            ["--no-interactive", "--input-file", input_file, "--severity-filter", value],
        )

        # click reports BadParameter as a usage error, exit code 2.
        assert result.exit_code == 2
        assert "Invalid value for '--severity-filter'" in result.stderr
        assert f"Invalid severity value '{bad_part}'" in result.stderr
        assert result.stdout == ""
        _assert_no_pipeline_activity(pipeline)


class TestOutputFormatOption:
    """Output format is json or markdown."""

    @pytest.mark.parametrize(
        "value, expected",
        [("json", "json"), ("markdown", "markdown"), ("Markdown", "markdown")],
    )
    def test_valid_output_format_passed_to_report_generator(
        self, runner, pipeline, input_file, value, expected
    ):
        result = runner.invoke(
            main,
            ["--no-interactive", "--input-file", input_file, "--output-format", value],
        )

        assert result.exit_code == 0, result.output
        assert pipeline.report.call_args.kwargs["output_format"] == expected

    @pytest.mark.parametrize("value", ["xml", "csv", "md"])
    def test_invalid_output_format_rejected(self, runner, pipeline, input_file, value):
        result = runner.invoke(
            main,
            ["--no-interactive", "--input-file", input_file, "--output-format", value],
        )

        assert result.exit_code == 2
        assert "Invalid value for '--output-format'" in result.stderr
        assert result.stdout == ""
        _assert_no_pipeline_activity(pipeline)


class TestRegionOption:
    """--region is passed through to every AWS call."""

    def test_region_passed_to_catalog_and_no_ou_skips_enabled_controls(
        self, runner, pipeline, input_file
    ):
        result = runner.invoke(
            main,
            ["--no-interactive", "--input-file", input_file, "--region", "eu-west-1"],
        )

        assert result.exit_code == 0, result.output
        pipeline.catalog.assert_called_once_with(region="eu-west-1")
        # No OU given: the enabled-controls retriever is never reached.
        pipeline.enabled.assert_not_called()

    def test_region_passed_to_catalog_and_enabled_controls_with_ou(
        self, runner, pipeline, input_file
    ):
        result = runner.invoke(
            main,
            [
                "--no-interactive",
                "--input-file", input_file,
                "--region", "ap-southeast-2",
                "--organizational-unit", "ou-abcd-12345678",
            ],
        )

        assert result.exit_code == 0, result.output
        pipeline.catalog.assert_called_once_with(region="ap-southeast-2")
        pipeline.enabled.assert_called_once_with(
            "ou-abcd-12345678", region="ap-southeast-2"
        )

    def test_region_passed_to_control_mappings_with_framework(
        self, runner, pipeline, input_file
    ):
        result = runner.invoke(
            main,
            [
                "--no-interactive",
                "--input-file", input_file,
                "--region", "us-west-2",
                "--framework", "PCI-DSS-v4.0",
            ],
        )

        assert result.exit_code == 0, result.output
        pipeline.mappings.assert_called_once_with(region="us-west-2")


class TestOutputFileOption:
    """--output-file is handed to the writer."""

    def test_output_file_passed_to_writer(self, runner, input_file, tmp_path):
        out_path = str(tmp_path / "reports" / "out.json")

        with patch(f"{CLI}.retrieve_control_catalog", return_value=list(CATALOG)), \
             patch(f"{CLI}.write_output") as writer:
            result = runner.invoke(
                main,
                ["--no-interactive", "--input-file", input_file, "--output-file", out_path],
            )

        assert result.exit_code == 0, result.output
        writer.assert_called_once()
        content, output_file = writer.call_args.args
        assert output_file == out_path
        assert json.loads(content)["summary"]["totalRecommended"] == len(CATALOG)
        # The report went to the writer, not to stdout.
        assert result.stdout == ""
