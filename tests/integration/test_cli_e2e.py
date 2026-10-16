"""End-to-end integration tests for the CLI pipeline.

Tests the full pipeline: input file → control retrieval → mapping → filtering → report output.
Uses click.testing.CliRunner and mocks the retriever functions (not boto3 directly)
since moto does not support controlcatalog.
"""

import json
import os
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError, ParamValidationError
from click.testing import CliRunner

from control_tower_controls_generator import cli
from control_tower_controls_generator.cli import main
from control_tower_controls_generator.enabled_controls_retriever import (
    retrieve_enabled_controls as real_retrieve_enabled_controls,
)
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    EnabledControl,
)


# --- Fixtures ---


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


SAMPLE_CONTROLS = [
    _make_control(
        arn="arn:aws:controlcatalog:::control/aaa",
        name="Alpha Control",
        behavior="PREVENTIVE",
        severity="HIGH",
        governed_resources=["AWS::EC2::Instance", "AWS::EC2::SecurityGroup"],
    ),
    _make_control(
        arn="arn:aws:controlcatalog:::control/bbb",
        name="Beta Control",
        behavior="DETECTIVE",
        severity="MEDIUM",
        governed_resources=["AWS::S3::Bucket"],
    ),
    _make_control(
        arn="arn:aws:controlcatalog:::control/ccc",
        name="Gamma Control",
        behavior="PROACTIVE",
        severity="CRITICAL",
        governed_resources=["AWS::Lambda::Function"],
    ),
    _make_control(
        arn="arn:aws:controlcatalog:::control/ddd",
        name="Delta Control",
        behavior="DETECTIVE",
        severity="LOW",
        governed_resources=["AWS::RDS::DBInstance"],
    ),
]

SAMPLE_ENABLED_CONTROLS = [
    EnabledControl(control_arn="arn:aws:controlcatalog:::control/aaa"),
]


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def simple_input_file(tmp_path):
    """Create a simple JSON array input file."""
    content = json.dumps(["AWS::EC2::Instance", "AWS::S3::Bucket", "AWS::Lambda::Function"])
    file_path = tmp_path / "input.json"
    file_path.write_text(content)
    return str(file_path)


@pytest.fixture
def config_aggregator_input_file(tmp_path):
    """Create a Config aggregator format input file."""
    content = json.dumps({
        "QueryInfo": {"SelectFields": [{"Name": "resourceType"}, {"Name": "accountId"}]},
        "Results": [
            json.dumps({"resourceType": "AWS::EC2::Instance", "accountId": "111111111111"}),
            json.dumps({"resourceType": "AWS::S3::Bucket", "accountId": "222222222222"}),
            json.dumps({"resourceType": "AWS::EC2::Instance", "accountId": "333333333333"}),
        ],
    })
    file_path = tmp_path / "aggregator.json"
    file_path.write_text(content)
    return str(file_path)


# --- Full pipeline tests (JSON output) ---


@patch("control_tower_controls_generator.cli.retrieve_enabled_controls")
@patch("control_tower_controls_generator.cli.retrieve_control_catalog")
class TestFullPipelineJSON:
    """Test end-to-end CLI execution with JSON output."""

    def test_simple_input_produces_json_report(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """Full pipeline: simple input → catalog → mapping → JSON report."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = []

        result = runner.invoke(main, ["--no-interactive", "--input-file", simple_input_file])

        assert result.exit_code == 0
        report = json.loads(result.output)
        assert "summary" in report
        assert "controls" in report
        # 3 controls should match (Alpha, Beta, Gamma)
        assert report["summary"]["totalRecommended"] == 3
        assert report["summary"]["gaps"] == 3
        assert report["summary"]["alreadyEnabled"] == 0

    def test_controls_sorted_alphabetically(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """Controls are sorted by name."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = []

        result = runner.invoke(main, ["--no-interactive", "--input-file", simple_input_file])

        assert result.exit_code == 0
        report = json.loads(result.output)
        names = [c["controlName"] for c in report["controls"]]
        assert names == sorted(names)

    def test_report_entry_fields(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """Report entries have required fields."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = []

        result = runner.invoke(main, ["--no-interactive", "--input-file", simple_input_file])

        assert result.exit_code == 0
        report = json.loads(result.output)
        for control in report["controls"]:
            assert "controlName" in control
            assert "controlArn" in control
            assert "behavior" in control
            assert "severity" in control
            assert "matchedResourceTypes" in control
            assert "enablementStatus" in control

    def test_severity_filter_minimum(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """Severity filter with minimum level."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = []

        result = runner.invoke(
            main, ["--no-interactive", "--input-file", simple_input_file, "--severity-filter", "HIGH"]
        )

        assert result.exit_code == 0
        report = json.loads(result.output)
        # Only HIGH and CRITICAL should pass (Alpha=HIGH, Gamma=CRITICAL)
        assert report["summary"]["totalRecommended"] == 2
        severities = {c["severity"] for c in report["controls"]}
        assert severities <= {"HIGH", "CRITICAL"}

    def test_severity_filter_specific_list(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """Severity filter with specific list."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = []

        result = runner.invoke(
            main, ["--no-interactive", "--input-file", simple_input_file, "--severity-filter", "MEDIUM,CRITICAL"]
        )

        assert result.exit_code == 0
        report = json.loads(result.output)
        severities = {c["severity"] for c in report["controls"]}
        assert severities <= {"MEDIUM", "CRITICAL"}


# --- Full pipeline tests (Markdown output) ---


@patch("control_tower_controls_generator.cli.retrieve_enabled_controls")
@patch("control_tower_controls_generator.cli.retrieve_control_catalog")
class TestFullPipelineMarkdown:
    """Test end-to-end CLI execution with Markdown output."""

    def test_markdown_output_has_header_and_table(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """Markdown output includes summary and table."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = []

        result = runner.invoke(
            main, ["--no-interactive", "--input-file", simple_input_file, "--output-format", "markdown"]
        )

        assert result.exit_code == 0
        output = result.output
        assert "# Control Tower Controls Report" in output
        assert "## Summary" in output
        assert "## Controls" in output
        assert "| Control Name |" in output

    def test_markdown_contains_all_matched_controls(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """All matched controls appear in the markdown table."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = []

        result = runner.invoke(
            main, ["--no-interactive", "--input-file", simple_input_file, "--output-format", "markdown"]
        )

        assert result.exit_code == 0
        assert "Alpha Control" in result.output
        assert "Beta Control" in result.output
        assert "Gamma Control" in result.output


# --- OU comparison tests ---

# ==============================================================================
# The successful OU run, end to end
#
# Before the fix the retriever could not return data under any circumstances:
# the request failed boto3 parameter validation, and had it not, the response
# was read with keys the service does not emit. So a successful comparison had
# never been exercised end to end -- every report ever produced with an OU
# supplied read "Already Enabled: 0" with "Gaps" equal to the total, which is
# exactly what the bug report shows. The tests below are that missing half.
#
# A non-zero Already Enabled count is the single clearest signal the bug is
# gone, so each success test asserts one.
#
# The failing half of this scenario is already covered by ``TestErrorScenarios``
# further down: auth failures by
# ``test_ou_auth_failure_exits_3_naming_the_ou_and_the_cause``, non-auth API
# failures by ``test_ou_non_auth_failure_exits_2_naming_the_ou_and_the_cause``.
# Nothing here duplicates them.
#
# ``FAILING_OU_ID`` / ``FAILING_OU_ARN`` and the two patch-target constants are
# defined further down alongside the failure helpers they arrived with. Module
# globals resolve at call time, so reusing them from here is deliberate: the
# successful and the failing runs are asserted against the same OU from the bug
# report rather than against two identifiers that could drift apart.
# ==============================================================================

#: ``output_writer.write_output`` announces a written file on **stderr**, not
#: stdout, so "stderr is empty" is false for any run using ``--output-file``
#: even when it went perfectly. Filtered out rather than asserted around, so the
#: remaining assertion stays "nothing else was said" instead of weakening to a
#: substring check.
REPORT_SAVED_PREFIX = "Report saved to "


def _stderr_without_report_saved(result) -> str:
    """``result.stderr`` with the ``Report saved to ...`` line removed.

    A successful retrieval must not emit a warning. Asserting the
    absence of ``Warning:`` alone would pass on a run that printed something
    else unexpected, so the stronger form is used: drop the one line the writer
    is documented to emit, and require what is left to be empty.
    """
    lines = [
        line
        for line in result.stderr.splitlines()
        if not line.startswith(REPORT_SAVED_PREFIX)
    ]
    return "\n".join(lines).strip()


def _successful_boto3(mock_boto3, pages: list[dict], ou_arn: str) -> None:
    """Point a mocked boto3 at clients that succeed, returning ``pages``.

    Mirrors ``_failing_boto3`` below, inverted: ``DescribeOrganizationalUnit``
    reports ``ou_arn`` and the ``ListEnabledControls`` paginator yields
    ``pages``. Pages are supplied in the **camelCase** shape the ``controltower``
    service model actually defines, which is the shape unfixed code silently
    read as empty.
    """
    client = mock_boto3.client.return_value
    client.describe_organizational_unit.return_value = {
        "OrganizationalUnit": {"Id": FAILING_OU_ID, "Arn": ou_arn}
    }
    client.get_paginator.return_value.paginate.return_value = pages


def _assert_summary_derived_from_labels(report: dict) -> None:
    """The summary counts must be the label counts.

    Checking the three numbers against the entries rather than against literals
    makes "a correct summary" mean consistent-with-the-report, so a summary that
    happens to match an expected constant while disagreeing with its own rows
    still fails.
    """
    labels = [entry["enablementStatus"] for entry in report["controls"]]
    summary = report["summary"]

    assert summary["totalRecommended"] == len(labels)
    assert summary["alreadyEnabled"] == labels.count("already enabled")
    assert summary["gaps"] == labels.count("not enabled")
    assert summary["totalRecommended"] == summary["alreadyEnabled"] + summary["gaps"]


# ==============================================================================
# Both identifier forms, and the unchanged no-OU path
#
# The fix put a second AWS call on the OU path: bare OU IDs are resolved through
# ``organizations:DescribeOrganizationalUnit`` because ``targetIdentifier`` is
# typed as an ARN. That call has to appear for exactly one of the two identifier
# forms and on neither of the runs that supply no OU at all, which is three
# claims about where an API call is *absent*. Absence is the part a mock makes
# easy to assert badly, so the helpers below read the ``boto3.client`` call log
# rather than only the per-operation mocks.
# ==============================================================================


def _client_services(mock_boto3) -> list:
    """Service names every ``boto3.client(...)`` attempt asked for, in order.

    ``_successful_boto3`` hands the same ``client.return_value`` back whatever
    service is asked for, which is what makes it convenient and also what makes
    "``describe_organizational_unit`` was never called" weaker than it looks: it
    would still hold if an Organizations client had been constructed and then
    left unused. The call log of ``boto3.client`` itself is the stronger
    evidence, and ordered, so it also shows resolution happening before the
    Control Tower client exists.
    """
    return [
        call.args[0] if call.args else call.kwargs.get("service_name")
        for call in mock_boto3.client.call_args_list
    ]


def _run_with_real_retriever(
    runner,
    input_file: str,
    ou_value: str | None = None,
    pages: list[dict] | None = None,
    ou_arn: str | None = None,
) -> dict:
    """Invoke the CLI through the *real* retriever and report what AWS saw.

    Replaces the class-level ``cli.retrieve_enabled_controls`` patch with the
    genuine function and mocks boto3 at the retriever's own seam, following
    ``test_real_retriever_success_end_to_end_from_camelcase_pages``.

    Returns the boto3 mocks alongside the result rather than asserting inline,
    so a caller can run two invocations and compare them. Asserting the two
    identifier forms against each other says something neither run says alone.

    ``ou_value=None`` omits ``--organizational-unit`` entirely, which is how the
    no-OU path is exercised with the real retriever wired in.
    """
    args = ["--no-interactive", "--input-file", input_file]
    if ou_value is not None:
        args += ["--organizational-unit", ou_value]

    with patch(CLI_RETRIEVER_TARGET, real_retrieve_enabled_controls), patch(
        ENABLED_CONTROLS_BOTO3_TARGET
    ) as mock_boto3:
        _successful_boto3(mock_boto3, pages or [], ou_arn or FAILING_OU_ARN)
        result = runner.invoke(main, args)

        client = mock_boto3.client.return_value
        return {
            "result": result,
            "services": _client_services(mock_boto3),
            "describe": client.describe_organizational_unit,
            "paginate": client.get_paginator.return_value.paginate,
        }


#: One page carrying Alpha Control, so the runs below produce a real
#: ``already enabled`` label instead of proving only that nothing crashed.
ONE_ENABLED_PAGE = [
    {"enabledControls": [{"controlIdentifier": "arn:aws:controlcatalog:::control/aaa"}]}
]


@patch("control_tower_controls_generator.cli.retrieve_enabled_controls")
@patch("control_tower_controls_generator.cli.retrieve_control_catalog")
class TestOUComparison:
    """Test the OU comparison flow end-to-end."""

    def test_ou_comparison_marks_enabled_controls(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """Enabled controls detected via OU."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = SAMPLE_ENABLED_CONTROLS

        result = runner.invoke(
            main,
            ["--no-interactive", "--input-file", simple_input_file, "--organizational-unit", "ou-abc-12345678"],
        )

        assert result.exit_code == 0
        report = json.loads(result.output)
        assert report["summary"]["alreadyEnabled"] == 1
        assert report["summary"]["gaps"] == 2

        # Alpha Control should be marked as already enabled
        alpha = next(c for c in report["controls"] if c["controlName"] == "Alpha Control")
        assert alpha["enablementStatus"] == "already enabled"

        # Others should be not enabled
        beta = next(c for c in report["controls"] if c["controlName"] == "Beta Control")
        assert beta["enablementStatus"] == "not enabled"

    def test_ou_comparison_calls_retriever_with_ou_id(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """OU ID is passed to the enabled controls retriever."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = []

        runner.invoke(
            main,
            ["--no-interactive", "--input-file", simple_input_file, "--organizational-unit", "ou-test-00000001"],
        )

        mock_enabled.assert_called_once_with("ou-test-00000001", region=None)

    def test_no_ou_means_all_not_enabled(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """Without OU, all controls are 'not enabled'."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = []

        result = runner.invoke(main, ["--no-interactive", "--input-file", simple_input_file])

        assert result.exit_code == 0
        report = json.loads(result.output)
        for control in report["controls"]:
            assert control["enablementStatus"] == "not enabled"
        mock_enabled.assert_not_called()

    # --- the successful OU run -----------
    #
    # Every test below passes ``--no-interactive``, so none of them reach the
    # interactive prompt path the older tests in this class rely on.

    def test_successful_ou_run_labels_and_summarizes_and_says_nothing(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """A successful comparison labels, counts, exits 0, and stays quiet.

        The outcome that was unreachable before the fix. Reported to stdout so
        no ``Report saved to`` line exists to filter, which makes "nothing was
        printed to stderr" assertable in its strongest form -- an exact match
        against empty rather than the absence of a substring.

        ``alreadyEnabled`` is asserted non-zero on purpose: that number was 0 on
        every OU run the unfixed code could produce.
        """
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = SAMPLE_ENABLED_CONTROLS

        result = runner.invoke(
            main,
            [
                "--no-interactive",
                "--input-file", simple_input_file,
                "--organizational-unit", FAILING_OU_ID,
            ],
        )

        assert result.exit_code == 0, f"stderr was {result.stderr!r}"
        assert result.stderr == "", (
            "a successful retrieval must not print a warning; stderr carried "
            f"{result.stderr!r}"
        )

        report = json.loads(result.stdout)
        enabled_arns = {ec.control_arn for ec in SAMPLE_ENABLED_CONTROLS}

        for entry in report["controls"]:
            expected = (
                "already enabled" if entry["controlArn"] in enabled_arns
                else "not enabled"
            )
            assert entry["enablementStatus"] == expected, (
                f"{entry['controlName']} ({entry['controlArn']}) was labelled "
                f"{entry['enablementStatus']!r}"
            )

        _assert_summary_derived_from_labels(report)
        assert report["summary"]["alreadyEnabled"] > 0, (
            "a successful comparison against an OU with controls enabled must "
            "report a non-zero Already Enabled count; 0 is the value the bug "
            "produced for every input"
        )

    def test_successful_ou_run_to_output_file_warns_nothing(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """The same run written to a file: still exit 0, still no warning.

        ``write_output`` prints ``Report saved to ...`` to stderr on success, so
        this variant filters that one line and requires the remainder to be
        empty (see ``_stderr_without_report_saved``). The absence of ``Warning:``
        is asserted alongside it, since that prefix is the literal shape of the
        message the unfixed retriever emitted.
        """
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = SAMPLE_ENABLED_CONTROLS

        with runner.isolated_filesystem():
            result = runner.invoke(
                main,
                [
                    "--no-interactive",
                    "--input-file", simple_input_file,
                    "--organizational-unit", FAILING_OU_ID,
                    "--output-file", "report.json",
                ],
            )

            assert result.exit_code == 0, f"stderr was {result.stderr!r}"
            assert os.path.exists("report.json"), (
                "a successful run writes its report"
            )
            with open("report.json") as f:
                report = json.load(f)

        assert "Warning:" not in result.stderr, (
            f"a successful retrieval warned: {result.stderr!r}"
        )
        # Pins the line the filter exists to remove. Without this the filter
        # could quietly become a no-op and the assertion below would still pass.
        assert REPORT_SAVED_PREFIX in result.stderr, (
            f"expected the writer's own stderr line; got {result.stderr!r}"
        )
        assert _stderr_without_report_saved(result) == "", (
            "the only thing a successful run may say on stderr is where it "
            f"saved the report; it also said {result.stderr!r}"
        )

        _assert_summary_derived_from_labels(report)
        assert report["summary"]["alreadyEnabled"] > 0

    def test_successful_ou_run_markdown_summary_is_not_all_gaps(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """The bug report quoted the markdown summary, so assert that form too.

        The reported symptom was ``Already Enabled: 0`` with ``Gaps`` equal to
        the total in the human-readable report. This is that same rendering,
        now showing a real count.
        """
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = SAMPLE_ENABLED_CONTROLS

        result = runner.invoke(
            main,
            [
                "--no-interactive",
                "--input-file", simple_input_file,
                "--organizational-unit", FAILING_OU_ID,
                "--output-format", "markdown",
            ],
        )

        assert result.exit_code == 0, f"stderr was {result.stderr!r}"
        assert result.stderr == ""

        output = result.stdout
        assert "- **Total Recommended**: 3" in output
        assert "- **Already Enabled**: 1" in output, (
            f"the reported symptom was 'Already Enabled: 0'; got {output!r}"
        )
        assert "- **Gaps**: 2" in output, (
            "Gaps equal to the total recommended count is the shape of the bug"
        )
        # The enabled control's row carries the label, not just the summary.
        alpha_row = next(
            line for line in output.splitlines() if line.startswith("| Alpha Control ")
        )
        assert "already enabled" in alpha_row

    def test_real_retriever_success_end_to_end_from_camelcase_pages(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """The user's original scenario, now working, through the real retriever.

        The one test that exercises the whole chain in a single run rather than
        in units: a bare OU ID resolved to an ARN, bound to ``targetIdentifier``,
        answered with camelCase ``enabledControls`` / ``controlIdentifier``
        pages, and turned into report labels. Every link in that chain was
        broken before the fix, and each was fixed in a different place, so
        asserting the report at the far end is the proof they compose.

        The class-level patch is replaced with the actual
        ``retrieve_enabled_controls`` and boto3 is mocked at the retriever's own
        seam, following the ``real_retriever`` tests in ``TestErrorScenarios``.

        Two pages, so page-then-item aggregation is exercised here too rather
        than only at the unit level.

        The ``controlIdentifier`` values are Control Catalog ARNs because that is
        the only namespace ``report_generator``'s set membership can match. The
        Control Tower ``controlIdentifier`` namespace mismatch is a separate,
        documented out-of-scope defect (bugfix.md, note on 2.6); using the
        matching form here keeps this test measuring the fix under test.
        """
        mock_catalog.return_value = SAMPLE_CONTROLS
        pages = [
            {"enabledControls": [
                {"controlIdentifier": "arn:aws:controlcatalog:::control/aaa"}
            ]},
            {"enabledControls": [
                {"controlIdentifier": "arn:aws:controlcatalog:::control/bbb"}
            ]},
        ]

        with patch(CLI_RETRIEVER_TARGET, real_retrieve_enabled_controls), patch(
            ENABLED_CONTROLS_BOTO3_TARGET
        ) as mock_boto3:
            _successful_boto3(mock_boto3, pages, FAILING_OU_ARN)
            result = runner.invoke(
                main,
                [
                    "--no-interactive",
                    "--input-file", simple_input_file,
                    "--organizational-unit", FAILING_OU_ID,
                ],
            )

            paginate = mock_boto3.client.return_value.get_paginator.return_value.paginate

        assert result.exit_code == 0, f"stderr was {result.stderr!r}"
        assert result.stderr == "", (
            f"the run that used to warn now says nothing: {result.stderr!r}"
        )

        # Entry point of the chain: the camelCase name, bound to the resolved
        # ARN rather than to the bare OU ID the user typed.
        paginate.assert_called_once_with(targetIdentifier=FAILING_OU_ARN)

        report = json.loads(result.stdout)
        statuses = {
            entry["controlName"]: entry["enablementStatus"]
            for entry in report["controls"]
        }
        assert statuses["Alpha Control"] == "already enabled"
        assert statuses["Beta Control"] == "already enabled"
        assert statuses["Gamma Control"] == "not enabled"

        _assert_summary_derived_from_labels(report)
        assert report["summary"]["alreadyEnabled"] == 2, (
            "both pages' controls have to reach the report, or aggregation "
            f"dropped one: {report['summary']!r}"
        )
        assert report["summary"]["gaps"] == 1

    def test_real_retriever_empty_result_is_a_genuine_zero(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """``Already Enabled: 0`` stays reachable -- but only through success.

        The other direction of the same guarantee. The failure tests in
        ``TestErrorScenarios`` prove a failed retrieval can no longer produce
        this report; this one proves an OU with genuinely nothing enabled still
        can, and that it is indistinguishable from success because it *is*
        success: exit 0, no warning, a report written.
        """
        mock_catalog.return_value = SAMPLE_CONTROLS

        with patch(CLI_RETRIEVER_TARGET, real_retrieve_enabled_controls), patch(
            ENABLED_CONTROLS_BOTO3_TARGET
        ) as mock_boto3:
            _successful_boto3(mock_boto3, [{"enabledControls": []}], FAILING_OU_ARN)
            result = runner.invoke(
                main,
                [
                    "--no-interactive",
                    "--input-file", simple_input_file,
                    "--organizational-unit", FAILING_OU_ID,
                ],
            )

        assert result.exit_code == 0, f"stderr was {result.stderr!r}"
        assert result.stderr == ""

        report = json.loads(result.stdout)
        assert report["summary"]["alreadyEnabled"] == 0
        assert report["summary"]["gaps"] == report["summary"]["totalRecommended"]
        _assert_summary_derived_from_labels(report)

    # --- identifier forms and no-OU ------

    def test_real_retriever_ou_arn_binds_verbatim_with_no_organizations_call(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """An OU ARN reaches Control Tower untouched and skips Organizations.

        This is a preservation guarantee, and the thing it preserves is
        something the fix could plausibly have broken: resolution was added for
        bare OU IDs, and an ARN must not acquire it. Two assertions carry that
        and they are different claims -- an Organizations client constructed and
        then left unused would satisfy "describe was never called" while still
        costing a call and a permission -- so the client construction log is
        checked as the stronger of the two.
        """
        mock_catalog.return_value = SAMPLE_CONTROLS

        observed = _run_with_real_retriever(
            runner,
            simple_input_file,
            ou_value=FAILING_OU_ARN,
            pages=ONE_ENABLED_PAGE,
        )
        result = observed["result"]

        assert result.exit_code == 0, f"stderr was {result.stderr!r}"
        assert result.stderr == ""

        observed["describe"].assert_not_called()
        assert observed["services"] == ["controltower"], (
            "an ARN needs no resolution, so Control Tower is the only client "
            f"the run may construct; it asked for {observed['services']!r}"
        )
        observed["paginate"].assert_called_once_with(targetIdentifier=FAILING_OU_ARN)

        # The ARN did not merely arrive -- it produced a comparison.
        report = json.loads(result.stdout)
        statuses = {
            entry["controlName"]: entry["enablementStatus"]
            for entry in report["controls"]
        }
        assert statuses["Alpha Control"] == "already enabled"
        _assert_summary_derived_from_labels(report)
        assert report["summary"]["alreadyEnabled"] == 1

    def test_real_retriever_identifier_forms_differ_only_by_the_resolution_call(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """Both identifier forms reach Control Tower with the same ARN.

        The bare OU ID's own end-to-end run is already covered by
        ``test_real_retriever_success_end_to_end_from_camelcase_pages``, which
        asserts ``paginate(targetIdentifier=<resolved ARN>)`` for the OU from the
        bug report. What that test cannot say is what makes the two forms
        different, and they are a matched pair: the resolution call
        is made for exactly one of them. Asserting the two runs against each
        other states the boundary between them rather than each side
        of it separately, and the final equality pins down that the difference
        stops at the resolution call -- everything downstream of it, including
        the report, is identical.
        """
        mock_catalog.return_value = SAMPLE_CONTROLS

        by_id = _run_with_real_retriever(
            runner, simple_input_file, ou_value=FAILING_OU_ID, pages=ONE_ENABLED_PAGE
        )
        by_arn = _run_with_real_retriever(
            runner, simple_input_file, ou_value=FAILING_OU_ARN, pages=ONE_ENABLED_PAGE
        )

        for label, observed in (("OU ID", by_id), ("OU ARN", by_arn)):
            result = observed["result"]
            assert result.exit_code == 0, (
                f"the {label} form exited {result.exit_code}; "
                f"stderr was {result.stderr!r}"
            )
            assert result.stderr == "", f"the {label} form said {result.stderr!r}"

        # The bare ID is resolved, and the ordered client log
        # shows resolution completing before the Control Tower client exists.
        by_id["describe"].assert_called_once_with(OrganizationalUnitId=FAILING_OU_ID)
        assert by_id["services"] == ["organizations", "controltower"], (
            "a bare OU ID resolves first, then calls Control Tower; the run "
            f"constructed {by_id['services']!r}"
        )

        # The ARN form makes no such call.
        by_arn["describe"].assert_not_called()
        assert by_arn["services"] == ["controltower"]

        # And the difference stops there: same request, same report.
        assert (
            by_id["paginate"].call_args.kwargs["targetIdentifier"]
            == by_arn["paginate"].call_args.kwargs["targetIdentifier"]
            == FAILING_OU_ARN
        ), (
            "both forms must name the same OU to Control Tower; got "
            f"{by_id['paginate'].call_args!r} and {by_arn['paginate'].call_args!r}"
        )
        assert json.loads(by_id["result"].stdout) == json.loads(
            by_arn["result"].stdout
        ), "the two identifier forms produced different reports"

    def test_real_retriever_no_ou_constructs_no_aws_client(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """No OU supplied: no AWS client is built at all, and exit 0.

        ``test_no_ou_means_all_not_enabled`` above already covers the labels and
        that ``cli.retrieve_enabled_controls`` is not reached, but it does so
        with the retriever mocked out, so it can say nothing about AWS. This one
        puts the real retriever back and asserts the stronger claim through
        boto3 at the retriever's own seam: ``boto3.client`` is never called.
        That claim is worth more after this fix than before it, because the fix
        added a second AWS call to the OU path and neither call belongs on this
        one.

        The exhaustive form lives in
        ``tests/property/test_ou_fix_preservation_props.py``, which compares 105
        report entries against a baseline recorded on pre-fix code across a
        generated option space. This is the plain integration-level case.
        """
        mock_catalog.return_value = SAMPLE_CONTROLS

        observed = _run_with_real_retriever(
            runner, simple_input_file, ou_value=None, pages=ONE_ENABLED_PAGE
        )
        result = observed["result"]

        assert result.exit_code == 0, f"stderr was {result.stderr!r}"
        assert result.stderr == ""

        assert observed["services"] == [], (
            "the no-OU path must construct no AWS client at all; it asked for "
            f"{observed['services']!r}"
        )
        observed["describe"].assert_not_called()
        observed["paginate"].assert_not_called()

        report = json.loads(result.stdout)
        for entry in report["controls"]:
            assert entry["enablementStatus"] == "not enabled", (
                f"{entry['controlName']} was labelled "
                f"{entry['enablementStatus']!r} with no OU supplied"
            )
        _assert_summary_derived_from_labels(report)
        assert report["summary"]["alreadyEnabled"] == 0
        assert report["summary"]["gaps"] == report["summary"]["totalRecommended"]


# --- Error scenarios ---

# ==============================================================================
# Failure Is Loud, Not Silent
#
# The end-to-end half of the contract asserted at the unit level in
# ``tests/unit/test_enabled_controls_retriever.py``: a failed enabled-controls
# retrieval must abort the run without writing a report, name the OU and the
# cause on stderr, and exit 3 for authentication or authorization failures and
# 2 otherwise.
#
# Two kinds of test below, and the distinction matters when reading a failure:
#
# * The routing tests patch ``cli.retrieve_enabled_controls`` to raise and check
#   where ``cli.py`` sends the failure. These PASS on unfixed code, and that is
#   the point, not an oversight -- ``cli.py`` is already correct. Retrieval is
#   step 5 inside the ``try``, ``write_output`` is step 7, and the existing
#   ``except RuntimeError`` handler already routes through ``_is_auth_error``.
#   They pin the behavior the fix relies on getting for free, so a later change
#   to ``cli.py`` cannot quietly remove it.
# * The two ``real_retriever`` tests run the *actual* retriever against a boto3
#   whose call fails, which is the invocation the bug was reported from. These
#   FAIL on unfixed code: ``except (ClientError, BotoCoreError)`` absorbs the
#   failure, so the run writes its report and exits 0 with
#   ``alreadyEnabled: 0`` and ``gaps`` equal to the total.
# ==============================================================================

#: The OU from the bug report, and the ARN form of that same OU.
FAILING_OU_ID = "ou-tito-abcd1234"
FAILING_OU_ARN = "arn:aws:organizations::111122223333:ou/o-abc123/ou-tito-abcd1234"

#: botocore's own report text for the reported failure, reproduced verbatim.
PARAM_VALIDATION_REPORT = (
    'Unknown parameter in input: "TargetIdentifier", must be one of: '
    "targetIdentifier, nextToken, maxResults, filter, includeChildren"
)

#: API failure codes outside ``cli.AUTH_ERROR_CODES``, which belong on exit 2.
NON_AUTH_ERROR_CODES = [
    "ValidationException",
    "TooManyRequestsException",
    "ServiceException",
]


def _client_error(code: str, message: str, operation: str) -> ClientError:
    """A ``ClientError`` shaped the way botocore raises them."""
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


def _wrapped_runtime_error(message: str, cause: BaseException) -> RuntimeError:
    """The ``RuntimeError`` that ``raise RuntimeError(message) from cause`` makes.

    ``cli._is_auth_error`` walks ``__cause__`` to choose exit 3 over exit 2, so
    the chain is the part under test.
    """
    error = RuntimeError(message)
    error.__cause__ = cause
    return error


def _control_tower_error(ou: str, code: str, message: str = "boom") -> RuntimeError:
    """The failure the fixed retriever raises for a Control Tower error.

    Message text mirrors the pattern ``control_retriever.py`` already uses, so
    stderr carries the OU as supplied and the underlying cause.
    """
    cause = _client_error(code, message, "ListEnabledControls")
    return _wrapped_runtime_error(
        f"AWS Control Tower API error for OU '{ou}' ({code}): {message}", cause
    )


def _organizations_error(ou: str, code: str, message: str = "boom") -> RuntimeError:
    """The same, for the AWS Organizations resolution call."""
    cause = _client_error(code, message, "DescribeOrganizationalUnit")
    return _wrapped_runtime_error(
        f"AWS Organizations API error for OU '{ou}' ({code}): {message}", cause
    )


#: The retriever module's own ``boto3`` reference. ``moto`` does not support the
#: ``controltower`` service and the client is constructed inside the function,
#: so this is the seam the real retriever is driven through.
ENABLED_CONTROLS_BOTO3_TARGET = (
    "control_tower_controls_generator.enabled_controls_retriever.boto3"
)

#: Where ``cli.py`` looks the retriever up, so the real one can be put back in
#: place over the class-level patch.
CLI_RETRIEVER_TARGET = "control_tower_controls_generator.cli.retrieve_enabled_controls"


def _failing_boto3(mock_boto3, error: BaseException) -> None:
    """Point a mocked boto3 at a client whose paginated call raises ``error``.

    ``DescribeOrganizationalUnit`` is stubbed with a real response so the run
    behaves the same whether or not identifier resolution exists yet, leaving
    the Control Tower failure as the only variable.
    """
    client = mock_boto3.client.return_value
    client.describe_organizational_unit.return_value = {
        "OrganizationalUnit": {"Id": FAILING_OU_ID, "Arn": FAILING_OU_ARN}
    }
    client.get_paginator.return_value.paginate.side_effect = error


@patch("control_tower_controls_generator.cli.retrieve_enabled_controls")
@patch("control_tower_controls_generator.cli.retrieve_control_catalog")
class TestErrorScenarios:
    """Test error handling end-to-end."""

    def test_missing_input_file(self, mock_catalog, mock_enabled, runner, tmp_path):
        """Missing file produces error exit code 1."""
        nonexistent = str(tmp_path / "does_not_exist.json")

        result = runner.invoke(main, ["--no-interactive", "--input-file", nonexistent])

        assert result.exit_code == 1
        assert "Error" in result.output

    def test_invalid_json_input_file(self, mock_catalog, mock_enabled, runner, tmp_path):
        """Invalid JSON produces error exit code 1."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not valid json {{{")

        result = runner.invoke(main, ["--no-interactive", "--input-file", str(bad_file)])

        assert result.exit_code == 1
        assert "Error" in result.output

    def test_empty_input_file(self, mock_catalog, mock_enabled, runner, tmp_path):
        """Empty array produces error exit code 1."""
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("[]")

        result = runner.invoke(main, ["--no-interactive", "--input-file", str(empty_file)])

        assert result.exit_code == 1
        assert "Error" in result.output

    def test_api_failure_exits_with_code_2(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """API failure produces exit code 2."""
        mock_catalog.side_effect = RuntimeError("AWS Control Catalog API error")

        result = runner.invoke(main, ["--no-interactive", "--input-file", simple_input_file])

        assert result.exit_code == 2
        assert "API error" in result.output

    def test_auth_failure_exits_with_code_3(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """Auth failure produces exit code 3."""
        from botocore.exceptions import ClientError

        auth_error = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
            "ListControls",
        )
        mock_catalog.side_effect = RuntimeError("Auth error")
        mock_catalog.side_effect.__cause__ = auth_error

        result = runner.invoke(main, ["--no-interactive", "--input-file", simple_input_file])

        assert result.exit_code == 3
        assert "Authentication error" in result.output

    def test_invalid_severity_filter_value(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """Invalid severity filter is rejected."""
        result = runner.invoke(
            main, ["--no-interactive", "--input-file", simple_input_file, "--severity-filter", "INVALID"]
        )

        assert result.exit_code == 2  # click exits with 2 for bad params

    # --- failure is loud, not silent ----
    #
    # Design test case 6 and the exit-code routing it depends on. Every test
    # below passes ``--no-interactive``, so none of them touch the interactive
    # prompt path the older tests in this file rely on.

    def test_ou_retrieval_failure_writes_no_output_file(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """Design test case 6: a failed comparison writes no report.

        The output path lives inside an isolated filesystem, so "was never
        created" is checkable rather than inferred.
        """
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.side_effect = _control_tower_error(
            FAILING_OU_ID, "ValidationException", "bad input"
        )

        with runner.isolated_filesystem():
            result = runner.invoke(
                main,
                [
                    "--no-interactive",
                    "--input-file", simple_input_file,
                    "--organizational-unit", FAILING_OU_ID,
                    "--output-file", "report.json",
                ],
            )

            assert result.exit_code != 0, (
                "a run whose requested comparison failed cannot report success"
            )
            assert not os.path.exists("report.json"), (
                "the report claims a gap analysis that was never performed"
            )

    def test_ou_retrieval_failure_writes_no_report_to_stdout(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """With no ``--output-file`` the report must not reach stdout either.

        The reachability constraint is on the outcome, not the file:
        ``Already Enabled: 0`` must only ever come from a retrieval that
        actually succeeded.
        """
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.side_effect = _control_tower_error(
            FAILING_OU_ID, "ValidationException", "bad input"
        )

        result = runner.invoke(
            main,
            [
                "--no-interactive",
                "--input-file", simple_input_file,
                "--organizational-unit", FAILING_OU_ID,
            ],
        )

        assert result.exit_code != 0
        assert "alreadyEnabled" not in result.stdout, (
            f"a failed comparison produced a report: {result.stdout!r}"
        )

    @pytest.mark.parametrize("code", sorted(cli.AUTH_ERROR_CODES))
    def test_ou_auth_failure_exits_3_naming_the_ou_and_the_cause(
        self, mock_catalog, mock_enabled, runner, simple_input_file, code
    ):
        """Every code in ``AUTH_ERROR_CODES`` routes to exit 3.

        Parametrized over ``cli.AUTH_ERROR_CODES`` itself rather than a copy, so
        the set and the routing cannot drift apart.
        """
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.side_effect = _control_tower_error(
            FAILING_OU_ID, code, "credentials rejected"
        )

        with runner.isolated_filesystem():
            result = runner.invoke(
                main,
                [
                    "--no-interactive",
                    "--input-file", simple_input_file,
                    "--organizational-unit", FAILING_OU_ID,
                    "--output-file", "report.json",
                ],
            )

            assert result.exit_code == 3, (
                f"'{code}' is an authentication failure; stderr was "
                f"{result.stderr!r}"
            )
            assert "Authentication error" in result.stderr
            assert FAILING_OU_ID in result.stderr, (
                "stderr has to say which OU the run was asking about"
            )
            assert code in result.stderr, (
                "stderr has to say why the call failed"
            )
            assert not os.path.exists("report.json")

    @pytest.mark.parametrize("code", NON_AUTH_ERROR_CODES)
    def test_ou_non_auth_failure_exits_2_naming_the_ou_and_the_cause(
        self, mock_catalog, mock_enabled, runner, simple_input_file, code
    ):
        """Everything else routes to exit 2, matching the catalog failures."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.side_effect = _control_tower_error(
            FAILING_OU_ID, code, "call rejected"
        )

        with runner.isolated_filesystem():
            result = runner.invoke(
                main,
                [
                    "--no-interactive",
                    "--input-file", simple_input_file,
                    "--organizational-unit", FAILING_OU_ID,
                    "--output-file", "report.json",
                ],
            )

            assert result.exit_code == 2, (
                f"'{code}' is not an authentication failure; stderr was "
                f"{result.stderr!r}"
            )
            assert "API error" in result.stderr
            assert FAILING_OU_ID in result.stderr
            assert code in result.stderr
            assert not os.path.exists("report.json")

    def test_param_validation_cause_exits_2(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """The reported bug's own failure class lands on exit 2, not exit 0.

        ``ParamValidationError`` subclasses ``BotoCoreError``, which is what let
        the swallowing handler absorb it.
        """
        cause = ParamValidationError(report=PARAM_VALIDATION_REPORT)
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.side_effect = _wrapped_runtime_error(
            f"AWS Control Tower connection error for OU '{FAILING_OU_ID}': {cause}",
            cause,
        )

        with runner.isolated_filesystem():
            result = runner.invoke(
                main,
                [
                    "--no-interactive",
                    "--input-file", simple_input_file,
                    "--organizational-unit", FAILING_OU_ID,
                    "--output-file", "report.json",
                ],
            )

            assert result.exit_code == 2
            assert "API error" in result.stderr
            assert FAILING_OU_ID in result.stderr
            assert "TargetIdentifier" in result.stderr
            assert not os.path.exists("report.json")

    def test_organizations_failure_names_organizations_and_exits_3(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """A failed identifier resolution is distinguishable on stderr.

        ``organizations:DescribeOrganizationalUnit`` is callable only from the
        management account or a delegated administrator, so
        ``AccessDeniedException`` here is the likeliest failure of the fix. It
        has to reach exit 3 and say which call failed, or the reader goes
        looking at Control Tower permissions.
        """
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.side_effect = _organizations_error(
            FAILING_OU_ID,
            "AccessDeniedException",
            "not authorized to perform organizations:DescribeOrganizationalUnit",
        )

        with runner.isolated_filesystem():
            result = runner.invoke(
                main,
                [
                    "--no-interactive",
                    "--input-file", simple_input_file,
                    "--organizational-unit", FAILING_OU_ID,
                    "--output-file", "report.json",
                ],
            )

            assert result.exit_code == 3
            assert "Authentication error" in result.stderr
            assert "Organizations" in result.stderr, (
                f"stderr must name the failing call; got {result.stderr!r}"
            )
            assert "Control Tower" not in result.stderr, (
                "Control Tower was never reached, so naming it would misdirect "
                f"the reader; got {result.stderr!r}"
            )
            assert FAILING_OU_ID in result.stderr
            assert not os.path.exists("report.json")

    def test_organizations_failure_exits_2_for_non_auth_codes(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """The resolution call splits its codes the same way."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.side_effect = _organizations_error(
            FAILING_OU_ID, "OrganizationalUnitNotFoundException", "OU not found"
        )

        with runner.isolated_filesystem():
            result = runner.invoke(
                main,
                [
                    "--no-interactive",
                    "--input-file", simple_input_file,
                    "--organizational-unit", FAILING_OU_ID,
                    "--output-file", "report.json",
                ],
            )

            assert result.exit_code == 2
            assert "API error" in result.stderr
            assert "Organizations" in result.stderr
            assert not os.path.exists("report.json")

    def test_real_retriever_failure_leaves_no_output_file(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """The reported invocation, end to end, with the real retriever.

        This is the counterexample rather than a routing check: the class-level
        patch is replaced with the actual ``retrieve_enabled_controls`` and the
        failure is injected at the boto3 seam, exactly as the user's run
        produced it. Unfixed code prints ``Warning: Failed to retrieve enabled
        controls for OU '...'``, hands back ``[]``, writes the report, and exits
        0.
        """
        mock_catalog.return_value = SAMPLE_CONTROLS
        cause = ParamValidationError(report=PARAM_VALIDATION_REPORT)

        with runner.isolated_filesystem():
            with patch(CLI_RETRIEVER_TARGET, real_retrieve_enabled_controls), patch(
                ENABLED_CONTROLS_BOTO3_TARGET
            ) as mock_boto3:
                _failing_boto3(mock_boto3, cause)
                result = runner.invoke(
                    main,
                    [
                        "--no-interactive",
                        "--input-file", simple_input_file,
                        "--organizational-unit", FAILING_OU_ID,
                        "--output-file", "report.json",
                    ],
                )

            assert result.exit_code != 0, (
                "the requested comparison never happened, so exit 0 reports a "
                f"success that did not occur; stderr was {result.stderr!r}"
            )
            assert not os.path.exists("report.json"), (
                "a report was written for a comparison that failed, which is "
                "the outcome the bug report shows: 'Already Enabled: 0' with "
                "'Gaps' equal to the total"
            )

    def test_real_retriever_failure_produces_no_zero_enabled_report(
        self, mock_catalog, mock_enabled, runner, simple_input_file
    ):
        """``Already Enabled: 0`` must be unreachable through a failure.

        Same real-retriever setup, reported to stdout so the fabricated summary
        itself is the assertion subject. On unfixed code this returns the report
        the user saw, with every recommended control labelled "not enabled".
        """
        mock_catalog.return_value = SAMPLE_CONTROLS
        cause = _client_error(
            "AccessDeniedException", "not authorized", "ListEnabledControls"
        )

        with patch(CLI_RETRIEVER_TARGET, real_retrieve_enabled_controls), patch(
            ENABLED_CONTROLS_BOTO3_TARGET
        ) as mock_boto3:
            _failing_boto3(mock_boto3, cause)
            result = runner.invoke(
                main,
                [
                    "--no-interactive",
                    "--input-file", simple_input_file,
                    "--organizational-unit", FAILING_OU_ID,
                ],
            )

        assert result.stdout.strip() == "", (
            "a failed retrieval produced a gap analysis the reader cannot tell "
            f"apart from a real one: {result.stdout!r}"
        )
        assert result.exit_code == 3, (
            "an authorization failure on the enabled-controls call is an "
            f"authentication error, not a zero; stderr was {result.stderr!r}"
        )
        assert "Warning: Failed to retrieve enabled controls" not in result.stderr, (
            "degrading to a warning is the defect: it lets the run continue to "
            f"write_output and exit 0. stderr was {result.stderr!r}"
        )


# --- Config aggregator input test ---


@patch("control_tower_controls_generator.cli.retrieve_enabled_controls")
@patch("control_tower_controls_generator.cli.retrieve_control_catalog")
class TestConfigAggregatorInput:
    """Test with Config aggregator format input."""

    def test_config_aggregator_input_includes_accounts(
        self, mock_catalog, mock_enabled, runner, config_aggregator_input_file
    ):
        """Config aggregator input with account data."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = []

        result = runner.invoke(main, ["--no-interactive", "--input-file", config_aggregator_input_file])

        assert result.exit_code == 0
        report = json.loads(result.output)

        # Alpha Control matches EC2::Instance, should have account info
        alpha = next(c for c in report["controls"] if c["controlName"] == "Alpha Control")
        assert alpha["accounts"] is not None
        assert "111111111111" in alpha["accounts"]
        assert "333333333333" in alpha["accounts"]

        # Beta Control matches S3::Bucket, should have account 222222222222
        beta = next(c for c in report["controls"] if c["controlName"] == "Beta Control")
        assert beta["accounts"] is not None
        assert "222222222222" in beta["accounts"]


# --- Output file test ---


@patch("control_tower_controls_generator.cli.retrieve_enabled_controls")
@patch("control_tower_controls_generator.cli.retrieve_control_catalog")
class TestOutputFile:
    """Test writing output to a file."""

    def test_output_file_written(
        self, mock_catalog, mock_enabled, runner, simple_input_file, tmp_path
    ):
        """Test that --output-file writes to a file instead of stdout."""
        mock_catalog.return_value = SAMPLE_CONTROLS
        mock_enabled.return_value = []
        output_path = str(tmp_path / "report.json")

        result = runner.invoke(
            main, ["--no-interactive", "--input-file", simple_input_file, "--output-file", output_path]
        )

        assert result.exit_code == 0
        assert os.path.exists(output_path)
        with open(output_path) as f:
            report = json.load(f)
        assert report["summary"]["totalRecommended"] == 3
