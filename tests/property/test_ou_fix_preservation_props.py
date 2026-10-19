"""Property-based preservation tests for the no-OU path (Property 4).

Feature: ou-id-parameter-case-fix. Covers Property 4 from the design document:
for any invocation where the bug condition does NOT hold -- that is, no
``--organizational-unit`` is supplied -- the code SHALL produce a report
byte-identical to the original code's report for both output formats, SHALL
exit 0, and SHALL make no Control Tower or Organizations API call.

Note on the one retained requirement tag: ``test_no_ou_report_bytes_match_baseline``
keeps its docstring verbatim (tag included) because Hypothesis derandomize
derives its generated example set from the function's source digest -- editing
that docstring drifts the set away from the checked-in pre-fix baseline, which
cannot be re-recorded on pre-fix code. Every other requirement tag in this file
has been removed.

Observation-first methodology
----------------------------
These tests are recorded against the **UNFIXED**
``enabled_controls_retriever.py`` and compared against that recording after the
fix lands. The baseline artifact is
``tests/property/baselines/no_ou_report_baseline.json`` and it is checked in on
purpose: once the fix lands the original no-OU report bytes are no longer
observable, so the recording is the only remaining evidence of what has to be
preserved.

Two modes:

* **Record** (one-off, unfixed code only)::

      OU_FIX_RECORD_BASELINE=1 python -m pytest tests/property/test_ou_fix_preservation_props.py -v

  Observed outcomes are collected in memory and flushed to the baseline
  artifact at interpreter exit.

* **Assert** (the default, and what CI and task 8.9 run)::

      python -m pytest tests/property/test_ou_fix_preservation_props.py -v

  Every observed outcome is compared against the recorded entry. A drawn key
  that is absent from the baseline FAILS loudly rather than being skipped or
  ``assume``-d past, because a silently-skipped key is indistinguishable from a
  preserved one.

Reproducibility
---------------
``derandomize=True`` fixes the example set for a given Hypothesis version and
test source, and ``database=None`` keeps the example database from replaying
shrunk examples that were never recorded (those would surface as spurious
"missing baseline key" failures and mask the real regression). Both ``json``
and ``markdown`` are additionally pinned with explicit ``@example`` cases so
neither format is merely covered probabilistically. The interpreter and
Hypothesis version used for the recording are stored in the artifact's
``metadata`` block; task 8.9 must re-run with the same ones or the example set
drifts and the byte comparison compares different draws. The recording is also
platform-coupled: ``write_output`` opens the report in text mode, so the on-disk
bytes carry the recording platform's newline.

Offline by construction: the control catalog and the framework mappings are
supplied by the small deterministic fixture below (a full real catalog is large
and non-deterministic, so it cannot back a checked-in baseline), and
``enabled_controls_retriever.boto3`` is replaced with a stub that records every
``client(...)`` construction attempt.

All Hypothesis strategies are defined locally in this module by design so the
file stays self-contained and does not collide with other parallel test tasks.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import os
import platform
import sys
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import hypothesis
from click.testing import CliRunner
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from control_tower_controls_generator import cli as cli_module
from control_tower_controls_generator import (
    enabled_controls_retriever as enabled_controls_retriever_module,
)
from control_tower_controls_generator.cli import AUTH_ERROR_CODES, main
from control_tower_controls_generator.enabled_controls_retriever import (
    retrieve_enabled_controls,
)
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    FrameworkAssociation,
)


# --- Baseline artifact -----------------------------------------------------

BASELINE_DIR = Path(__file__).parent / "baselines"
BASELINE_PATH = BASELINE_DIR / "no_ou_report_baseline.json"

RECORD_MODE = os.environ.get("OU_FIX_RECORD_BASELINE") == "1"

SECTION_REPORTS = "no_ou_reports"
SECTION_EXIT_CODES = "other_exit_codes"

_MAX_EXAMPLES = 100

_RECORD_COMMAND = (
    "OU_FIX_RECORD_BASELINE=1 python -m pytest "
    "tests/property/test_ou_fix_preservation_props.py -v"
)

# Outcomes observed during a record-mode run, flushed at interpreter exit.
_RECORDED: dict[str, dict[str, Any]] = {SECTION_REPORTS: {}, SECTION_EXIT_CODES: {}}


def _empty_envelope() -> dict[str, Any]:
    return {"metadata": {}, SECTION_REPORTS: {}, SECTION_EXIT_CODES: {}}


def _read_baseline() -> dict[str, Any]:
    if not BASELINE_PATH.exists():
        return _empty_envelope()
    with open(BASELINE_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _metadata() -> dict[str, Any]:
    """Provenance of the recording, so task 8.9 can match the environment."""
    return {
        "feature": "ou-id-parameter-case-fix",
        "property": "4 - Preservation: No OU Supplied Is Byte-Identical",
        "recorded_against": (
            "UNFIXED src/control_tower_controls_generator/"
            "enabled_controls_retriever.py"
        ),
        "python": platform.python_version(),
        "python_executable_platform": sys.platform,
        "hypothesis": hypothesis.__version__,
        "click": _pkg_version("click"),
        "hypothesis_settings": {
            "max_examples": _MAX_EXAMPLES,
            "derandomize": True,
            "database": None,
        },
        "record_command": _RECORD_COMMAND,
    }


_BASELINE: dict[str, Any] = _read_baseline()


def _flush_baseline() -> None:
    """Merge record-mode observations into the checked-in baseline artifact."""
    if not RECORD_MODE:
        return
    if not any(_RECORDED.values()):
        return

    envelope = _read_baseline()
    envelope["metadata"] = _metadata()
    for section, entries in _RECORDED.items():
        merged = dict(envelope.get(section) or {})
        merged.update(entries)
        envelope[section] = dict(sorted(merged.items()))

    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    with open(BASELINE_PATH, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(envelope, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


atexit.register(_flush_baseline)


def _canonical_key(scenario: dict[str, Any]) -> str:
    """Canonical, stable serialization of the drawn options."""
    return json.dumps(scenario, sort_keys=True, separators=(",", ":"))


def _baseline_entry(section: str, key: str) -> dict[str, Any]:
    """Look up a recorded outcome, failing loudly when it is absent."""
    entries = _BASELINE.get(section) or {}
    if key not in entries:
        recorded = _BASELINE.get("metadata") or {}
        raise AssertionError(
            f"No recorded baseline for {section}[{key}].\n"
            f"Baseline artifact: {BASELINE_PATH}\n"
            f"Recorded with: python "
            f"{recorded.get('python', '<unrecorded>')} / hypothesis "
            f"{recorded.get('hypothesis', '<unrecorded>')}\n"
            f"Running with:  python {platform.python_version()} / hypothesis "
            f"{hypothesis.__version__}\n"
            "A missing key means the generated example set drifted (different "
            "interpreter, different Hypothesis version, or edited strategies) "
            "or the baseline was never recorded. Property 4 cannot be checked "
            "against an unrecorded example, so this is a hard failure rather "
            "than a skip. Re-record on UNFIXED code only, with:\n"
            f"  {_RECORD_COMMAND}"
        )
    return entries[key]


def _record_or_assert(section: str, key: str, observed: dict[str, Any]) -> None:
    """Record ``observed`` in record mode, else assert it against the baseline."""
    if RECORD_MODE:
        _RECORDED[section][key] = observed
        return

    expected = _baseline_entry(section, key)

    # Report bytes first: that is the byte-identity claim of Property 4. The
    # digest is compared before the text so a mismatch reports a short diff
    # before dumping two full reports.
    if "sha256" in expected or "sha256" in observed:
        line_endings_only = (
            observed.get("sha256") != expected.get("sha256")
            and observed.get("sha256_normalized") == expected.get("sha256_normalized")
        )
        assert observed.get("sha256") == expected.get("sha256"), (
            f"Report bytes changed for {section}[{key}]:\n"
            f"  recorded sha256: {expected.get('sha256')}\n"
            f"  observed sha256: {observed.get('sha256')}\n"
            + (
                "  Line endings alone differ; the report content is unchanged. "
                "The baseline was recorded on "
                f"{(_BASELINE.get('metadata') or {}).get('python_executable_platform')} "
                f"and is running on {sys.platform}. write_output writes in text "
                "mode, so the on-disk bytes carry the platform's newline; "
                "re-run on the recording platform."
                if line_endings_only
                else "  The report content itself differs."
            )
        )
        assert observed.get("report") == expected.get("report"), (
            f"Report text changed for {section}[{key}] despite matching digests."
        )

    for field in sorted(set(expected) | set(observed)):
        if field in ("sha256", "sha256_normalized", "report"):
            continue
        assert observed.get(field) == expected.get(field), (
            f"{field} changed for {section}[{key}]: "
            f"recorded {expected.get(field)!r}, observed {observed.get(field)!r}"
        )


# --- Deterministic offline fixture -----------------------------------------


def _control(
    suffix: str,
    name: str,
    behavior: str,
    severity: str,
    governed_resources: list[str],
) -> Control:
    return Control(
        arn=f"arn:aws:controlcatalog:::control/ct-fixture-{suffix}",
        name=name,
        description=f"Fixture control {suffix} for the no-OU preservation baseline.",
        behavior=behavior,
        severity=severity,
        implementation=ControlImplementation(
            type="AWS::CloudFormation::Type::HOOK",
            identifier=f"AWS-GR_FIXTURE_{suffix.upper()}",
        ),
        governed_resources=governed_resources,
    )


# A small catalog rather than the full 1620-control catalog keeps the checked-in
# baseline reviewable. The last entry has no governed resources so the mapper's
# "excluded" branch is exercised on every example.
FIXTURE_CATALOG: list[Control] = [
    _control(
        "0001",
        "Alpha Enforce EC2 IMDSv2",
        "PREVENTIVE",
        "CRITICAL",
        ["AWS::EC2::Instance", "AWS::EC2::SecurityGroup"],
    ),
    _control(
        "0002",
        "Beta Detect Public S3 Buckets",
        "DETECTIVE",
        "HIGH",
        ["AWS::S3::Bucket"],
    ),
    _control(
        "0003",
        "Gamma Require Lambda VPC Attachment",
        "PROACTIVE",
        "MEDIUM",
        ["AWS::Lambda::Function", "AWS::EC2::SecurityGroup"],
    ),
    _control(
        "0004",
        "Delta Encrypt RDS Storage",
        "PREVENTIVE",
        "HIGH",
        ["AWS::RDS::DBInstance"],
    ),
    _control(
        "0005",
        "Epsilon Detect Wildcard IAM Policies",
        "DETECTIVE",
        "LOW",
        ["AWS::IAM::Role"],
    ),
    _control(
        "0006",
        "Zeta Rotate KMS Keys",
        "DETECTIVE",
        "MEDIUM",
        ["AWS::KMS::Key"],
    ),
    _control(
        "0007",
        "Eta Restrict Root User Access",
        "PREVENTIVE",
        "CRITICAL",
        ["AWS::IAM::Role", "AWS::S3::Bucket"],
    ),
    _control(
        "0008",
        "Theta Ungoverned Control",
        "DETECTIVE",
        "LOW",
        [],
    ),
]

# Framework associations keyed by control ARN, the shape
# ``retrieve_control_mappings`` returns. "Epsilon" is deliberately absent so an
# active framework filter drops a control that the resource-type mapping kept.
FIXTURE_MAPPING_INDEX: dict[str, list[FrameworkAssociation]] = {
    "arn:aws:controlcatalog:::control/ct-fixture-0001": [
        FrameworkAssociation(name="PCI-DSS-v4.0", item="1.2.3"),
        FrameworkAssociation(name="NIST-SP-800-53-r5", item="AC-2"),
    ],
    "arn:aws:controlcatalog:::control/ct-fixture-0002": [
        FrameworkAssociation(name="PCI-DSS-v4.0", item="3.4.1"),
    ],
    "arn:aws:controlcatalog:::control/ct-fixture-0003": [
        FrameworkAssociation(name="NIST-SP-800-53-r5", item="SC-7"),
    ],
    "arn:aws:controlcatalog:::control/ct-fixture-0004": [
        FrameworkAssociation(name="CIS-AWS-Benchmark-v1.4.0", item="2.3.1"),
    ],
    "arn:aws:controlcatalog:::control/ct-fixture-0006": [
        FrameworkAssociation(name="NIST-SP-800-53-r5", item="SC-12"),
    ],
    "arn:aws:controlcatalog:::control/ct-fixture-0007": [
        FrameworkAssociation(name="PCI-DSS-v4.0", item="8.3.1"),
        FrameworkAssociation(name="CIS-AWS-Benchmark-v1.4.0", item="1.7"),
    ],
}

# Fixed account IDs per resource type, so the Config-aggregator input form (the
# only form that yields an account mapping) stays deterministic.
ACCOUNTS_BY_RESOURCE_TYPE: dict[str, tuple[str, ...]] = {
    "AWS::EC2::Instance": ("111111111111", "222222222222"),
    "AWS::EC2::SecurityGroup": ("111111111111",),
    "AWS::S3::Bucket": ("333333333333",),
    "AWS::Lambda::Function": ("222222222222", "444444444444"),
    "AWS::RDS::DBInstance": ("555555555555",),
    "AWS::IAM::Role": ("111111111111",),
    "AWS::KMS::Key": ("666666666666",),
    "AWS::DynamoDB::Table": ("777777777777",),
}


# --- Local Hypothesis strategies -------------------------------------------

# "AWS::DynamoDB::Table" is governed by no fixture control, so drawn sets can
# legitimately match nothing and exercise the empty-report branch.
_RESOURCE_TYPES = tuple(ACCOUNTS_BY_RESOURCE_TYPE)
_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_BEHAVIORS = ("PREVENTIVE", "DETECTIVE", "PROACTIVE")
_KNOWN_FRAMEWORKS = ("PCI-DSS-v4.0", "NIST-SP-800-53-r5", "CIS-AWS-Benchmark-v1.4.0")
# Requested but absent from the index, so the "unrecognized framework" warning
# path is part of the recorded baseline too.
_UNKNOWN_FRAMEWORKS = ("Not-A-Framework-v9",)

_resource_type_sets = st.lists(
    st.sampled_from(_RESOURCE_TYPES),
    min_size=1,
    max_size=len(_RESOURCE_TYPES),
    unique=True,
)

# A single level is the "minimum severity" form; a comma list is the "specific
# levels" form. Both are accepted by validate_severity_filter.
_severity_filters = st.one_of(
    st.none(),
    st.sampled_from(_SEVERITIES),
    st.lists(st.sampled_from(_SEVERITIES), min_size=2, max_size=4, unique=True).map(
        ",".join
    ),
)

_behavior_filters = st.one_of(
    st.none(),
    st.lists(st.sampled_from(_BEHAVIORS), min_size=1, max_size=3, unique=True).map(
        ",".join
    ),
)

_framework_filters = st.one_of(
    st.none(),
    st.lists(
        st.sampled_from(_KNOWN_FRAMEWORKS + _UNKNOWN_FRAMEWORKS),
        min_size=1,
        max_size=3,
        unique=True,
    ).map(",".join),
)


@st.composite
def _no_ou_invocations(draw) -> dict[str, Any]:
    """Generate a CLI invocation that supplies no ``--organizational-unit``."""
    return {
        "mode": "non-interactive",
        "input_format": draw(st.sampled_from(("array", "aggregator"))),
        "resource_types": draw(_resource_type_sets),
        "output_format": draw(st.sampled_from(("json", "markdown"))),
        "severity_filter": draw(_severity_filters),
        "behavior_filter": draw(_behavior_filters),
        "framework": draw(_framework_filters),
    }


def _scenario(**overrides: Any) -> dict[str, Any]:
    """Build an explicit scenario with the same shape the strategy produces."""
    scenario: dict[str, Any] = {
        "mode": "non-interactive",
        "input_format": "array",
        "resource_types": list(_RESOURCE_TYPES),
        "output_format": "json",
        "severity_filter": None,
        "behavior_filter": None,
        "framework": None,
    }
    scenario.update(overrides)
    return scenario


# Explicit cases so both renderers are always covered rather than covered
# probabilistically: plain json, plain markdown, json with an account mapping
# and framework attribution, and markdown whose resource types match nothing
# (the empty-report branch).
_EXAMPLE_JSON = _scenario(output_format="json")
_EXAMPLE_MARKDOWN = _scenario(output_format="markdown")
_EXAMPLE_JSON_RICH = _scenario(
    input_format="aggregator",
    output_format="json",
    severity_filter="HIGH,CRITICAL",
    behavior_filter="PREVENTIVE,DETECTIVE",
    framework="PCI-DSS-v4.0,Not-A-Framework-v9",
)
_EXAMPLE_MARKDOWN_NO_MATCH = _scenario(
    output_format="markdown",
    resource_types=["AWS::DynamoDB::Table"],
)


# --- Invocation harness ----------------------------------------------------


def _write_input_file(scenario: dict[str, Any]) -> str:
    """Write the input file for a scenario into the current directory."""
    resource_types = scenario["resource_types"]

    if scenario["input_format"] == "aggregator":
        rows = [
            json.dumps({"resourceType": rt, "accountId": account_id}, sort_keys=True)
            for rt in resource_types
            for account_id in ACCOUNTS_BY_RESOURCE_TYPE[rt]
        ]
        payload = json.dumps(
            {
                "QueryInfo": {
                    "SelectFields": [{"Name": "resourceType"}, {"Name": "accountId"}]
                },
                "Results": rows,
            },
            indent=2,
        )
        name = "input-aggregator.json"
    else:
        payload = json.dumps(resource_types, indent=2)
        name = "input-array.json"

    Path(name).write_text(payload, encoding="utf-8")
    return name


def _cli_args(scenario: dict[str, Any], input_path: str, output_path: str) -> list[str]:
    args = [
        "--no-interactive",
        "--input-file",
        input_path,
        "--output-format",
        scenario["output_format"],
        "--output-file",
        output_path,
    ]
    if scenario["severity_filter"] is not None:
        args += ["--severity-filter", scenario["severity_filter"]]
    if scenario["behavior_filter"] is not None:
        args += ["--behavior-filter", scenario["behavior_filter"]]
    if scenario["framework"] is not None:
        args += ["--framework", scenario["framework"]]
    return args


def _stderr_lines(result: Any) -> list[str]:
    """Deterministic stderr lines: the absolute save path is machine-specific."""
    return [
        line
        for line in result.stderr.splitlines()
        if line and not line.startswith("Report saved to ")
    ]


def _client_services(boto3_stub: MagicMock) -> list[Optional[str]]:
    """Service names every ``boto3.client(...)`` attempt asked for."""
    services: list[Optional[str]] = []
    for call in boto3_stub.client.call_args_list:
        if call.args:
            services.append(call.args[0])
        else:
            services.append(call.kwargs.get("service_name"))
    return services


def _assert_no_enabled_controls_api_call(
    enabled_spy: MagicMock, boto3_stub: MagicMock
) -> None:
    """The no-OU path must not reach the retriever or construct its clients."""
    assert not enabled_spy.called, (
        "cli.retrieve_enabled_controls was invoked on the no-OU path "
        f"with {enabled_spy.call_args_list!r}"
    )
    services = _client_services(boto3_stub)
    assert "controltower" not in services, (
        f"a controltower client was constructed on the no-OU path: {services!r}"
    )
    assert "organizations" not in services, (
        f"an organizations client was constructed on the no-OU path: {services!r}"
    )
    assert services == [], (
        f"enabled_controls_retriever.boto3.client was called on the no-OU path: "
        f"{services!r}"
    )


def _run_no_ou(scenario: dict[str, Any]) -> dict[str, Any]:
    """Run the CLI with no OU supplied and return the observed outcome.

    ``cli.retrieve_enabled_controls`` is wrapped rather than stubbed out, so an
    unexpected invocation would run the real retriever against the stubbed
    ``boto3`` and be caught twice over: once by the spy and once by the
    client-construction assertion.
    """
    runner = CliRunner()
    enabled_spy = MagicMock(wraps=retrieve_enabled_controls)
    boto3_stub = MagicMock(name="enabled_controls_retriever.boto3")
    output_path = "report.out"

    with runner.isolated_filesystem():
        input_path = _write_input_file(scenario)

        with (
            patch.object(
                cli_module,
                "retrieve_control_catalog",
                return_value=list(FIXTURE_CATALOG),
            ),
            patch.object(
                cli_module,
                "retrieve_control_mappings",
                return_value=dict(FIXTURE_MAPPING_INDEX),
            ),
            patch.object(cli_module, "retrieve_enabled_controls", enabled_spy),
            patch.object(enabled_controls_retriever_module, "boto3", boto3_stub),
        ):
            if scenario["mode"] == "interactive-empty-ou":
                # Prompts, in order: severity, behavior, framework, region, OU
                # (all left empty).
                result = runner.invoke(
                    main,
                    [
                        "--input-file",
                        input_path,
                        "--output-format",
                        scenario["output_format"],
                        "--output-file",
                        output_path,
                    ],
                    input="\n\n\n\n\n",
                )
            else:
                result = runner.invoke(
                    main, _cli_args(scenario, input_path, output_path)
                )

        report_path = Path(output_path)
        report_bytes = report_path.read_bytes() if report_path.exists() else None

    _assert_no_enabled_controls_api_call(enabled_spy, boto3_stub)

    assert result.exit_code == 0, (
        f"expected exit 0 on the no-OU path, got {result.exit_code}; "
        f"stderr={result.stderr!r}; exception={result.exception!r}"
    )
    assert report_bytes is not None, "no report was written on the no-OU path"

    report_text = report_bytes.decode("utf-8")

    return {
        "exit_code": result.exit_code,
        "report_bytes": len(report_bytes),
        # sha256 over the raw on-disk bytes: the byte-identity claim. write_output
        # writes in text mode, so these bytes carry the recording platform's
        # newline. sha256_normalized is recorded alongside purely so a line-ending
        # difference can be told apart from a content change in the failure text.
        "sha256": hashlib.sha256(report_bytes).hexdigest(),
        "sha256_normalized": hashlib.sha256(
            report_text.replace("\r\n", "\n").encode("utf-8")
        ).hexdigest(),
        "report": report_text,
        "stderr_lines": _stderr_lines(result),
        "enabled_controls_retriever_called": enabled_spy.called,
        "aws_clients_constructed": _client_services(boto3_stub),
    }


# --- Property 4: no-OU report bytes are byte-identical ---------------------


# Feature: ou-id-parameter-case-fix, Property 4: Preservation - No OU Supplied Is Byte-Identical
# NOTE: keep this test's docstring VERBATIM, including its requirement tag.
# Hypothesis derandomize derives the generated example set from the function's
# source digest, so any edit to the docstring drifts the set away from the
# checked-in pre-fix baseline (no_ou_report_baseline.json), which cannot be
# regenerated on pre-fix code. This is the one intentionally retained tag; see
# the note in the module docstring.
@settings(
    max_examples=_MAX_EXAMPLES,
    derandomize=True,
    database=None,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(scenario=_no_ou_invocations())
@example(scenario=_EXAMPLE_JSON)
@example(scenario=_EXAMPLE_MARKDOWN)
@example(scenario=_EXAMPLE_JSON_RICH)
@example(scenario=_EXAMPLE_MARKDOWN_NO_MATCH)
def test_no_ou_report_bytes_match_baseline(scenario):
    """No-OU runs reproduce the recorded report bytes and exit 0.

    **Validates: Requirements 3.1, 3.7**
    """
    observed = _run_no_ou(scenario)
    _record_or_assert(SECTION_REPORTS, _canonical_key(scenario), observed)


# Feature: ou-id-parameter-case-fix, Property 4: Preservation - No OU Supplied Is Byte-Identical
@settings(
    max_examples=_MAX_EXAMPLES,
    derandomize=True,
    database=None,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(scenario=_no_ou_invocations())
@example(scenario=_EXAMPLE_JSON)
@example(scenario=_EXAMPLE_MARKDOWN)
def test_no_ou_run_constructs_no_aws_client(scenario):
    """No-OU runs never reach the retriever or construct its AWS clients.

    ``_run_no_ou`` asserts this for every example of every test in this module;
    this test states it as its own property so the guarantee is named rather
    than incidental.
    """
    observed = _run_no_ou(scenario)

    assert observed["enabled_controls_retriever_called"] is False
    assert observed["aws_clients_constructed"] == []


def test_interactive_empty_ou_skips_retrieval():
    """Leaving the interactive OU prompt empty still skips retrieval, exit 0."""
    scenario = _scenario(mode="interactive-empty-ou")

    observed = _run_no_ou(scenario)

    assert observed["exit_code"] == 0
    assert observed["enabled_controls_retriever_called"] is False
    assert observed["aws_clients_constructed"] == []
    _record_or_assert(SECTION_REPORTS, _canonical_key(scenario), observed)


# --- Property 4: exit codes on paths unrelated to this retriever -----------

_INPUT_ERROR_KINDS = (
    "missing_input_file",
    "invalid_json",
    "empty_array",
    "unsupported_shape",
    "no_input_file_flag",
)

_AUTH_ERROR_CODES = tuple(sorted(AUTH_ERROR_CODES))
_NON_AUTH_ERROR_CODES = (
    "InternalServerException",
    "ResourceNotFoundException",
    "ServiceQuotaExceededException",
    "ThrottlingException",
    "ValidationException",
)
# BotoCoreError subclasses reachable from catalog retrieval. NoCredentialsError
# is an auth failure by cli._is_auth_error; the other two are not.
_CONNECTION_ERRORS = (
    "ConnectTimeoutError",
    "EndpointConnectionError",
    "NoCredentialsError",
)

_error_scenarios = st.one_of(
    st.sampled_from(_INPUT_ERROR_KINDS).map(
        lambda kind: {"failure": "input", "detail": kind}
    ),
    st.sampled_from(_AUTH_ERROR_CODES + _NON_AUTH_ERROR_CODES).map(
        lambda code: {"failure": "catalog_client_error", "detail": code}
    ),
    st.sampled_from(_CONNECTION_ERRORS).map(
        lambda name: {"failure": "catalog_connection_error", "detail": name}
    ),
)


def _catalog_failure(scenario: dict[str, Any]) -> RuntimeError:
    """Build the RuntimeError the catalog retriever raises, with __cause__ set.

    ``control_retriever`` wraps botocore failures in ``RuntimeError ... from e``,
    and ``cli._is_auth_error`` walks ``__cause__`` to choose exit 3 over 2, so
    the cause is what decides the code.
    """
    from botocore import exceptions as botocore_exceptions
    from botocore.exceptions import ClientError

    if scenario["failure"] == "catalog_client_error":
        cause: BaseException = ClientError(
            {
                "Error": {
                    "Code": scenario["detail"],
                    "Message": f"simulated {scenario['detail']}",
                }
            },
            "ListControls",
        )
        error = RuntimeError(
            f"AWS Control Catalog API error ({scenario['detail']}): "
            f"simulated {scenario['detail']}"
        )
    else:
        cause_cls = getattr(botocore_exceptions, scenario["detail"])
        if scenario["detail"] == "NoCredentialsError":
            cause = cause_cls()
        else:
            cause = cause_cls(endpoint_url="https://controlcatalog.us-east-1.amazonaws.com")
        error = RuntimeError(f"AWS Control Catalog connection error: {cause}")

    error.__cause__ = cause
    return error


def _run_error_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    """Run a failing CLI invocation that never touches enabled-controls."""
    runner = CliRunner()
    enabled_spy = MagicMock(wraps=retrieve_enabled_controls)
    boto3_stub = MagicMock(name="enabled_controls_retriever.boto3")
    output_path = "report.out"

    with runner.isolated_filesystem():
        args = ["--no-interactive", "--output-file", output_path]

        if scenario["failure"] == "input":
            kind = scenario["detail"]
            if kind == "missing_input_file":
                args += ["--input-file", "does-not-exist.json"]
            elif kind == "invalid_json":
                Path("bad.json").write_text("not valid json {{{", encoding="utf-8")
                args += ["--input-file", "bad.json"]
            elif kind == "empty_array":
                Path("empty.json").write_text("[]", encoding="utf-8")
                args += ["--input-file", "empty.json"]
            elif kind == "unsupported_shape":
                Path("shape.json").write_text('{"NotResults": 1}', encoding="utf-8")
                args += ["--input-file", "shape.json"]
            elif kind == "no_input_file_flag":
                pass
            else:  # pragma: no cover - guards against an unhandled kind
                raise AssertionError(f"unhandled input error kind: {kind}")
            catalog_kwargs: dict[str, Any] = {
                "return_value": list(FIXTURE_CATALOG)
            }
        else:
            Path("input.json").write_text(
                json.dumps(["AWS::EC2::Instance"]), encoding="utf-8"
            )
            args += ["--input-file", "input.json"]
            catalog_kwargs = {"side_effect": _catalog_failure(scenario)}

        with (
            patch.object(cli_module, "retrieve_control_catalog", **catalog_kwargs),
            patch.object(
                cli_module,
                "retrieve_control_mappings",
                return_value=dict(FIXTURE_MAPPING_INDEX),
            ),
            patch.object(cli_module, "retrieve_enabled_controls", enabled_spy),
            patch.object(enabled_controls_retriever_module, "boto3", boto3_stub),
        ):
            result = runner.invoke(main, args)

        output_created = Path(output_path).exists()

    _assert_no_enabled_controls_api_call(enabled_spy, boto3_stub)

    stderr = result.stderr
    if stderr.startswith("Authentication error:"):
        marker = "Authentication error"
    elif stderr.startswith("API error:"):
        marker = "API error"
    elif stderr.startswith("Error:"):
        marker = "Error"
    else:  # pragma: no cover - recorded so drift is visible rather than silent
        marker = "<none>"

    return {
        "exit_code": result.exit_code,
        "stderr_marker": marker,
        "output_file_created": output_created,
    }


# Feature: ou-id-parameter-case-fix, Property 4: Preservation - No OU Supplied Is Byte-Identical
@settings(
    max_examples=_MAX_EXAMPLES,
    derandomize=True,
    database=None,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(scenario=_error_scenarios)
@example(scenario={"failure": "input", "detail": "missing_input_file"})
@example(scenario={"failure": "input", "detail": "no_input_file_flag"})
@example(scenario={"failure": "catalog_client_error", "detail": "AccessDeniedException"})
@example(scenario={"failure": "catalog_client_error", "detail": "ThrottlingException"})
@example(scenario={"failure": "catalog_connection_error", "detail": "NoCredentialsError"})
@example(
    scenario={"failure": "catalog_connection_error", "detail": "EndpointConnectionError"}
)
def test_other_exit_codes_match_baseline(scenario):
    """Exit 1 for input errors and 2/3 for catalog failures are preserved.

    These paths never touch the enabled-controls retriever, so the fix must
    leave their exit codes and their "no report written" outcome alone.
    """
    observed = _run_error_scenario(scenario)

    if scenario["failure"] == "input":
        expected_exit = 1
    elif scenario["failure"] == "catalog_client_error":
        expected_exit = 3 if scenario["detail"] in AUTH_ERROR_CODES else 2
    else:
        expected_exit = 3 if scenario["detail"] == "NoCredentialsError" else 2

    assert observed["exit_code"] == expected_exit, (
        f"{scenario} produced exit {observed['exit_code']}, "
        f"expected {expected_exit}"
    )
    assert observed["output_file_created"] is False

    _record_or_assert(SECTION_EXIT_CODES, _canonical_key(scenario), observed)
