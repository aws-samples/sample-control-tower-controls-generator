"""Property-based tests for the report generator.

Covers four correctness properties of
``control_tower_controls_generator.report_generator.generate_report``:

* Output report alphabetical ordering: controls are listed in
  non-decreasing order by control name, and every matched control is listed.
* Report entry field completeness: each entry carries the control
  name, ARN, behavior, severity and matched resource types of its source
  control; when account-level data is available the entry also lists the
  accounts that contained the matched resource types.
* Enablement status determined by ARN membership: a control is
  "already enabled" iff its ARN is (exactly) in the enabled set, otherwise
  "not enabled"; with no OU (empty enabled list) every control is "not enabled".
* Summary count invariant: totalRecommended = alreadyEnabled +
  gaps, with alreadyEnabled / gaps equal to the per-status entry counts.

Assertions are made primarily against the parsed JSON output (camelCase keys),
which is the tool's default format. The summary-count test additionally cross-checks the
Markdown summary section.

Alphabetical ordering is checked with Python's native string comparison, which
is the ordering the generator uses (lexicographic by code point).

All Hypothesis strategies are defined locally in this module by design so the
file stays self-contained and does not collide with other parallel test tasks.
Mapped controls are generated with unique ARNs (as the mapper guarantees) so
report entries can be traced back to their source control by ARN.
"""

import json
import re
import string
from typing import Optional

from hypothesis import given, settings
from hypothesis import strategies as st

from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    EnabledControl,
    MappedControl,
)
from control_tower_controls_generator.report_generator import generate_report


# --- Fixed input domains -----------------------------------------------------

BEHAVIORS = ["PREVENTIVE", "DETECTIVE", "PROACTIVE"]
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
RESOURCE_TYPES = [
    "AWS::EC2::Instance",
    "AWS::S3::Bucket",
    "AWS::IAM::Role",
    "AWS::RDS::DBInstance",
    "AWS::Lambda::Function",
    "AWS::ECS::TaskDefinition",
]

ALREADY_ENABLED = "already enabled"
NOT_ENABLED = "not enabled"


# --- Local Hypothesis strategies ---------------------------------------------

# Control names: broad Unicode text (surrogates excluded so JSON round-trips),
# mixed case, punctuation and whitespace, to stress the ordering comparison.
_free_names = st.text(
    alphabet=st.characters(
        min_codepoint=32, max_codepoint=0x2FFF, blacklist_categories=("Cs",)
    ),
    min_size=1,
    max_size=30,
)

_arn_suffixes = st.text(
    alphabet=string.ascii_lowercase + string.digits, min_size=4, max_size=16
)

_account_ids = st.text(alphabet=string.digits, min_size=12, max_size=12)

_implementations = st.builds(
    ControlImplementation,
    type=st.sampled_from(
        ["SERVICE_CONTROL_POLICY", "AWS_CONFIG_RULE", "CLOUD_FORMATION_GUARD_RULE"]
    ),
    identifier=st.none() | st.text(alphabet=string.ascii_letters, max_size=10),
)


@st.composite
def _mapped_controls(draw, min_size: int = 0, max_size: int = 12) -> list[MappedControl]:
    """A list of mapped controls with unique ARNs.

    Names are drawn either from a small shared pool (so duplicate names, i.e.
    ordering ties, are common) or freely, and the list is emitted in random
    order so the generator's sorting is actually exercised. Each control has at
    least one distinct matched resource type, as produced by the mapper.
    """
    suffixes = draw(
        st.lists(_arn_suffixes, min_size=min_size, max_size=max_size, unique=True)
    )
    shared_names = draw(st.lists(_free_names, min_size=1, max_size=3))
    name_strategy = st.one_of(st.sampled_from(shared_names), _free_names)

    controls: list[MappedControl] = []
    for suffix in suffixes:
        control = Control(
            arn=f"arn:aws:controlcatalog:::control/{suffix}",
            name=draw(name_strategy),
            description=draw(st.text(max_size=20)),
            behavior=draw(st.sampled_from(BEHAVIORS)),
            severity=draw(st.sampled_from(SEVERITIES)),
            implementation=draw(_implementations),
            governed_resources=list(RESOURCE_TYPES),
        )
        matched = draw(
            st.lists(
                st.sampled_from(RESOURCE_TYPES), min_size=1, max_size=4, unique=True
            )
        )
        controls.append(MappedControl(control=control, matched_resource_types=matched))
    return controls


# Account mapping: None (no account-level data) or resourceType -> accountIds.
# Keys may cover only some resource types; account lists may overlap across
# types so de-duplication of the per-control union is exercised.
_account_mappings = st.none() | st.dictionaries(
    keys=st.sampled_from(RESOURCE_TYPES),
    values=st.lists(_account_ids, min_size=0, max_size=4),
    max_size=len(RESOURCE_TYPES),
)


def _near_miss_arns(arn: str) -> list[str]:
    """ARN look-alikes that are NOT an exact match (case/whitespace variants)."""
    variants = {arn.upper(), f" {arn}", f"{arn} ", f"{arn}/"}
    variants.discard(arn)
    return sorted(variants)


@st.composite
def _controls_and_enabled(draw) -> tuple[list[MappedControl], list[EnabledControl]]:
    """Mapped controls plus an enabled-controls list for the OU comparison.

    The enabled list mixes (a) exact ARNs of a random subset of the recommended
    controls, (b) near-miss look-alikes of recommended ARNs that must NOT count
    as enabled, and (c) unrelated ARNs; it may contain repeats and is shuffled.
    """
    controls = draw(_mapped_controls())
    arns = [mc.control.arn for mc in controls]

    enabled_subset = (
        draw(st.lists(st.sampled_from(arns), max_size=len(arns))) if arns else []
    )
    near_misses = (
        [
            draw(st.sampled_from(_near_miss_arns(a)))
            for a in draw(st.lists(st.sampled_from(arns), max_size=3))
        ]
        if arns
        else []
    )
    unrelated = [
        f"arn:aws:controltower:us-east-1::control/{s}"
        for s in draw(st.lists(_arn_suffixes, max_size=3))
    ]

    enabled_arns = draw(st.permutations(enabled_subset + near_misses + unrelated))
    return controls, [EnabledControl(control_arn=a) for a in enabled_arns]


# --- Helpers -------------------------------------------------------------------


def _json_report(
    controls: list[MappedControl],
    enabled: list[EnabledControl],
    account_mapping: Optional[dict[str, list[str]]] = None,
) -> dict:
    """Generate the report in JSON format and parse it."""
    return json.loads(
        generate_report(
            mapped_controls=controls,
            enabled_controls=enabled,
            account_mapping=account_mapping,
            output_format="json",
        )
    )


# ---


# For any set of matched controls, the Output_Report SHALL list controls in strictly non-decreasing alphabetical order by control name
@settings(max_examples=100)
@given(controls=_mapped_controls())
def test_report_lists_controls_in_alphabetical_order(controls):
    """Report entries are in non-decreasing name order and include every control.

    """
    report = _json_report(controls, enabled=[])
    names = [entry["controlName"] for entry in report["controls"]]

    # Non-decreasing by control name (ties allowed).
    for earlier, later in zip(names, names[1:]):
        assert earlier <= later

    # All matched controls are listed -- nothing dropped, added or duplicated.
    assert sorted(entry["controlArn"] for entry in report["controls"]) == sorted(
        mc.control.arn for mc in controls
    )


# ---


# For any matched control in the Output_Report, the report entry SHALL contain the control name, control ARN, behavior type, severity, and matched resource types. When account-level data is available, the entry SHALL also include the list of accounts
@settings(max_examples=100)
@given(
    inputs=_controls_and_enabled(),
    account_mapping=_account_mappings,
)
def test_report_entries_contain_all_required_fields(inputs, account_mapping):
    """Each entry reproduces its source control's fields, plus accounts when available.

    """
    controls, enabled = inputs
    report = _json_report(controls, enabled, account_mapping)
    sources = {mc.control.arn: mc for mc in controls}

    assert len(report["controls"]) == len(controls)

    for entry in report["controls"]:
        # Required fields are present and non-null.
        for key in (
            "controlName",
            "controlArn",
            "behavior",
            "severity",
            "matchedResourceTypes",
        ):
            assert key in entry
            assert entry[key] is not None

        source = sources[entry["controlArn"]]
        assert entry["controlName"] == source.control.name
        assert entry["behavior"] == source.control.behavior
        assert entry["behavior"] in BEHAVIORS
        # Severity is displayed for every recommended control.
        assert entry["severity"] == source.control.severity
        assert entry["severity"] in SEVERITIES
        # The resource types that triggered the recommendation are all listed.
        assert sorted(entry["matchedResourceTypes"]) == sorted(
            source.matched_resource_types
        )

        # With account-level data, list the accounts that contained
        # the control's matched resource types; without it, no attribution.
        assert "accounts" in entry
        if account_mapping is None:
            assert entry["accounts"] is None
        else:
            expected_accounts = {
                acct
                for rt in source.matched_resource_types
                for acct in account_mapping.get(rt, [])
            }
            assert isinstance(entry["accounts"], list)
            assert set(entry["accounts"]) == expected_accounts
            assert len(entry["accounts"]) == len(set(entry["accounts"]))


# ---


# For any set of recommended control ARNs and any set of already-enabled control ARNs, a recommended control SHALL be categorized as "already enabled" if and only if its ARN exists in the enabled set; otherwise it SHALL be "not enabled"
@settings(max_examples=100)
@given(inputs=_controls_and_enabled())
def test_enablement_status_matches_exact_arn_membership(inputs):
    """Status is "already enabled" iff the control ARN is exactly in the enabled set.

    """
    controls, enabled = inputs
    enabled_set = {ec.control_arn for ec in enabled}

    report = _json_report(controls, enabled)

    assert len(report["controls"]) == len(controls)
    for entry in report["controls"]:
        expected = ALREADY_ENABLED if entry["controlArn"] in enabled_set else NOT_ENABLED
        assert entry["enablementStatus"] == expected


# When no OU is specified (empty enabled list), all controls SHALL be marked "not enabled"
@settings(max_examples=100)
@given(controls=_mapped_controls(), account_mapping=_account_mappings)
def test_all_controls_not_enabled_without_ou(controls, account_mapping):
    """With no OU comparison (empty enabled list) every control is "not enabled".

    """
    report = _json_report(controls, enabled=[], account_mapping=account_mapping)

    assert len(report["controls"]) == len(controls)
    for entry in report["controls"]:
        assert entry["enablementStatus"] == NOT_ENABLED
    assert report["summary"]["alreadyEnabled"] == 0
    assert report["summary"]["gaps"] == len(controls)


# ---

_MD_SUMMARY = {
    "totalRecommended": re.compile(r"^- \*\*Total Recommended\*\*: (\d+)$", re.M),
    "alreadyEnabled": re.compile(r"^- \*\*Already Enabled\*\*: (\d+)$", re.M),
    "gaps": re.compile(r"^- \*\*Gaps\*\*: (\d+)$", re.M),
}


# For any Output_Report, the summary SHALL satisfy: totalRecommended = alreadyEnabled + gaps, where alreadyEnabled equals the count of controls marked "already enabled" and gaps equals the count marked "not enabled"
@settings(max_examples=100)
@given(inputs=_controls_and_enabled(), account_mapping=_account_mappings)
def test_summary_counts_are_consistent(inputs, account_mapping):
    """Summary totals agree with each other and with the per-entry statuses.

    """
    controls, enabled = inputs
    report = _json_report(controls, enabled, account_mapping)
    summary = report["summary"]
    statuses = [entry["enablementStatus"] for entry in report["controls"]]

    assert summary["totalRecommended"] == summary["alreadyEnabled"] + summary["gaps"]
    assert summary["alreadyEnabled"] == statuses.count(ALREADY_ENABLED)
    assert summary["gaps"] == statuses.count(NOT_ENABLED)
    assert summary["totalRecommended"] == len(report["controls"]) == len(controls)

    # The Markdown rendering reports the same summary counts.
    markdown = generate_report(
        mapped_controls=controls,
        enabled_controls=enabled,
        account_mapping=account_mapping,
        output_format="markdown",
    )
    for key, pattern in _MD_SUMMARY.items():
        match = pattern.search(markdown)
        assert match is not None, f"missing Markdown summary line for {key}"
        assert int(match.group(1)) == summary[key]
