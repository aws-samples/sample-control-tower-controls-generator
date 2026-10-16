"""Property-based test for attribution omission.

Validates that when a report is
generated with framework attribution *disabled* (the default,
``include_framework_attribution=False``), the report contains no framework
attribution at all -- the JSON output has no non-null ``frameworks`` field for
any control, and the Markdown output has no ``Frameworks`` column. This holds
even when the source ``MappedControl`` values carry framework associations,
proving those associations are not rendered when the filter is inactive.

All Hypothesis strategies are defined locally in this module by design so this
file stays self-contained and does not collide with other parallel test tasks.
"""

import json

from hypothesis import given, settings
from hypothesis import strategies as st

from control_tower_controls_generator.report_generator import generate_report
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    FrameworkAssociation,
    MappedControl,
)


# --- Reserved framework-association vocabulary ------------------------------
# These association name/item tokens are deliberately drawn from a vocabulary
# that the control/arn/resource-type generators below can never produce (they
# use uppercase letters and dashes, while control-derived text is lowercase
# letters + digits, and the resource-type pool is fixed and contains none of
# them). So if any of these tokens shows up in a rendered report, it can only be
# because attribution leaked -- which this property forbids.
_ASSOC_NAMES = ["PCI-DSS-v4.0", "NIST-SP-800-53-r5", "CIS-v8.0", "HIPAA", "SOC-2"]
_ASSOC_ITEMS = ["ZZITEM-7.2.2", "ZZITEM-CM-5", "ZZITEM-A.9.2", "ZZITEM-1.1.1"]

# The exact controls-table header the report renders when attribution is absent
# (copied from report_generator._render_markdown). The presence of a
# "Frameworks" column would change this line.
_HEADER_NO_ATTRIBUTION = (
    "| Control Name | ARN | Behavior | Severity | "
    "Matched Resource Types | Accounts | Status |"
)

# JSON control keys expected when attribution is absent (back-compat shape).
_EXPECTED_JSON_KEYS = {
    "controlName",
    "controlArn",
    "behavior",
    "severity",
    "matchedResourceTypes",
    "accounts",
    "enablementStatus",
}


# --- Local Hypothesis strategies --------------------------------------------
# Lowercase letters + digits only: this keeps control-derived text free of the
# uppercase reserved tokens above and free of the literal "Frameworks", and free
# of the pipe/newline characters that would otherwise break the Markdown table.
_LOWER_DIGITS = "abcdefghijklmnopqrstuvwxyz0123456789"

_names = st.text(alphabet=_LOWER_DIGITS, min_size=1, max_size=20)
_descriptions = st.text(alphabet=_LOWER_DIGITS + " ", min_size=0, max_size=30)

# ARN-like keys built from a safe suffix; contain only lowercase/digits/":"/"/".
_arns = st.builds(
    lambda suffix: f"arn:aws:controlcatalog:::control/{suffix}",
    st.text(alphabet=_LOWER_DIGITS, min_size=1, max_size=16),
)

# A small fixed pool of realistic resource types. None contain "Frameworks",
# a pipe, a newline, or any reserved association token.
_resource_types = st.sampled_from(
    [
        "AWS::EC2::Instance",
        "AWS::S3::Bucket",
        "AWS::IAM::Role",
        "AWS::RDS::DBInstance",
        "AWS::Lambda::Function",
    ]
)

_control_implementations = st.builds(
    ControlImplementation,
    type=st.sampled_from(
        ["SERVICE_CONTROL_POLICY", "AWS_CONFIG_RULE", "CLOUD_FORMATION_GUARD_RULE"]
    ),
    identifier=st.none() | _names,
)

_controls = st.builds(
    Control,
    arn=_arns,
    name=_names,
    description=_descriptions,
    behavior=st.sampled_from(["PREVENTIVE", "DETECTIVE", "PROACTIVE"]),
    severity=st.sampled_from(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    implementation=_control_implementations,
    governed_resources=st.lists(_resource_types, max_size=3),
)

_framework_associations = st.builds(
    FrameworkAssociation,
    name=st.sampled_from(_ASSOC_NAMES),
    item=st.sampled_from(_ASSOC_ITEMS),
)

# MappedControls may carry framework associations: with attribution disabled the
# report must render none of them.
_mapped_controls = st.builds(
    MappedControl,
    control=_controls,
    matched_resource_types=st.lists(_resource_types, min_size=0, max_size=3),
    framework_associations=st.lists(_framework_associations, min_size=0, max_size=4),
)


# Attribution omitted when framework filter is inactive
@settings(max_examples=100)
@given(controls=st.lists(_mapped_controls, min_size=1, max_size=10))
def test_attribution_omitted_when_filter_inactive(controls):
    """With attribution disabled, no framework attribution appears in output."""
    # --- JSON: attribution explicitly disabled -------------------------------
    json_report = generate_report(
        mapped_controls=controls,
        enabled_controls=[],
        output_format="json",
        include_framework_attribution=False,
    )
    data = json.loads(json_report)

    # At least one control entry is rendered (input is non-empty).
    assert data["controls"], "expected at least one control entry in the report"
    for control in data["controls"]:
        # No non-null attribution field: the key is omitted entirely.
        assert "frameworks" not in control
        # Back-compatible shape: exactly the pre-framework-filter key set.
        assert set(control.keys()) == _EXPECTED_JSON_KEYS

    # --- Markdown: relying on the default (attribution disabled) -------------
    md_report = generate_report(
        mapped_controls=controls,
        enabled_controls=[],
        output_format="markdown",
    )
    lines = md_report.splitlines()
    # The one controls-table header. Control names are lowercase, so no data row
    # can start with "| Control Name |"; only the real header does.
    header_lines = [ln for ln in lines if ln.startswith("| Control Name |")]
    assert len(header_lines) == 1
    # The header has no Frameworks column and is identical to today's output.
    assert "Frameworks" not in header_lines[0]
    assert header_lines[0] == _HEADER_NO_ATTRIBUTION

    # --- No association data leaks into either rendering ---------------------
    # The controls above may carry associations; with attribution off, none of
    # the reserved association tokens may appear in the JSON or Markdown output.
    for token in _ASSOC_NAMES + _ASSOC_ITEMS:
        assert token not in json_report
        assert token not in md_report
