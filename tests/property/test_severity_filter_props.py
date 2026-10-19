"""Property-based tests for the severity filter.

Covers the three filtering modes of
``control_tower_controls_generator.severity_filter.filter_by_severity``, which
together fully validate severity filtering correctness:

* No filter (both ``minimum`` and ``specific`` are None): every control passes
  through unchanged.
* Minimum severity level: exactly those controls whose severity rank is at or
  above the threshold survive, using the ordering LOW < MEDIUM < HIGH < CRITICAL.
* Specific severity list: exactly those controls whose severity is one of the
  requested levels survive.

Each mode is checked against an independent oracle (a locally defined severity
rank / membership computation) asserting both inclusion (every qualifying
control is kept) and exclusion (no disqualified control is kept).

All Hypothesis strategies are defined locally in this module by design so the
file stays self-contained and does not collide with other parallel test tasks.
Controls are generated with unique ARNs so filter outputs can be compared by
ARN set. The generated severities are drawn from the canonical set
["LOW", "MEDIUM", "HIGH", "CRITICAL"] but their letter-case is randomized (as
are the filter values) to exercise the implementation's case-insensitive
matching.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from control_tower_controls_generator.severity_filter import filter_by_severity
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    MappedControl,
    SeverityFilterConfig,
)


# --- Fixed input domains -----------------------------------------------------

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
BEHAVIORS = ["PREVENTIVE", "PROACTIVE", "DETECTIVE"]

# Independent oracle for the severity ordering LOW < MEDIUM < HIGH < CRITICAL.
# Defined locally (rather than importing SEVERITY_ORDER) so the test checks the
# implementation against an independent source of truth for the ranking.
_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# --- Helpers -----------------------------------------------------------------


def _arns(controls: list[MappedControl]) -> set[str]:
    """Reduce a list of mapped controls to the set of their control ARNs.

    ARNs are generated unique per example, so comparing by ARN set keeps the
    inclusion/exclusion comparisons well-defined regardless of ordering.
    """
    return {mc.control.arn for mc in controls}


def _cased_variants(severity: str) -> list[str]:
    """All letter-case renderings of a canonical severity used to exercise
    the implementation's ``.upper()`` normalization."""
    return [severity, severity.lower(), severity.upper(), severity.capitalize()]


# --- Strategies (local, self-contained) --------------------------------------

_arn_suffixes = st.text(alphabet="abcdef0123456789", min_size=4, max_size=10)

# A severity string whose semantic level is from the canonical set but whose
# letter-case is randomized (e.g. "high", "High", "HIGH", "Critical").
_cased_severity = st.sampled_from(SEVERITIES).flatmap(
    lambda s: st.sampled_from(_cased_variants(s))
)


@st.composite
def _controls(draw) -> list[MappedControl]:
    """Generate a list of mapped controls with unique ARNs and varied severities.

    Length may be zero to cover the empty-input edge case. Severity levels are
    drawn from the canonical set with randomized case so the filter's
    case-insensitive matching is exercised.
    """
    suffixes = draw(st.lists(_arn_suffixes, min_size=0, max_size=8, unique=True))

    controls: list[MappedControl] = []
    for suffix in suffixes:
        severity = draw(st.sampled_from(SEVERITIES))
        cased_severity = draw(st.sampled_from(_cased_variants(severity)))
        control = Control(
            arn=f"arn:aws:controlcatalog:::control/{suffix}",
            name=f"Control {suffix}",
            description="",
            behavior=draw(st.sampled_from(BEHAVIORS)),
            severity=cased_severity,
            implementation=ControlImplementation(type="SERVICE_CONTROL_POLICY"),
        )
        controls.append(MappedControl(control=control, matched_resource_types=[]))

    return controls


@st.composite
def _specific_severities(draw) -> list[str]:
    """A non-empty list of distinct severity levels (case randomized).

    Sizes from 1 to 4 cover both single-value and multi-value (comma-separated
    style, e.g. ["LOW", "CRITICAL"]) filter selections.
    """
    chosen = draw(
        st.lists(st.sampled_from(SEVERITIES), min_size=1, max_size=4, unique=True)
    )
    return [draw(st.sampled_from(_cased_variants(s))) for s in chosen]


# --- severity filter tests --------------------------------------------------------


# When no filter is specified, all controls pass through
@settings(max_examples=100)
@given(controls=_controls())
def test_no_filter_passes_all_controls_through(controls: list[MappedControl]):
    """No severity filter returns every control unchanged (no additions, no drops)."""
    config = SeverityFilterConfig()  # minimum=None, specific=None

    result = filter_by_severity(controls, config)

    # The output equals the input: same ARNs, same count, same order preserved.
    assert [mc.control.arn for mc in result] == [mc.control.arn for mc in controls]
    assert _arns(result) == _arns(controls)
    assert len(result) == len(controls)


# Minimum severity filter keeps exactly the controls at or above the threshold
@settings(max_examples=100)
@given(controls=_controls(), minimum=_cased_severity)
def test_minimum_severity_filter_keeps_at_or_above_threshold(
    controls: list[MappedControl], minimum: str
):
    """Minimum filter keeps exactly controls whose severity rank >= the minimum's rank.

    Uses the ordering LOW < MEDIUM < HIGH < CRITICAL via an independent rank
    oracle, asserting both inclusion (all qualifying controls kept) and
    exclusion (no lower-severity control kept).
    """
    config = SeverityFilterConfig(minimum=minimum)

    result = filter_by_severity(controls, config)
    result_arns = _arns(result)

    min_rank = _RANK[minimum.upper()]
    expected = {
        mc.control.arn
        for mc in controls
        if _RANK[mc.control.severity.upper()] >= min_rank
    }

    # Exactly the qualifying controls survive (inclusion + exclusion combined).
    assert result_arns == expected

    # Exclusion: nothing below the threshold survives.
    for mc in result:
        assert _RANK[mc.control.severity.upper()] >= min_rank

    # Inclusion: every qualifying input control is retained.
    for mc in controls:
        if _RANK[mc.control.severity.upper()] >= min_rank:
            assert mc.control.arn in result_arns


# Specific severity list filter keeps exactly the controls matching those levels
@settings(max_examples=100)
@given(controls=_controls(), specific=_specific_severities())
def test_specific_severity_list_filter_keeps_matching_levels(
    controls: list[MappedControl], specific: list[str]
):
    """Specific-list filter keeps exactly controls whose severity is in the requested set.

    Covers single- and multi-value selections (e.g. ["LOW", "CRITICAL"]) and
    asserts both inclusion (every matching control kept) and exclusion (no
    non-matching control kept) against an independent membership oracle.
    """
    config = SeverityFilterConfig(specific=specific)

    result = filter_by_severity(controls, config)
    result_arns = _arns(result)

    allowed = {s.upper() for s in specific}
    expected = {
        mc.control.arn for mc in controls if mc.control.severity.upper() in allowed
    }

    # Exactly the controls whose severity is in the requested set survive.
    assert result_arns == expected

    # Exclusion: nothing outside the requested set survives.
    for mc in result:
        assert mc.control.severity.upper() in allowed

    # Inclusion: every matching input control is retained.
    for mc in controls:
        if mc.control.severity.upper() in allowed:
            assert mc.control.arn in result_arns
