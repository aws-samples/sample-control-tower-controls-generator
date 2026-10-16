"""Property-based test for the framework filter opt-in behavior.

This module validates that when no
Framework is requested (an unset ``FrameworkFilterConfig``), the pure
``filter_by_framework`` function is opt-out and returns every input control
unchanged, attaching no framework attribution.

Hypothesis strategies are defined locally on purpose so this test file is
self-contained (no shared conftest or strategy module).
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from control_tower_controls_generator.framework_filter import filter_by_framework
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    FrameworkAssociation,
    FrameworkFilterConfig,
    MappedControl,
)


# --- Local Hypothesis strategies -------------------------------------------

# Control ARNs: non-empty strings so every generated control has a lookup key.
_arns = st.text(min_size=1, max_size=40)

_control_implementations = st.builds(
    ControlImplementation,
    type=st.sampled_from(["SERVICE_CONTROL_POLICY", "AWS_CONFIG_RULE", "CLOUD_FORMATION_GUARD_RULE"]),
    identifier=st.none() | st.text(max_size=20),
)

_controls = st.builds(
    Control,
    arn=_arns,
    name=st.text(max_size=30),
    description=st.text(max_size=40),
    behavior=st.sampled_from(["PREVENTIVE", "DETECTIVE", "PROACTIVE"]),
    severity=st.sampled_from(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    implementation=_control_implementations,
    governed_resources=st.lists(st.text(max_size=15), max_size=3),
)

# MappedControl generated without framework_associations so the default empty
# list applies: the opt-in path must not add any attribution to these.
_mapped_controls = st.builds(
    MappedControl,
    control=_controls,
    matched_resource_types=st.lists(st.text(max_size=15), max_size=3),
)

_framework_associations = st.builds(
    FrameworkAssociation,
    name=st.text(max_size=25),
    item=st.text(max_size=25),
)

# An arbitrary framework-association index: keys are control ARNs, values are
# lists of associations (repeated ARNs are impossible in a dict, but the values
# exercise the many-to-many shape).
_mapping_indexes = st.dictionaries(
    keys=_arns,
    values=st.lists(_framework_associations, max_size=4),
    max_size=6,
)


@settings(max_examples=100)
@given(
    controls=st.lists(_mapped_controls, max_size=12),
    mapping_index=_mapping_indexes,
)
def test_opt_in_unset_framework_includes_all_controls(controls, mapping_index):
    # Opt-in — unset framework includes all controls
    config = FrameworkFilterConfig(frameworks=None)

    # Snapshot the input to detect any mutation after filtering.
    input_arns = [mapped.control.arn for mapped in controls]
    input_association_snapshot = [
        list(mapped.framework_associations) for mapped in controls
    ]

    result = filter_by_framework(controls, mapping_index, config)

    # Output length equals input length: no control is dropped.
    assert len(result) == len(controls)

    # The same controls, in the same order (by ARN), are returned unchanged.
    assert [mapped.control.arn for mapped in result] == input_arns
    assert result == controls

    # No framework attribution is attached to any returned control.
    for mapped in result:
        assert mapped.framework_associations == []

    # The input controls are not mutated by the call.
    assert [mapped.control.arn for mapped in controls] == input_arns
    assert [
        list(mapped.framework_associations) for mapped in controls
    ] == input_association_snapshot
