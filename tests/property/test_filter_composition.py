"""Property-based test for framework filter composition.

Validates that the framework, severity, and behavior filters compose as a
logical AND and are order-independent: applying any two filters yields the same
set of controls regardless of order, and that set equals the intersection of
the controls each filter retains on its own.

Hypothesis strategies are defined locally in this module on purpose (no shared
conftest/strategy module) so this test is fully self-contained.
"""

from typing import NamedTuple, Optional

from hypothesis import given, settings
from hypothesis import strategies as st

from control_tower_controls_generator.framework_filter import filter_by_framework
from control_tower_controls_generator.severity_filter import filter_by_severity
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    MappedControl,
    FrameworkAssociation,
    FrameworkFilterConfig,
    SeverityFilterConfig,
)


# --- Fixed input domains -----------------------------------------------------

FRAMEWORK_POOL = [
    "PCI-DSS-v4.0",
    "NIST-SP-800-53-r5",
    "CIS-v8.0",
    "HIPAA",
    "SOC-2",
]
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
BEHAVIORS = ["PREVENTIVE", "PROACTIVE", "DETECTIVE"]


class Scenario(NamedTuple):
    """A generated scenario exercising two active filters over shared controls."""

    controls: list[MappedControl]
    mapping_index: dict[str, list[FrameworkAssociation]]
    framework_config: FrameworkFilterConfig
    severity_config: SeverityFilterConfig
    allowed_behaviors: set[str]


# --- Helpers modeling the CLI's filters --------------------------------------


def _arns(controls: list[MappedControl]) -> set[str]:
    """Reduce a list of mapped controls to the set of their control ARNs.

    ``filter_by_framework`` returns fresh ``MappedControl`` instances (with
    attribution attached), so object identity cannot be used to compare filter
    outputs. Comparing by ARN keeps the composition/intersection comparison
    well-defined; ARNs are generated unique per scenario.
    """
    return {mc.control.arn for mc in controls}


def _apply_behavior(controls: list[MappedControl], allowed: set[str]) -> list[MappedControl]:
    """Model the CLI's behavior filter predicate exactly.

    Mirrors ``cli.py``: ``control.behavior.upper() in allowed_behaviors``.
    """
    allowed_upper = {b.upper() for b in allowed}
    return [mc for mc in controls if mc.control.behavior.upper() in allowed_upper]


# --- Strategies (local, self-contained) --------------------------------------

_arn_suffixes = st.text(alphabet="abcdef0123456789", min_size=4, max_size=10)


@st.composite
def _scenarios(draw) -> Scenario:
    suffixes = draw(
        st.lists(_arn_suffixes, min_size=0, max_size=8, unique=True)
    )

    controls: list[MappedControl] = []
    mapping_index: dict[str, list[FrameworkAssociation]] = {}
    for suffix in suffixes:
        arn = f"arn:aws:controlcatalog:::control/{suffix}"
        control = Control(
            arn=arn,
            name=f"Control {suffix}",
            description="",
            behavior=draw(st.sampled_from(BEHAVIORS)),
            severity=draw(st.sampled_from(SEVERITIES)),
            implementation=ControlImplementation(type="SERVICE_CONTROL_POLICY"),
        )
        controls.append(MappedControl(control=control, matched_resource_types=[]))

        assoc_names = draw(
            st.lists(st.sampled_from(FRAMEWORK_POOL), min_size=0, max_size=3)
        )
        if assoc_names:
            mapping_index[arn] = [
                FrameworkAssociation(name=name, item=f"{name}-{idx}")
                for idx, name in enumerate(assoc_names)
            ]

    # Requested frameworks: a non-empty selection from the pool, with the case
    # of each requested name randomized to exercise case-insensitive matching.
    requested_names = draw(
        st.lists(st.sampled_from(FRAMEWORK_POOL), min_size=1, max_size=4, unique=True)
    )
    requested = [
        draw(st.sampled_from([name, name.lower(), name.upper()]))
        for name in requested_names
    ]
    framework_config = FrameworkFilterConfig(frameworks=requested)

    # Severity filter: an active config, either a minimum level or a specific set.
    if draw(st.booleans()):
        severity_config = SeverityFilterConfig(minimum=draw(st.sampled_from(SEVERITIES)))
    else:
        specific = draw(
            st.lists(st.sampled_from(SEVERITIES), min_size=1, max_size=4, unique=True)
        )
        severity_config = SeverityFilterConfig(specific=specific)

    # Behavior filter: an active, non-empty set of allowed behaviors.
    allowed_behaviors = set(
        draw(st.lists(st.sampled_from(BEHAVIORS), min_size=1, max_size=3, unique=True))
    )

    return Scenario(
        controls=controls,
        mapping_index=mapping_index,
        framework_config=framework_config,
        severity_config=severity_config,
        allowed_behaviors=allowed_behaviors,
    )


# Filter composition is AND and order-independent
@settings(max_examples=100)
@given(scenario=_scenarios())
def test_property_4_filter_composition_is_and_and_order_independent(scenario: Scenario):
    controls = scenario.controls
    mapping_index = scenario.mapping_index

    def apply_framework(cs: list[MappedControl]) -> list[MappedControl]:
        return filter_by_framework(cs, mapping_index, scenario.framework_config)

    def apply_severity(cs: list[MappedControl]) -> list[MappedControl]:
        return filter_by_severity(cs, scenario.severity_config)

    def apply_behavior(cs: list[MappedControl]) -> list[MappedControl]:
        return _apply_behavior(cs, scenario.allowed_behaviors)

    # Each filter applied alone (compared by ARN set).
    framework_alone = _arns(apply_framework(controls))
    severity_alone = _arns(apply_severity(controls))
    behavior_alone = _arns(apply_behavior(controls))

    # Framework + severity: order-independent AND, equal to the intersection.
    fw_then_sev = _arns(apply_severity(apply_framework(controls)))
    sev_then_fw = _arns(apply_framework(apply_severity(controls)))
    assert fw_then_sev == sev_then_fw
    assert fw_then_sev == (framework_alone & severity_alone)

    # Framework + behavior: order-independent AND, equal to the intersection.
    fw_then_beh = _arns(apply_behavior(apply_framework(controls)))
    beh_then_fw = _arns(apply_framework(apply_behavior(controls)))
    assert fw_then_beh == beh_then_fw
    assert fw_then_beh == (framework_alone & behavior_alone)
