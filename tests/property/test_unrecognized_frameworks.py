"""Property-based test for Unrecognized framework detection.

This is a dedicated test module for the framework filter's unrecognized-framework detection.
Hypothesis strategies are defined locally here (no shared conftest or strategy
module) so the test is fully self-contained.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from control_tower_controls_generator.framework_filter import (
    filter_by_framework,
    find_unrecognized_frameworks,
)
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    MappedControl,
    FrameworkAssociation,
    FrameworkFilterConfig,
)


# A small, fixed pool of framework names shared between the generated index and
# the requested-name list so scenarios genuinely exercise both the recognized
# and unrecognized paths (rather than always producing unrecognized names).
FRAMEWORK_NAME_POOL = [
    "PCI-DSS-v4.0",
    "NIST-SP-800-53-r5",
    "CIS-v8.0",
    "HIPAA",
    "SOC2",
    "ISO-27001",
    "FedRAMP-Moderate",
]

_ITEM_STRATEGY = st.text(
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-",
    min_size=1,
    max_size=8,
)


def _make_mapped_control(arn: str) -> MappedControl:
    """Build a MappedControl for a given ARN.

    Only ``control.arn`` matters to the functions under test; the remaining
    fields are filled with valid, fixed placeholder values.
    """
    return MappedControl(
        control=Control(
            arn=arn,
            name="Placeholder control",
            description="Placeholder description",
            behavior="DETECTIVE",
            severity="MEDIUM",
            implementation=ControlImplementation(
                type="AWS::Config::ConfigRule", identifier=None
            ),
            governed_resources=[],
        ),
        matched_resource_types=["AWS::EC2::Instance"],
    )


def _recase(value: str, mode: str) -> str:
    """Re-case a string to exercise case-insensitive matching."""
    if mode == "lower":
        return value.lower()
    if mode == "upper":
        return value.upper()
    if mode == "swap":
        return value.swapcase()
    return value


@st.composite
def _scenarios(draw):
    """Generate (controls, mapping_index, requested_framework_names).

    - ``mapping_index`` maps unique control ARNs to non-empty lists of
      FrameworkAssociation values whose names are drawn from the shared pool
      (many-to-many is exercised via repeated names per ARN).
    - ``controls`` includes one MappedControl per indexed ARN, plus some extra
      controls whose ARNs are absent from the index (always dropped).
    - ``requested`` mixes pool names in arbitrary casing (some recognized, some
      not depending on the generated index) with novel names guaranteed to be
      unrecognized.
    """
    association = st.builds(
        FrameworkAssociation,
        name=st.sampled_from(FRAMEWORK_NAME_POOL),
        item=_ITEM_STRATEGY,
    )

    n_index = draw(st.integers(min_value=0, max_value=6))
    mapping_index: dict[str, list[FrameworkAssociation]] = {}
    for i in range(n_index):
        arn = f"arn:aws:controlcatalog:::control/idx{i}"
        mapping_index[arn] = draw(st.lists(association, min_size=1, max_size=4))

    controls = [_make_mapped_control(arn) for arn in mapping_index]
    n_extra = draw(st.integers(min_value=0, max_value=3))
    for j in range(n_extra):
        controls.append(
            _make_mapped_control(f"arn:aws:controlcatalog:::control/extra{j}")
        )

    recased_pool_name = st.builds(
        _recase,
        st.sampled_from(FRAMEWORK_NAME_POOL),
        st.sampled_from(["orig", "lower", "upper", "swap"]),
    )
    novel_name = st.builds(
        lambda n: f"ZZZ-UNKNOWN-{n}", st.integers(min_value=0, max_value=20)
    )
    requested = draw(
        st.lists(st.one_of(recased_pool_name, novel_name), min_size=1, max_size=6)
    )

    return controls, mapping_index, requested


@settings(max_examples=100)
@given(scenario=_scenarios())
def test_unrecognized_framework_detection(scenario):
    # Unrecognized framework detection
    controls, mapping_index, requested = scenario
    config = FrameworkFilterConfig(frameworks=requested)

    known_lower = {
        assoc.name.lower()
        for assocs in mapping_index.values()
        for assoc in assocs
    }

    # (a) find_unrecognized_frameworks returns exactly the requested names that
    # have no case-insensitive exact match among the association names present
    # in the index, preserving the original casing and request order.
    expected_unrecognized = [n for n in requested if n.lower() not in known_lower]
    assert find_unrecognized_frameworks(config, mapping_index) == expected_unrecognized

    # (b) filter_by_framework still retains the controls associated with the
    # recognized requested names. Unrecognized names cannot match any
    # association, so retention is driven entirely by the recognized names:
    # a control is retained iff at least one of its associations matches a
    # recognized requested name (case-insensitive exact).
    recognized_lower = {n.lower() for n in requested if n.lower() in known_lower}
    filtered = filter_by_framework(controls, mapping_index, config)
    filtered_arns = [mc.control.arn for mc in filtered]

    for control in controls:
        associated_lower = {
            assoc.name.lower()
            for assoc in mapping_index.get(control.control.arn, [])
        }
        associated_with_recognized = bool(associated_lower & recognized_lower)
        if associated_with_recognized:
            assert control.control.arn in filtered_arns
        else:
            assert control.control.arn not in filtered_arns

    # Each retained control carries at least one association, and every attached
    # association corresponds to a recognized requested name.
    for mc in filtered:
        assert mc.framework_associations
        assert all(
            assoc.name.lower() in recognized_lower
            for assoc in mc.framework_associations
        )
