"""Property-based tests for the resource-to-control mapper.

Covers two correctness properties of
``control_tower_controls_generator.control_mapper.map_resource_types_to_controls``:

* Resource-to-Control mapping correctness: a control appears in
  the output if and only if its GovernedResources array is non-empty and
  contains at least one input resource type as an exact string match.
* Mapped controls are deduplicated with all triggering resource
  types preserved: a control whose GovernedResources matches several input
  resource types appears exactly once, and its ``matched_resource_types``
  contains every input resource type that matched (and nothing else).

Each property is checked against an independent oracle computed locally from
the generated inputs. Controls are generated with unique ARNs so outputs can be
compared by ARN.

Resource types are drawn from a small shared pool so that overlaps between the
input and GovernedResources are frequent. The pool deliberately includes
"near-miss" variants (different letter-case, surrounding whitespace) of real
identifiers to verify that matching is an exact string comparison rather than a
normalized one.

All Hypothesis strategies are defined locally in this module by design so the
file stays self-contained and does not collide with other parallel test tasks.
"""

import string

from hypothesis import given, settings
from hypothesis import strategies as st

from control_tower_controls_generator.control_mapper import (
    map_resource_types_to_controls,
)
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    MappedControl,
)


# --- Local Hypothesis strategies -------------------------------------------

_rt_segment = st.text(
    alphabet=string.ascii_letters + string.digits, min_size=1, max_size=10
)

# Realistic AWS resource type identifier, e.g. "AWS::EC2::Instance".
_aws_resource_type = st.builds(
    lambda service, resource: f"AWS::{service}::{resource}",
    _rt_segment,
    _rt_segment,
)


def _near_misses(resource_type: str) -> list[str]:
    """Strings that look like ``resource_type`` but are NOT an exact match."""
    variants = {
        resource_type.lower(),
        resource_type.upper(),
        f" {resource_type}",
        f"{resource_type} ",
    }
    variants.discard(resource_type)
    return sorted(variants)


@st.composite
def _resource_type_pool(draw) -> list[str]:
    """A small pool of distinct resource type strings, including near-misses.

    Drawing both the input and every control's GovernedResources from this
    shared pool makes matches (and non-matches between look-alike strings)
    common, so both directions of the "if and only if" are exercised.
    """
    base = draw(st.lists(_aws_resource_type, min_size=1, max_size=6, unique=True))
    pool = list(base)
    for rt in base:
        if draw(st.booleans()):
            pool.append(draw(st.sampled_from(_near_misses(rt))))
    # Preserve uniqueness (a near-miss could coincide with another base type).
    return list(dict.fromkeys(pool))


def _make_control(index: int, governed_resources: list[str]) -> Control:
    """Build a Control with a unique ARN and the given GovernedResources."""
    return Control(
        arn=f"arn:aws:controlcatalog:::control/c{index}",
        name=f"Control {index}",
        description="",
        behavior="PREVENTIVE",
        severity="HIGH",
        implementation=ControlImplementation(type="SERVICE_CONTROL_POLICY"),
        governed_resources=list(governed_resources),
    )


@st.composite
def _mapping_inputs(draw) -> tuple[list[str], list[Control]]:
    """Generate ``(resource_types, controls)`` drawn from a shared pool.

    * ``resource_types`` may be empty and may contain duplicates (the mapper
      should treat it as a set).
    * Each control has a unique ARN and a GovernedResources list of distinct
      entries drawn from the pool; the list may be empty to cover the
      exclusion rule for empty GovernedResources.
    """
    pool = draw(_resource_type_pool())
    resource_types = draw(st.lists(st.sampled_from(pool), min_size=0, max_size=10))
    num_controls = draw(st.integers(min_value=0, max_value=12))
    controls = [
        _make_control(
            i,
            draw(st.lists(st.sampled_from(pool), min_size=0, max_size=6, unique=True)),
        )
        for i in range(num_controls)
    ]
    return resource_types, controls


@st.composite
def _multi_match_inputs(draw) -> tuple[list[str], list[Control], str]:
    """Inputs guaranteed to contain a control matching 2+ input resource types.

    Returns ``(resource_types, controls, multi_arn)`` where ``multi_arn`` is the
    ARN of a control whose GovernedResources contains at least two distinct
    input resource types. Additional controls (some of which may also match)
    are mixed in around it, so the deduplication guarantee is checked in the
    presence of other matching and non-matching controls.
    """
    resource_types, controls = draw(_mapping_inputs())

    # At least two distinct input resource types the multi-match control governs.
    triggers = draw(
        st.lists(_aws_resource_type, min_size=2, max_size=5, unique=True)
    )
    # Extra governed entries that are NOT in the input (should not be reported).
    input_set = set(resource_types) | set(triggers)
    extras = [
        rt
        for rt in draw(st.lists(_aws_resource_type, min_size=0, max_size=3, unique=True))
        if rt not in input_set
    ]
    governed = draw(st.permutations(list(dict.fromkeys(triggers + extras))))

    # Input contains every trigger, possibly repeated, in shuffled order.
    repeats = draw(st.lists(st.sampled_from(triggers), min_size=0, max_size=4))
    full_input = draw(st.permutations(resource_types + triggers + repeats))

    multi_control = _make_control(len(controls), governed)
    position = draw(st.integers(min_value=0, max_value=len(controls)))
    all_controls = controls[:position] + [multi_control] + controls[position:]
    return list(full_input), all_controls, multi_control.arn


# --- Independent oracle ------------------------------------------------------


def _expected_matches(
    resource_types: list[str], controls: list[Control]
) -> dict[str, set[str]]:
    """Map each qualifying control ARN to its set of matched input resource types.

    A control qualifies iff its GovernedResources is non-empty and shares at
    least one exact string with the input resource types.
    """
    input_set = set(resource_types)
    expected: dict[str, set[str]] = {}
    for control in controls:
        if not control.governed_resources:
            continue
        matched = {gr for gr in control.governed_resources if gr in input_set}
        if matched:
            expected[control.arn] = matched
    return expected


def _arn_list(result: list[MappedControl]) -> list[str]:
    return [mc.control.arn for mc in result]


# ---


# For any set of resource types and any set of controls, a control appears in the mapping output if and only if its GovernedResources array contains at least one of the input resource types as an exact string match (and GovernedResources is non-empty)
@settings(max_examples=100)
@given(inputs=_mapping_inputs())
def test_mapping_includes_exactly_controls_with_matching_governed_resources(inputs):
    """A control is in the output iff its non-empty GovernedResources exactly matches an input type.

    """
    resource_types, controls = inputs
    input_set = set(resource_types)

    result = map_resource_types_to_controls(resource_types, controls)
    result_arns = set(_arn_list(result))

    # Exactly the qualifying controls appear (inclusion + exclusion combined).
    assert result_arns == set(_expected_matches(resource_types, controls))

    controls_by_arn = {c.arn: c for c in controls}
    for mc in result:
        # Output controls come from the catalog unchanged.
        assert mc.control is controls_by_arn[mc.control.arn]
        # A control with empty GovernedResources is never emitted.
        assert mc.control.governed_resources
        # At least one exact-string match exists.
        assert input_set.intersection(mc.control.governed_resources)

    for control in controls:
        exact_match = bool(input_set.intersection(control.governed_resources))
        # Membership is decided solely by exact string match.
        assert (control.arn in result_arns) == exact_match

    # Input resource types with no matching control never appear in
    # any output entry, and mapping them raises no error.
    all_governed = {gr for c in controls for gr in c.governed_resources}
    reported = {rt for mc in result for rt in mc.matched_resource_types}
    for rt in input_set - all_governed:
        assert rt not in reported


# ---


# For any set of resource types and controls where a single control's GovernedResources matches multiple input resource types, that control SHALL appear exactly once in the output, and its matchedResourceTypes list SHALL contain all input resource types that matched
@settings(max_examples=100)
@given(inputs=_multi_match_inputs())
def test_multi_match_control_appears_once_with_all_triggering_types(inputs):
    """A control matched by several input types is emitted once with every trigger preserved.

    """
    resource_types, controls, multi_arn = inputs
    input_set = set(resource_types)
    expected = _expected_matches(resource_types, controls)

    result = map_resource_types_to_controls(resource_types, controls)
    arns = _arn_list(result)

    # The multi-match control (2+ triggers by construction) appears exactly once.
    assert len(expected[multi_arn]) >= 2
    assert arns.count(multi_arn) == 1

    # Every mapped control appears exactly once (no duplicates in the output).
    assert len(arns) == len(set(arns))

    for mc in result:
        matched = mc.matched_resource_types
        # All triggering input resource types are preserved -- and only those.
        assert set(matched) == expected[mc.control.arn]
        # Each triggering type is listed once, despite repeats in the input.
        assert len(matched) == len(set(matched))
        # Every reported type is genuinely an input type governed by the control.
        for rt in matched:
            assert rt in input_set
            assert rt in mc.control.governed_resources
