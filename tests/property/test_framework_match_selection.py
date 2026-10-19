"""Property-based test for framework match selection.

Validates that ``filter_by_framework`` retains exactly the controls that have at
least one framework association matching a requested name under case-insensitive
*exact* comparison, and drops all others. Matching must be case-insensitive and
must never treat a substring as a match.

All Hypothesis strategies are defined locally in this module by design so this
file stays self-contained and does not collide with other parallel test tasks.
"""

from hypothesis import given, settings, strategies as st

from control_tower_controls_generator.framework_filter import filter_by_framework
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    FrameworkAssociation,
    FrameworkFilterConfig,
    MappedControl,
)


# Framework-name pool for generated data. Deliberately includes substring pairs
# ("PCI" / "PCI-DSS-v4.0", "NIST" / "NIST-SP-800-53-r5") so the generator
# regularly exercises the "a substring must not match" behavior on its own.
_GEN_FRAMEWORK_NAMES = [
    "PCI",
    "PCI-DSS-v4.0",
    "NIST",
    "NIST-SP-800-53-r5",
    "CIS-v8.0",
    "HIPAA",
    "SOC-2",
    "ISO-27001",
]

# Reserved framework names used ONLY by the deterministic anchor controls. They
# never appear in generated data, so the anchors' outcomes are fixed regardless
# of what the generators draw.
_ANCHOR_CI_NAME = "ZeroFramework-CI-v1.0"  # has upper+lower letters => real case diff
_ANCHOR_SUBSTR_FULL = "ZeroFramework-Substr-Full-v1.0"  # the association's name
_ANCHOR_SUBSTR_REQ = "ZeroFramework-Substr"  # strict substring of the full name


def _make_control(arn: str) -> Control:
    """Build a minimal Control. Only ``arn`` matters for framework matching."""
    return Control(
        arn=arn,
        name=f"Control {arn.rsplit('/', 1)[-1]}",
        description="desc",
        behavior="DETECTIVE",
        severity="MEDIUM",
        implementation=ControlImplementation(type="AWS::Config::Rule", identifier=None),
        governed_resources=[],
    )


def _associations() -> st.SearchStrategy:
    """A list (possibly empty) of framework associations drawn from the pool."""
    association = st.builds(
        FrameworkAssociation,
        name=st.sampled_from(_GEN_FRAMEWORK_NAMES),
        item=st.sampled_from(["1.1", "7.2.2", "CM-5", "A.9.2", "3.4.1"]),
    )
    return st.lists(association, min_size=0, max_size=4)


@st.composite
def _requested_name(draw) -> str:
    """A requested framework name from the pool with a random case transform.

    Every transform only changes letter case, so ``value.lower()`` always equals
    the pool name's lower form. Requiring these to match forces the filter to be
    case-insensitive rather than case-sensitive.
    """
    base = draw(st.sampled_from(_GEN_FRAMEWORK_NAMES))
    transform = draw(
        st.sampled_from([str, str.upper, str.lower, str.swapcase, str.title])
    )
    return transform(base)


@st.composite
def _scenarios(draw):
    """Generate (controls, mapping_index, requested_names).

    - Controls have unique ARNs; each ARN may be absent from the index, present
      with no associations, or present with several (many-to-many) associations.
    - The index also gets a little noise: entries for ARNs with no control.
    - Requested names are non-empty and case-varied.
    """
    n = draw(st.integers(min_value=0, max_value=6))
    controls: list[MappedControl] = []
    mapping_index: dict[str, list[FrameworkAssociation]] = {}

    for i in range(n):
        arn = f"arn:aws:controlcatalog:::control/gen-{i:04d}"
        controls.append(
            MappedControl(
                control=_make_control(arn),
                matched_resource_types=["AWS::EC2::Instance"],
            )
        )
        # Some controls appear in the index (with 0..N associations), some don't.
        if draw(st.booleans()):
            mapping_index[arn] = draw(_associations())

    # Noise: index entries that no control references.
    for j in range(draw(st.integers(min_value=0, max_value=2))):
        mapping_index[f"arn:aws:controlcatalog:::control/noise-{j}"] = draw(
            _associations()
        )

    requested = draw(st.lists(_requested_name(), min_size=1, max_size=5))
    return controls, mapping_index, requested


# Framework match selection
@settings(max_examples=100)
@given(_scenarios())
def test_framework_match_selection(scenario):
    """Retained controls are exactly those with a case-insensitive exact match."""
    controls, mapping_index, requested = scenario

    # --- Deterministic anchors (reserved vocabulary, never generated) ---------
    # These guarantee that every example exercises (a) a case-insensitive match
    # and (b) a substring that must NOT match, independent of Hypothesis's draws.
    ci_arn = "arn:aws:controlcatalog:::control/anchor-ci"
    substr_arn = "arn:aws:controlcatalog:::control/anchor-substr"

    mapping_index = dict(mapping_index)  # copy so we never mutate generated data
    mapping_index[ci_arn] = [FrameworkAssociation(name=_ANCHOR_CI_NAME, item="1.1")]
    mapping_index[substr_arn] = [
        FrameworkAssociation(name=_ANCHOR_SUBSTR_FULL, item="2.2")
    ]

    controls = list(controls) + [
        MappedControl(
            control=_make_control(ci_arn),
            matched_resource_types=["AWS::S3::Bucket"],
        ),
        MappedControl(
            control=_make_control(substr_arn),
            matched_resource_types=["AWS::S3::Bucket"],
        ),
    ]

    # Request the CI anchor in a DIFFERENT case (proves case-insensitivity), and
    # request ONLY a strict substring of the substr anchor's full name (proves a
    # substring does not match). The full substr name is never requested.
    requested = list(requested) + [_ANCHOR_CI_NAME.lower(), _ANCHOR_SUBSTR_REQ]

    config = FrameworkFilterConfig(frameworks=requested)
    result = filter_by_framework(controls, mapping_index, config)

    # --- Independent reference: case-insensitive EXACT membership -------------
    requested_lower = {name.lower() for name in requested}

    def expected_matches(arn: str) -> list[FrameworkAssociation]:
        # `in` against a SET is exact membership, never a substring test.
        return [
            a for a in mapping_index.get(arn, []) if a.name.lower() in requested_lower
        ]

    expected_arns = {
        c.control.arn for c in controls if expected_matches(c.control.arn)
    }
    result_arns = [r.control.arn for r in result]
    result_arn_set = set(result_arns)

    # Both directions: retained set is EXACTLY the controls with >=1 match.
    assert result_arn_set == expected_arns
    # ARNs are unique, so no control is retained more than once.
    assert len(result_arns) == len(result_arn_set)

    # Retained controls carry >=1 association, and every carried association is
    # an exact (case-insensitive) match -- never a substring match.
    by_arn = {r.control.arn: r for r in result}
    for arn, retained in by_arn.items():
        assert len(retained.framework_associations) >= 1
        for association in retained.framework_associations:
            assert association.name.lower() in requested_lower
        assert retained.framework_associations == expected_matches(arn)

    # Dropped controls genuinely have no matching association.
    for control in controls:
        if control.control.arn not in result_arn_set:
            assert expected_matches(control.control.arn) == []

    # --- Deterministic anchor checks (do not rely on the reference) -----------
    # Case-insensitivity: CI anchor requested in a different case IS retained.
    assert ci_arn in result_arn_set
    assert any(
        a.name == _ANCHOR_CI_NAME for a in by_arn[ci_arn].framework_associations
    )
    # Substring: requesting only a strict substring of the full name does NOT match.
    assert substr_arn not in result_arn_set
