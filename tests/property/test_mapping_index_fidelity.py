"""Property-based test for Mapping index fidelity.

Exercises the pure page-processing helper ``_index_mappings`` in
``control_mappings_retriever``. Given raw ``ListControlMappings``-shaped pages
mixing ``FRAMEWORK`` and ``COMMON_CONTROL`` entries (with control ARNs possibly
repeated and split across multiple pages), the built index must:

  * have keys equal to EXACTLY the set of ARNs that appear in >= 1 complete
    ``FRAMEWORK`` mapping,
  * associate, for each such ARN, exactly one ``FrameworkAssociation(name, item)``
    per ``FRAMEWORK`` mapping of that ARN, in encounter order (many-to-many,
    order-preserving),
  * and let NO ``COMMON_CONTROL`` mapping contribute any key or value.

``FRAMEWORK`` entries missing their ``Name`` or ``Item``
are skipped; the generator produces some of these and the independent expected
model excludes them.

All Hypothesis strategies are defined locally in this module by design so this
file stays self-contained and does not collide with other parallel test tasks.
"""

from hypothesis import given, settings, strategies as st

from control_tower_controls_generator.control_mappings_retriever import (
    _index_mappings,
)
from control_tower_controls_generator.models import FrameworkAssociation


# Non-empty pools guarantee that complete FRAMEWORK entries always carry a real
# Name and Item (never None), so they are always indexed rather than skipped.
_FRAMEWORK_NAMES = [
    "PCI-DSS-v4.0",
    "NIST-SP-800-53-r5",
    "CIS-v8.0",
    "HIPAA",
    "SOC-2",
    "ISO-27001",
]
_FRAMEWORK_ITEMS = ["7.2.2", "CM-5", "1.1", "A.9.2", "3.4.1", "AC-2"]

# Mapping "kind" pool, weighted toward complete FRAMEWORK entries while still
# producing occasional skipped-FRAMEWORK entries and COMMON_CONTROL noise.
_KINDS = (
    ["framework"] * 5
    + ["framework_no_name", "framework_no_item"]
    + ["common"] * 2
)


def _arn(i: int) -> str:
    """A deterministic control ARN for pool index ``i``."""
    return f"arn:aws:controlcatalog:::control/gen-{i:04d}"


def _to_raw(entry: dict) -> dict:
    """Build one raw ListControlMappings mapping dict from a generated entry."""
    kind = entry["kind"]
    arn = entry["arn"]
    if kind == "framework":
        return {
            "ControlArn": arn,
            "MappingType": "FRAMEWORK",
            "Mapping": {"Framework": {"Name": entry["name"], "Item": entry["item"]}},
        }
    if kind == "framework_no_name":
        # Missing Name => skipped.
        return {
            "ControlArn": arn,
            "MappingType": "FRAMEWORK",
            "Mapping": {"Framework": {"Item": entry["item"]}},
        }
    if kind == "framework_no_item":
        # Missing Item => skipped.
        return {
            "ControlArn": arn,
            "MappingType": "FRAMEWORK",
            "Mapping": {"Framework": {"Name": entry["name"]}},
        }
    # COMMON_CONTROL => must contribute nothing. The helper
    # never inspects the CommonControl payload, so its shape is arbitrary.
    return {
        "ControlArn": arn,
        "MappingType": "COMMON_CONTROL",
        "Mapping": {"CommonControl": {"Name": entry["name"], "Item": entry["item"]}},
    }


@st.composite
def _scenarios(draw):
    """Generate ``(entries, pages)``.

    ``entries`` is the abstract, ordered list of mappings that were emitted;
    ``pages`` is those mappings rendered as raw dicts and split into contiguous
    pages (some possibly empty) to exercise pagination aggregation. Contiguous
    slicing preserves the overall encounter order the helper iterates in.
    """
    arn_pool_size = draw(st.integers(min_value=1, max_value=5))
    arns = [_arn(i) for i in range(arn_pool_size)]

    entry_strategy = st.fixed_dictionaries(
        {
            "arn": st.sampled_from(arns),  # small pool => ARNs repeat often
            "kind": st.sampled_from(_KINDS),
            "name": st.sampled_from(_FRAMEWORK_NAMES),
            "item": st.sampled_from(_FRAMEWORK_ITEMS),
        }
    )
    entries = draw(st.lists(entry_strategy, min_size=0, max_size=30))

    raw_mappings = [_to_raw(e) for e in entries]

    # Split into contiguous chunks across multiple pages. Cut points are drawn
    # in [0, n] and sorted, so concatenating the slices reproduces the original
    # order exactly; equal/consecutive cut points yield empty pages.
    n = len(raw_mappings)
    num_cuts = draw(st.integers(min_value=0, max_value=4))
    cut_points = sorted(
        draw(
            st.lists(
                st.integers(min_value=0, max_value=n),
                min_size=num_cuts,
                max_size=num_cuts,
            )
        )
    )
    pages = []
    prev = 0
    for cut in cut_points:
        pages.append({"ControlMappings": raw_mappings[prev:cut]})
        prev = cut
    pages.append({"ControlMappings": raw_mappings[prev:]})

    return entries, pages


# Mapping index fidelity
@settings(max_examples=100)
@given(_scenarios())
def test_mapping_index_fidelity(scenario):
    """Index keys/values reflect exactly the complete FRAMEWORK mappings."""
    entries, pages = scenario

    # --- Independent expected index -----------------------------------------
    # Iterate entries in encounter order; only complete FRAMEWORK entries
    # contribute, appending one association each (preserving order + repeats).
    expected: dict[str, list[FrameworkAssociation]] = {}
    for entry in entries:
        if entry["kind"] == "framework":
            expected.setdefault(entry["arn"], []).append(
                FrameworkAssociation(name=entry["name"], item=entry["item"])
            )

    result = _index_mappings(pages)

    # Full structural equality: same keys, and per key the same ordered list of
    # (name, item) associations (FrameworkAssociation is a dataclass with __eq__).
    assert result == expected

    # --- Explicit property-statement checks ---------------------------------
    # Keys are EXACTLY the ARNs appearing in >= 1 complete FRAMEWORK mapping.
    contributing_arns = {e["arn"] for e in entries if e["kind"] == "framework"}
    assert set(result.keys()) == contributing_arns

    # No COMMON_CONTROL (or skipped-FRAMEWORK) mapping contributes a key: any
    # ARN that never appears in a complete FRAMEWORK mapping is absent entirely.
    non_contributing_arns = {e["arn"] for e in entries} - contributing_arns
    for arn in non_contributing_arns:
        assert arn not in result

    # Per ARN, the number of associations equals the number of complete
    # FRAMEWORK mappings for that ARN (many-to-many fully preserved).
    for arn, associations in result.items():
        complete_count = sum(
            1 for e in entries if e["kind"] == "framework" and e["arn"] == arn
        )
        assert len(associations) == complete_count
