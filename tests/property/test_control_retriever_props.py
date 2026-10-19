"""Property-based test for control catalog field preservation.

Covers mapping a valid ListControls API
response item to the internal ``Control`` model preserves every field -- ARN,
name, description, behavior, severity, implementation type, implementation
identifier, and the governed resources list.

The mapping under test is the pure helper
``control_tower_controls_generator.control_retriever._map_api_item_to_control``,
which ``_fetch_from_api`` calls for each paginated API item. Exercising the
pure helper keeps the property fast: no boto3 client or stubbing is needed per
Hypothesis example.

All Hypothesis strategies are defined locally in this module by design so the
file stays self-contained and does not collide with other parallel test tasks.
"""

import string

from hypothesis import example, given, settings
from hypothesis import strategies as st

from control_tower_controls_generator.control_retriever import (
    _map_api_item_to_control,
)
from control_tower_controls_generator.models import Control, ControlImplementation


# --- Local Hypothesis strategies -------------------------------------------

# Behavior and severity are drawn from the closed enumerations the Control
# Catalog uses.
_BEHAVIORS = ("PREVENTIVE", "DETECTIVE", "PROACTIVE")
_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# The mapping copies string fields verbatim (no strip/normalisation), so the
# text space is deliberately broad -- any text, including empty and whitespace.
_broad_text = st.text(max_size=60)

# A single path segment of an AWS resource type: ASCII letters/digits only.
_rt_segment = st.text(
    alphabet=string.ascii_letters + string.digits, min_size=1, max_size=12
)
# Realistic AWS resource type identifier, e.g. "AWS::EC2::Instance".
_aws_resource_type = st.builds(
    lambda service, resource: f"AWS::{service}::{resource}",
    _rt_segment,
    _rt_segment,
)
# Governed resource entries: realistic AWS identifiers mixed with broad text to
# widen the input space (the mapping copies the list verbatim regardless).
_governed_entry = st.one_of(_aws_resource_type, _broad_text)


@st.composite
def _api_items(draw):
    """Generate an ``(api_item, expected)`` pair for a ListControls response row.

    ``Implementation.Identifier`` and ``GovernedResources`` are independently
    present or absent so both the "value carried through" and the
    "absent -> default" branches are exercised. ``expected`` captures the
    originally drawn values (with ``None`` / ``[]`` for absent optionals) so the
    assertions compare against an independent source of truth rather than
    re-reading the item under test.
    """
    arn = draw(_broad_text)
    name = draw(_broad_text)
    description = draw(_broad_text)
    behavior = draw(st.sampled_from(_BEHAVIORS))
    severity = draw(st.sampled_from(_SEVERITIES))
    impl_type = draw(_broad_text)

    implementation: dict = {"Type": impl_type}
    include_identifier = draw(st.booleans())
    identifier = None
    if include_identifier:
        identifier = draw(_broad_text)
        implementation["Identifier"] = identifier

    item: dict = {
        "Arn": arn,
        "Name": name,
        "Description": description,
        "Behavior": behavior,
        "Severity": severity,
        "Implementation": implementation,
    }

    include_governed = draw(st.booleans())
    governed = None
    if include_governed:
        governed = draw(st.lists(_governed_entry, max_size=8))
        item["GovernedResources"] = governed

    expected = {
        "arn": arn,
        "name": name,
        "description": description,
        "behavior": behavior,
        "severity": severity,
        "impl_type": impl_type,
        "identifier": identifier,
        "governed_resources": governed if include_governed else [],
    }
    return item, expected


# An explicit "both optionals absent" item, guaranteeing the absent branches
# (Implementation.Identifier -> None, GovernedResources -> []) are always
# exercised, not merely covered probabilistically.
_BOTH_ABSENT = (
    {
        "Arn": "arn:aws:controlcatalog:::control/example",
        "Name": "Example control",
        "Description": "An example.",
        "Behavior": "PREVENTIVE",
        "Severity": "LOW",
        "Implementation": {"Type": "AWS::Config::ConfigRule"},
    },
    {
        "arn": "arn:aws:controlcatalog:::control/example",
        "name": "Example control",
        "description": "An example.",
        "behavior": "PREVENTIVE",
        "severity": "LOW",
        "impl_type": "AWS::Config::ConfigRule",
        "identifier": None,
        "governed_resources": [],
    },
)


# Control catalog field preservation
@settings(max_examples=100)
@given(item_and_expected=_api_items())
@example(item_and_expected=_BOTH_ABSENT)
def test_control_catalog_field_preservation(item_and_expected):
    """Mapping a ListControls API item to Control preserves every field."""
    item, expected = item_and_expected

    control = _map_api_item_to_control(item)

    assert isinstance(control, Control)
    assert isinstance(control.implementation, ControlImplementation)

    # Scalar fields are carried through verbatim.
    assert control.arn == expected["arn"]
    assert control.name == expected["name"]
    assert control.description == expected["description"]
    assert control.behavior == expected["behavior"]
    assert control.severity == expected["severity"]

    # Implementation type is preserved; identifier is None when absent.
    assert control.implementation.type == expected["impl_type"]
    assert control.implementation.identifier == expected["identifier"]

    # Governed resources are preserved in order; absent maps to an empty list.
    assert control.governed_resources == expected["governed_resources"]
