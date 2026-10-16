"""Unit tests for the framework_filter module edge cases.

Plain example-based pytest tests (no Hypothesis) covering the edge cases called
out in the design's Testing Strategy > Unit tests for ``filter_by_framework``
and ``find_unrecognized_frameworks``.
"""

from control_tower_controls_generator.framework_filter import (
    filter_by_framework,
    find_unrecognized_frameworks,
)
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    FrameworkAssociation,
    FrameworkFilterConfig,
    MappedControl,
)


def _make_control(arn: str, name: str = "Control") -> Control:
    """Build a Control with the minimum fields needed for filtering."""
    return Control(
        arn=arn,
        name=name,
        description="desc",
        behavior="Preventive",
        severity="HIGH",
        implementation=ControlImplementation(type="SERVICE_CONTROL_POLICY"),
        governed_resources=[],
    )


def _make_mapped(
    arn: str,
    name: str = "Control",
    resource_types: list[str] | None = None,
    associations: list[FrameworkAssociation] | None = None,
) -> MappedControl:
    """Build a MappedControl for the given ARN."""
    return MappedControl(
        control=_make_control(arn, name=name),
        matched_resource_types=list(resource_types or []),
        framework_associations=list(associations or []),
    )


class TestFilterByFrameworkUnset:
    """Unset config (opt-out) returns everything unchanged with no attribution."""

    def test_unset_config_returns_all_controls_unchanged(self):
        controls = [
            _make_mapped("arn:1", name="A", resource_types=["AWS::S3::Bucket"]),
            _make_mapped("arn:2", name="B", resource_types=["AWS::EC2::Instance"]),
        ]
        index = {"arn:1": [FrameworkAssociation("PCI-DSS-v4.0", "1.1")]}
        config = FrameworkFilterConfig(frameworks=None)

        result = filter_by_framework(controls, index, config)

        assert len(result) == 2
        # Same instances returned, in the same order.
        assert result[0] is controls[0]
        assert result[1] is controls[1]

    def test_unset_config_attaches_no_attribution(self):
        controls = [_make_mapped("arn:1")]
        index = {"arn:1": [FrameworkAssociation("PCI-DSS-v4.0", "1.1")]}
        config = FrameworkFilterConfig(frameworks=None)

        result = filter_by_framework(controls, index, config)

        assert result[0].framework_associations == []

    def test_unset_config_returns_new_list_object(self):
        controls = [_make_mapped("arn:1")]
        config = FrameworkFilterConfig(frameworks=None)

        result = filter_by_framework(controls, {}, config)

        # A new list is returned so the caller's list is never aliased/mutated.
        assert result is not controls
        assert result == controls


class TestFilterByFrameworkEmptyRequestedList:
    """A genuinely empty requested list matches nothing.

    The CLI parser never produces an empty list (blank input becomes
    ``frameworks=None``), but an explicit empty list is a boundary worth
    pinning down: with no requested names, no association can match, so every
    control is dropped.
    """

    def test_empty_requested_list_drops_all_controls(self):
        controls = [_make_mapped("arn:1"), _make_mapped("arn:2")]
        index = {
            "arn:1": [FrameworkAssociation("PCI-DSS-v4.0", "1.1")],
            "arn:2": [FrameworkAssociation("NIST-SP-800-53-r5", "CM-5")],
        }
        config = FrameworkFilterConfig(frameworks=[])

        result = filter_by_framework(controls, index, config)

        assert result == []


class TestFilterByFrameworkMatching:
    """Selection behavior when one or more frameworks are requested."""

    def test_control_with_no_index_entry_is_dropped(self):
        controls = [_make_mapped("arn:missing")]
        index = {"arn:other": [FrameworkAssociation("PCI-DSS-v4.0", "1.1")]}
        config = FrameworkFilterConfig(frameworks=["PCI-DSS-v4.0"])

        result = filter_by_framework(controls, index, config)

        assert result == []

    def test_control_with_only_non_matching_associations_is_dropped(self):
        controls = [_make_mapped("arn:1")]
        index = {
            "arn:1": [
                FrameworkAssociation("NIST-SP-800-53-r5", "CM-5"),
                FrameworkAssociation("CIS-v8.0", "1.2"),
            ]
        }
        config = FrameworkFilterConfig(frameworks=["PCI-DSS-v4.0"])

        result = filter_by_framework(controls, index, config)

        assert result == []

    def test_control_with_single_matching_association_is_retained(self):
        assoc = FrameworkAssociation("PCI-DSS-v4.0", "7.2.2")
        controls = [_make_mapped("arn:1", resource_types=["AWS::S3::Bucket"])]
        index = {"arn:1": [assoc]}
        config = FrameworkFilterConfig(frameworks=["PCI-DSS-v4.0"])

        result = filter_by_framework(controls, index, config)

        assert len(result) == 1
        assert result[0].control.arn == "arn:1"
        assert result[0].framework_associations == [assoc]
        assert result[0].matched_resource_types == ["AWS::S3::Bucket"]

    def test_control_with_multiple_matching_associations_retained_any_of(self):
        pci = FrameworkAssociation("PCI-DSS-v4.0", "7.2.2")
        nist = FrameworkAssociation("NIST-SP-800-53-r5", "CM-5")
        cis = FrameworkAssociation("CIS-v8.0", "1.2")  # present but not requested
        controls = [_make_mapped("arn:1", associations=None)]
        index = {"arn:1": [pci, nist, cis]}
        config = FrameworkFilterConfig(
            frameworks=["PCI-DSS-v4.0", "NIST-SP-800-53-r5"]
        )

        result = filter_by_framework(controls, index, config)

        assert len(result) == 1
        # Any-of: retained because it matches at least one requested framework,
        # and it carries ONLY the matched associations (CIS is excluded).
        assert result[0].framework_associations == [pci, nist]

    def test_case_insensitive_exact_match_retains(self):
        assoc = FrameworkAssociation("PCI-DSS-v4.0", "7.2.2")
        controls = [_make_mapped("arn:1")]
        index = {"arn:1": [assoc]}
        config = FrameworkFilterConfig(frameworks=["pci-dss-v4.0"])

        result = filter_by_framework(controls, index, config)

        assert len(result) == 1
        assert result[0].framework_associations == [assoc]

    def test_substring_does_not_match(self):
        controls = [_make_mapped("arn:1")]
        index = {"arn:1": [FrameworkAssociation("PCI-DSS-v4.0", "7.2.2")]}
        config = FrameworkFilterConfig(frameworks=["PCI"])

        result = filter_by_framework(controls, index, config)

        assert result == []

    def test_multiple_controls_only_matching_retained_in_order(self):
        controls = [
            _make_mapped("arn:1", name="A"),  # matches
            _make_mapped("arn:2", name="B"),  # dropped
            _make_mapped("arn:3", name="C"),  # matches
        ]
        index = {
            "arn:1": [FrameworkAssociation("PCI-DSS-v4.0", "1.1")],
            "arn:2": [FrameworkAssociation("CIS-v8.0", "2.2")],
            "arn:3": [FrameworkAssociation("PCI-DSS-v4.0", "3.3")],
        }
        config = FrameworkFilterConfig(frameworks=["PCI-DSS-v4.0"])

        result = filter_by_framework(controls, index, config)

        assert [m.control.arn for m in result] == ["arn:1", "arn:3"]


class TestFilterByFrameworkNoMutation:
    """The filter must never mutate its inputs and must return fresh objects."""

    def test_does_not_mutate_input_framework_associations(self):
        mapped = _make_mapped("arn:1")
        original_assocs = mapped.framework_associations
        index = {"arn:1": [FrameworkAssociation("PCI-DSS-v4.0", "1.1")]}
        config = FrameworkFilterConfig(frameworks=["PCI-DSS-v4.0"])

        filter_by_framework([mapped], index, config)

        assert mapped.framework_associations == []
        assert mapped.framework_associations is original_assocs

    def test_returns_new_mappedcontrol_instances(self):
        mapped = _make_mapped("arn:1")
        index = {"arn:1": [FrameworkAssociation("PCI-DSS-v4.0", "1.1")]}
        config = FrameworkFilterConfig(frameworks=["PCI-DSS-v4.0"])

        result = filter_by_framework([mapped], index, config)

        assert result[0] is not mapped

    def test_does_not_mutate_input_matched_resource_types(self):
        mapped = _make_mapped("arn:1", resource_types=["AWS::S3::Bucket"])
        index = {"arn:1": [FrameworkAssociation("PCI-DSS-v4.0", "1.1")]}
        config = FrameworkFilterConfig(frameworks=["PCI-DSS-v4.0"])

        result = filter_by_framework([mapped], index, config)
        # Mutating the returned control's list must not leak into the input.
        result[0].matched_resource_types.append("AWS::EC2::Instance")

        assert mapped.matched_resource_types == ["AWS::S3::Bucket"]


class TestFindUnrecognizedFrameworks:
    """Detection of requested framework names absent from the mapping index."""

    def test_returns_empty_list_when_config_unset(self):
        index = {"arn:1": [FrameworkAssociation("PCI-DSS-v4.0", "1.1")]}
        config = FrameworkFilterConfig(frameworks=None)

        assert find_unrecognized_frameworks(config, index) == []

    def test_returns_unrecognized_names(self):
        index = {"arn:1": [FrameworkAssociation("PCI-DSS-v4.0", "1.1")]}
        config = FrameworkFilterConfig(
            frameworks=["PCI-DSS-v4.0", "MADE-UP-FRAMEWORK"]
        )

        assert find_unrecognized_frameworks(config, index) == ["MADE-UP-FRAMEWORK"]

    def test_recognizes_names_case_insensitively(self):
        index = {"arn:1": [FrameworkAssociation("PCI-DSS-v4.0", "1.1")]}
        config = FrameworkFilterConfig(frameworks=["pci-dss-v4.0"])

        assert find_unrecognized_frameworks(config, index) == []

    def test_returns_only_unrecognized_preserving_order_and_casing(self):
        index = {
            "arn:1": [FrameworkAssociation("PCI-DSS-v4.0", "1.1")],
            "arn:2": [FrameworkAssociation("NIST-SP-800-53-r5", "CM-5")],
        }
        config = FrameworkFilterConfig(
            frameworks=["Made-Up", "pci-dss-v4.0", "Another-Fake"]
        )

        assert find_unrecognized_frameworks(config, index) == [
            "Made-Up",
            "Another-Fake",
        ]

    def test_all_recognized_returns_empty(self):
        index = {
            "arn:1": [
                FrameworkAssociation("PCI-DSS-v4.0", "1.1"),
                FrameworkAssociation("CIS-v8.0", "2.2"),
            ]
        }
        config = FrameworkFilterConfig(frameworks=["PCI-DSS-v4.0", "CIS-v8.0"])

        assert find_unrecognized_frameworks(config, index) == []

    def test_empty_index_marks_all_requested_unrecognized(self):
        config = FrameworkFilterConfig(frameworks=["PCI-DSS-v4.0", "CIS-v8.0"])

        assert find_unrecognized_frameworks(config, {}) == [
            "PCI-DSS-v4.0",
            "CIS-v8.0",
        ]

    def test_does_not_print_anything(self, capsys):
        index = {"arn:1": [FrameworkAssociation("PCI-DSS-v4.0", "1.1")]}
        config = FrameworkFilterConfig(frameworks=["PCI-DSS-v4.0", "UNKNOWN"])

        find_unrecognized_frameworks(config, index)

        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""
