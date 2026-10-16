"""Unit tests for severity filtering.

Covers ``filter_by_severity`` in ``control_tower_controls_generator.severity_filter``
and the CLI helpers that turn the ``--severity-filter`` string into a
``SeverityFilterConfig`` (``parse_severity_filter``) and reject invalid values
(``validate_severity_filter``) in ``control_tower_controls_generator.cli``.

"""

import click
import pytest

from control_tower_controls_generator.cli import (
    parse_severity_filter,
    validate_severity_filter,
)
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    MappedControl,
    SeverityFilterConfig,
)
from control_tower_controls_generator.severity_filter import filter_by_severity


def _make_mapped(name: str, severity: str) -> MappedControl:
    """Build a MappedControl with the given name and severity."""
    return MappedControl(
        control=Control(
            arn=f"arn:aws:controlcatalog:::control/{name.lower()}",
            name=name,
            description="desc",
            behavior="PREVENTIVE",
            severity=severity,
            implementation=ControlImplementation(type="SERVICE_CONTROL_POLICY"),
            governed_resources=["AWS::S3::Bucket"],
        ),
        matched_resource_types=["AWS::S3::Bucket"],
    )


@pytest.fixture
def controls() -> list[MappedControl]:
    """One control per severity level, in a non-sorted order."""
    return [
        _make_mapped("Medium", "MEDIUM"),
        _make_mapped("Critical", "CRITICAL"),
        _make_mapped("Low", "LOW"),
        _make_mapped("High", "HIGH"),
    ]


def _names(result: list[MappedControl]) -> list[str]:
    return [mc.control.name for mc in result]


class TestMinimumSeverityFilter:
    """Minimum level includes controls at or above it."""

    @pytest.mark.parametrize(
        "minimum,expected",
        [
            ("LOW", ["Medium", "Critical", "Low", "High"]),
            ("MEDIUM", ["Medium", "Critical", "High"]),
            ("HIGH", ["Critical", "High"]),
            ("CRITICAL", ["Critical"]),
        ],
    )
    def test_minimum_includes_at_or_above(self, controls, minimum, expected):
        result = filter_by_severity(controls, SeverityFilterConfig(minimum=minimum))

        # Input order is preserved for the controls that pass.
        assert _names(result) == expected

    def test_high_includes_only_high_and_critical(self, controls):
        result = filter_by_severity(controls, SeverityFilterConfig(minimum="HIGH"))

        assert {mc.control.severity for mc in result} == {"HIGH", "CRITICAL"}

    def test_minimum_is_case_insensitive(self, controls):
        result = filter_by_severity(controls, SeverityFilterConfig(minimum="high"))

        assert _names(result) == ["Critical", "High"]

    def test_control_severity_is_compared_case_insensitively(self):
        controls = [_make_mapped("Lower", "high"), _make_mapped("Below", "medium")]

        result = filter_by_severity(controls, SeverityFilterConfig(minimum="HIGH"))

        assert _names(result) == ["Lower"]

    def test_control_with_unknown_severity_is_excluded(self):
        controls = [_make_mapped("Unknown", "UNKNOWN"), _make_mapped("Low", "LOW")]

        result = filter_by_severity(controls, SeverityFilterConfig(minimum="LOW"))

        assert _names(result) == ["Low"]


class TestSpecificSeverityFilter:
    """A list includes only controls matching those levels."""

    def test_low_and_critical_only(self, controls):
        result = filter_by_severity(
            controls, SeverityFilterConfig(specific=["LOW", "CRITICAL"])
        )

        assert _names(result) == ["Critical", "Low"]

    def test_specific_does_not_apply_ordering(self, controls):
        # "MEDIUM" alone as a specific list excludes HIGH and CRITICAL,
        # unlike a minimum of MEDIUM.
        result = filter_by_severity(controls, SeverityFilterConfig(specific=["MEDIUM"]))

        assert _names(result) == ["Medium"]

    def test_specific_is_case_insensitive(self, controls):
        result = filter_by_severity(
            controls, SeverityFilterConfig(specific=["low", "Critical"])
        )

        assert _names(result) == ["Critical", "Low"]

    def test_specific_with_no_matching_controls_returns_empty(self):
        controls = [_make_mapped("Low", "LOW"), _make_mapped("Medium", "MEDIUM")]

        result = filter_by_severity(
            controls, SeverityFilterConfig(specific=["HIGH", "CRITICAL"])
        )

        assert result == []

    def test_specific_takes_precedence_over_minimum(self, controls):
        # When both are set, the specific list wins.
        result = filter_by_severity(
            controls, SeverityFilterConfig(minimum="LOW", specific=["HIGH"])
        )

        assert _names(result) == ["High"]


class TestNoSeverityFilter:
    """No filter returns every control."""

    def test_no_filter_returns_all_controls(self, controls):
        result = filter_by_severity(controls, SeverityFilterConfig())

        assert result == controls

    def test_no_filter_returns_a_new_list(self, controls):
        result = filter_by_severity(controls, SeverityFilterConfig())

        assert result is not controls

    def test_no_filter_keeps_unknown_severity(self):
        controls = [_make_mapped("Unknown", "UNKNOWN")]

        result = filter_by_severity(controls, SeverityFilterConfig())

        assert result == controls

    def test_empty_input_returns_empty(self):
        assert filter_by_severity([], SeverityFilterConfig(minimum="HIGH")) == []
        assert filter_by_severity([], SeverityFilterConfig()) == []


class TestParseSeverityFilter:
    """The CLI string maps to a minimum (single value) or specific (list)."""

    def test_none_returns_unset_config(self):
        assert parse_severity_filter(None) == SeverityFilterConfig()

    def test_single_value_is_minimum(self):
        assert parse_severity_filter("HIGH") == SeverityFilterConfig(minimum="HIGH")

    def test_comma_list_is_specific(self):
        assert parse_severity_filter("LOW,CRITICAL") == SeverityFilterConfig(
            specific=["LOW", "CRITICAL"]
        )

    def test_values_are_trimmed_and_uppercased(self):
        assert parse_severity_filter(" low , Critical ") == SeverityFilterConfig(
            specific=["LOW", "CRITICAL"]
        )
        assert parse_severity_filter(" high ") == SeverityFilterConfig(minimum="HIGH")

    def test_parsed_config_drives_filter(self, controls):
        result = filter_by_severity(controls, parse_severity_filter("LOW,CRITICAL"))

        assert _names(result) == ["Critical", "Low"]


class TestInvalidSeverityValue:
    """Only LOW, MEDIUM, HIGH, CRITICAL are accepted.

    ``validate_severity_filter`` is the click callback; it ignores ``ctx`` and
    ``param``, so they are passed as None.
    """

    def test_none_is_accepted(self):
        assert validate_severity_filter(None, None, None) is None

    @pytest.mark.parametrize(
        "value", ["LOW", "MEDIUM", "HIGH", "CRITICAL", "high", "LOW,CRITICAL", " low , high "]
    )
    def test_valid_values_are_returned_unchanged(self, value):
        assert validate_severity_filter(None, None, value) == value

    def test_invalid_single_value_is_rejected(self):
        with pytest.raises(click.BadParameter, match="Invalid severity value 'INVALID'"):
            validate_severity_filter(None, None, "INVALID")

    def test_invalid_value_in_list_is_rejected(self):
        with pytest.raises(click.BadParameter, match="Invalid severity value 'SEVERE'"):
            validate_severity_filter(None, None, "HIGH,SEVERE")

    def test_error_lists_allowed_values(self):
        with pytest.raises(click.BadParameter) as exc_info:
            validate_severity_filter(None, None, "URGENT")

        assert "Allowed values: CRITICAL, HIGH, LOW, MEDIUM" in str(exc_info.value)

    @pytest.mark.parametrize("value", ["", "HIGH,", ",LOW"])
    def test_empty_token_is_rejected(self, value):
        with pytest.raises(click.BadParameter):
            validate_severity_filter(None, None, value)
