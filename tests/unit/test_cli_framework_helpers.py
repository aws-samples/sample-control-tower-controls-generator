"""Unit tests for the CLI framework filter helpers.

Covers ``parse_framework_filter`` and ``validate_framework_filter`` in
``control_tower_controls_generator.cli``.
"""

from control_tower_controls_generator.cli import (
    parse_framework_filter,
    validate_framework_filter,
)
from control_tower_controls_generator.models import FrameworkFilterConfig


class TestParseFrameworkFilter:
    """Tests for ``parse_framework_filter`` (string -> FrameworkFilterConfig)."""

    def test_none_returns_unset_config(self):
        # None input => unset (opt-out) config with frameworks=None.
        result = parse_framework_filter(None)

        assert isinstance(result, FrameworkFilterConfig)
        assert result.frameworks is None

    def test_empty_string_returns_unset_config(self):
        # "" resolves to no names, so downstream treats it as unset.
        result = parse_framework_filter("")

        assert result == FrameworkFilterConfig(frameworks=None)
        assert result.frameworks is None

    def test_whitespace_only_returns_unset_config(self):
        # Whitespace-only input strips to nothing => unset config.
        result = parse_framework_filter("   ")

        assert result == FrameworkFilterConfig(frameworks=None)
        assert result.frameworks is None

    def test_single_name(self):
        result = parse_framework_filter("PCI-DSS-v4.0")

        assert result.frameworks == ["PCI-DSS-v4.0"]

    def test_comma_list_with_surrounding_whitespace_is_trimmed(self):
        # Leading/trailing whitespace around each name is stripped.
        result = parse_framework_filter("  PCI-DSS-v4.0 , NIST-SP-800-53-r5 ")

        assert result.frameworks == ["PCI-DSS-v4.0", "NIST-SP-800-53-r5"]

    def test_trailing_comma_drops_empty_token(self):
        # The empty token produced by the trailing comma is dropped.
        result = parse_framework_filter("PCI-DSS-v4.0,")

        assert result.frameworks == ["PCI-DSS-v4.0"]

    def test_duplicate_names_are_preserved(self):
        # Documented actual behavior: the parser does not de-duplicate names.
        result = parse_framework_filter("PCI-DSS-v4.0,PCI-DSS-v4.0")

        assert result.frameworks == ["PCI-DSS-v4.0", "PCI-DSS-v4.0"]


class TestValidateFrameworkFilter:
    """Tests for ``validate_framework_filter`` (click callback).

    The callback ignores ``ctx`` and ``param``; they are passed as None.
    """

    def test_none_returns_none(self):
        assert validate_framework_filter(None, None, None) is None

    def test_empty_string_returns_none(self):
        assert validate_framework_filter(None, None, "") is None

    def test_whitespace_only_returns_none(self):
        assert validate_framework_filter(None, None, "   ") is None

    def test_single_name_returns_value(self):
        assert validate_framework_filter(None, None, "PCI-DSS-v4.0") == "PCI-DSS-v4.0"

    def test_non_empty_value_returned_untrimmed(self):
        # Non-empty input is returned raw; trimming happens later in parsing.
        value = "  PCI-DSS-v4.0 , NIST-SP-800-53-r5 "

        assert validate_framework_filter(None, None, value) == value
