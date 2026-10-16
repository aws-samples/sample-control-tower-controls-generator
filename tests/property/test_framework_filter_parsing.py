"""Property-based test for framework filter value parsing and trimming.

Validates that ``parse_framework_filter`` interprets a Framework_Filter_Value as a
comma-separated list of Framework names, trims leading/trailing whitespace from
each name, preserves their order, and treats a None/empty/whitespace-only value
as an unset config (``frameworks is None``).

All Hypothesis strategies are defined locally in this module by design so the
file stays self-contained and does not collide with other parallel test tasks.
"""

import string

from hypothesis import given, settings
from hypothesis import strategies as st

from control_tower_controls_generator.cli import parse_framework_filter
from control_tower_controls_generator.models import FrameworkFilterConfig


# --- Local Hypothesis strategies -------------------------------------------

# Token alphabet: every printable ASCII character EXCEPT commas and whitespace.
# Excluding commas keeps each token a single comma-separated field; excluding
# whitespace guarantees a token is non-empty, is not pure-whitespace, and has no
# leading/trailing whitespace of its own -- so trimming the wrapped value is
# unambiguous and always recovers the original token exactly.
_TOKEN_CHARS = "".join(c for c in string.printable if not c.isspace() and c != ",")

# A single Framework-name token: non-empty, comma-free, whitespace-free.
_tokens = st.text(alphabet=_TOKEN_CHARS, min_size=1, max_size=20)

# Leading/trailing padding wrapped around each token: spaces and tabs, possibly
# empty (a token may be supplied with no surrounding whitespace).
_padding = st.text(alphabet=" \t", max_size=4)

# Whitespace-only values (any ASCII whitespace), used to exercise the unset path.
_whitespace_only = st.text(alphabet=" \t\r\n\f\v", min_size=1, max_size=6)


@st.composite
def _parsing_cases(draw):
    """Build ``(tokens, joined, whitespace_only)``.

    ``tokens`` is a non-empty list of clean Framework names. ``joined`` wraps
    each token in arbitrary leading/trailing whitespace and joins them with
    commas -- the value a user might type. ``whitespace_only`` is a separate
    blank/whitespace value that must parse to an unset config.
    """
    tokens = draw(st.lists(_tokens, min_size=1, max_size=6))

    wrapped_fields = []
    for token in tokens:
        lead = draw(_padding)
        trail = draw(_padding)
        wrapped_fields.append(f"{lead}{token}{trail}")

    joined = ",".join(wrapped_fields)
    whitespace_only = draw(_whitespace_only)
    return tokens, joined, whitespace_only


# Framework filter value parsing and trimming
@settings(max_examples=100)
@given(_parsing_cases())
def test_framework_filter_value_parsing_and_trimming(case):
    """Parsing round-trips trimmed tokens in order; blanks yield an unset config."""
    tokens, joined, whitespace_only = case

    # Parsing a comma-separated value yields exactly the original tokens, with
    # surrounding whitespace removed, in the same order.
    config = parse_framework_filter(joined)
    assert isinstance(config, FrameworkFilterConfig)
    assert config.frameworks == tokens

    # A whitespace-only value, an empty string, and None all parse to an unset
    # config so downstream treats the framework filter as opt-out.
    assert parse_framework_filter(whitespace_only).frameworks is None
    assert parse_framework_filter("").frameworks is None
    assert parse_framework_filter(None).frameworks is None
