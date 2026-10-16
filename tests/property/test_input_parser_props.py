"""Property-based tests for the input parser.

Covers three correctness properties of
``control_tower_controls_generator.input_parser``:

* Simple array input parsing round-trip: serializing a list of
  valid resource type strings to JSON and parsing it back yields the same set
  of resource types.
* Config aggregator input parsing extracts all resource types and
  accounts: every unique resource type present in the query results is
  extracted, and each is mapped to exactly the set of account IDs it appears
  with.
* Deduplication produces unique resource types without data loss:
  ``_deduplicate`` yields an output whose elements are unique, preserves
  first-seen order, and loses no distinct input element.

The round-trip properties exercise the public ``parse_input_file`` through a
real on-disk JSON file (so the JSON-decode path is genuinely covered), while
the deduplication property exercises the pure ``_deduplicate`` helper directly
so order preservation can be asserted.

All Hypothesis strategies are defined locally in this module by design so the
file stays self-contained and does not collide with other parallel test tasks.
"""

import json
import string

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from control_tower_controls_generator.input_parser import (
    _deduplicate,
    parse_input_file,
)


# --- Local Hypothesis strategies -------------------------------------------

# A single path segment of an AWS resource type: ASCII letters/digits only, so
# it carries no surrounding or internal whitespace. This guarantees the parser's
# ``.strip()`` is a no-op and the token is never dropped as empty/whitespace.
_rt_segment = st.text(
    alphabet=string.ascii_letters + string.digits, min_size=1, max_size=12
)

# Realistic AWS resource type identifier, e.g. "AWS::EC2::Instance".
_aws_resource_type = st.builds(
    lambda service, resource: f"AWS::{service}::{resource}",
    _rt_segment,
    _rt_segment,
)

# Every printable ASCII character EXCEPT whitespace. A non-empty token drawn
# from this alphabet is never empty or whitespace-only and has no leading or
# trailing whitespace, so the parser stores it verbatim (strip is a no-op).
_GENERIC_TOKEN_CHARS = "".join(c for c in string.printable if not c.isspace())
_generic_token = st.text(alphabet=_GENERIC_TOKEN_CHARS, min_size=1, max_size=20)

# A "valid resource type string" for the simple-array format: realistic AWS
# identifiers mixed with arbitrary non-whitespace tokens to broaden the input
# space while staying strip-invariant and never-dropped.
_resource_type = st.one_of(_aws_resource_type, _generic_token)

# A 12-digit AWS account identifier (digits only => strip-invariant, non-empty).
_account_id = st.text(alphabet=string.digits, min_size=12, max_size=12)


@st.composite
def _lists_with_duplicates(draw):
    """A list of resource type strings drawn from a small pool.

    Sampling from a small, distinct pool makes duplicates common so the
    deduplication behaviour is genuinely exercised. Length may be zero to cover
    the empty-input edge case.
    """
    pool = draw(st.lists(_resource_type, min_size=1, max_size=6, unique=True))
    return draw(st.lists(st.sampled_from(pool), min_size=0, max_size=30))


@st.composite
def _aggregator_pairs(draw):
    """Generate ``(resourceType, accountId)`` rows for a Config aggregator query.

    Resource types and account IDs are each sampled from a small distinct pool
    so the same resource type recurs across different accounts (and vice versa),
    genuinely exercising the many-to-many resourceType -> accounts mapping.
    """
    rt_pool = draw(st.lists(_aws_resource_type, min_size=1, max_size=4, unique=True))
    acct_pool = draw(st.lists(_account_id, min_size=1, max_size=4, unique=True))
    return draw(
        st.lists(
            st.tuples(st.sampled_from(rt_pool), st.sampled_from(acct_pool)),
            min_size=1,
            max_size=30,
        )
    )


def _first_seen_unique(items):
    """Return ``items`` de-duplicated, preserving first-seen order."""
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


# Simple array input parsing round-trip
@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(resource_types=st.lists(_resource_type, min_size=1, max_size=15))
def test_simple_array_round_trip(tmp_path, resource_types):
    """Serializing valid resource types to JSON and parsing back yields the same set."""
    input_path = tmp_path / "input.json"
    input_path.write_text(json.dumps(resource_types), encoding="utf-8")

    result = parse_input_file(str(input_path))

    # Same set of resource types survives the JSON serialize -> parse round-trip.
    assert set(result.resource_types) == set(resource_types)
    # Output is deduplicated: every element is unique.
    assert len(result.resource_types) == len(set(result.resource_types))
    # A simple array carries no account data.
    assert result.account_mapping is None


# Config aggregator input parsing extracts all resource types and accounts
@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(pairs=_aggregator_pairs())
def test_config_aggregator_extracts_resource_types_and_accounts(tmp_path, pairs):
    """Parser extracts the unique resource types and maps each to its account IDs."""
    results = [
        json.dumps({"resourceType": rt, "accountId": aid}) for rt, aid in pairs
    ]
    data = {"QueryInfo": {"SelectFields": []}, "Results": results}

    # Independent expected model: unique resource types in first-seen order, and
    # each resource type mapped to its unique account IDs in first-seen order.
    expected_resource_types = _first_seen_unique([rt for rt, _ in pairs])
    expected_mapping: dict[str, list[str]] = {}
    for rt, aid in pairs:
        accounts = expected_mapping.setdefault(rt, [])
        if aid not in accounts:
            accounts.append(aid)

    input_path = tmp_path / "aggregator.json"
    input_path.write_text(json.dumps(data), encoding="utf-8")

    result = parse_input_file(str(input_path))

    # Exactly the set of unique resource types present in the results.
    assert set(result.resource_types) == {rt for rt, _ in pairs}
    assert result.resource_types == expected_resource_types

    # Account data is present, so mapping is a dict keyed by resource type.
    assert result.account_mapping is not None
    assert set(result.account_mapping.keys()) == {rt for rt, _ in pairs}
    assert result.account_mapping == expected_mapping

    # Each resource type maps to exactly its set of account IDs, with no dupes.
    for rt, accounts in result.account_mapping.items():
        assert len(accounts) == len(set(accounts))
        assert set(accounts) == {aid for r, aid in pairs if r == rt}


# Deduplication produces unique resource types without data loss
@settings(max_examples=100)
@given(items=_lists_with_duplicates())
def test_deduplication_unique_without_data_loss(items):
    """Deduplication yields unique elements, preserves order, and loses nothing."""
    result = _deduplicate(items)

    # Every element in the output is unique.
    assert len(result) == len(set(result))
    # No data loss: every distinct input element is present in the output, and
    # nothing extra is introduced.
    assert set(result) == set(items)
    # First-seen order is preserved.
    assert result == _first_seen_unique(items)
