"""Property-based tests for the account-id injection remediation.

This module hosts the Hypothesis property tests for the two-layer remediation:
parse-time account-id validation in ``input_parser`` (Layer 1) and sink-level
Markdown cell escaping in ``report_generator`` (Layer 2).

This module covers Layer 1: only values matching the canonical
account-id format ``^\\d{12}$`` (ASCII) survive parse-time validation, across both
the Config aggregator path and the CSV path. Further properties are appended to this
same module by later tasks and reuse the module-level strategies defined below.

All Hypothesis strategies are defined locally so the module stays self-contained,
mirroring ``tests/property/test_input_parser_props.py``.
"""

import csv
import json
import re
import string

import pytest
from hypothesis import HealthCheck, assume, example, given, settings
from hypothesis import strategies as st

from control_tower_controls_generator.input_parser import (
    InputParserError,
    parse_input_file,
)


# --- Canonical format (independent restatement of the requirement) ----------

# The requirement's Canonical_Account_Id_Format: exactly twelve ASCII digits.
# ``re.ASCII`` constrains ``\d`` to ``[0-9]`` so Unicode digits never satisfy it.
# Defined locally (rather than imported from the module under test) so the test
# asserts the requirement directly instead of whatever constant the code uses.
CANONICAL_ACCOUNT_ID = re.compile(r"^\d{12}$", re.ASCII)


# --- Shared module-level Hypothesis strategies ------------------------------
# Defined once here and reused by the properties appended to
# this same module.

# A single AWS resource-type path segment: ASCII letters/digits only, so it is
# strip-invariant, never dropped as empty, and safe to embed in both JSON and
# CSV without any quoting concerns.
_rt_segment = st.text(
    alphabet=string.ascii_letters + string.digits, min_size=1, max_size=12
)

# Realistic AWS resource type, e.g. "AWS::EC2::Instance". Starts with "AWS::" so
# it is accepted by the CSV path (which requires that prefix) as well as by the
# Config aggregator path.
aws_resource_type = st.builds(
    lambda service, resource: f"AWS::{service}::{resource}",
    _rt_segment,
    _rt_segment,
)

# A canonical account id: exactly twelve ASCII digits. ``string.digits`` is ASCII,
# so every value matches CANONICAL_ACCOUNT_ID and is strip-invariant.
valid_account_id = st.text(alphabet=string.digits, min_size=12, max_size=12)

# Twelve non-ASCII digits (full-width U+FF10-19 and Arabic-Indic U+0660-69).
# These match ``\d`` in Unicode mode but NOT under ``re.ASCII``, so they must be
# treated as invalid -- the case that specifically exercises the re.ASCII guard.
_FULLWIDTH_DIGITS = "".join(chr(c) for c in range(0xFF10, 0xFF1A))
_ARABIC_INDIC_DIGITS = "".join(chr(c) for c in range(0x0660, 0x066A))
_non_ascii_digit_id = st.one_of(
    st.text(alphabet=_FULLWIDTH_DIGITS, min_size=12, max_size=12),
    st.text(alphabet=_ARABIC_INDIC_DIGITS, min_size=12, max_size=12),
)

# Strings carrying the structural / markup / newline characters the escaper
# neutralizes; none of these can match the canonical format.
_special_char_id = st.sampled_from(
    [
        "|",
        "12345|678901",
        "123456789012|",
        "<img src=x onerror=alert(document.domain)>",
        "<script>alert(1)</script>",
        "a&b",
        "1<2>3",
        "line1\nline2",
        "carriage\r\nreturn",
        "&amp;",
    ]
)

# Any text that must FAIL the canonical format. Built as a union of the specific
# invalid shapes called out by the design, then filtered so that no value which
# is canonical *after stripping* can slip through. Both parse paths validate the
# stripped value, so filtering on ``.strip()`` is the strictest guard and also
# implies the raw value fails the pattern.
invalid_account_id = st.one_of(
    st.just(""),  # empty
    st.text(alphabet=string.digits, min_size=1, max_size=11),  # too short
    st.text(alphabet=string.digits, min_size=13, max_size=20),  # too long
    st.text(  # digit + letter mixes (and pure letters)
        alphabet=string.digits + string.ascii_letters, min_size=1, max_size=20
    ),
    _special_char_id,  # |, <, >, &, newlines
    _non_ascii_digit_id,  # twelve non-ASCII digits
    st.text(min_size=0, max_size=30),  # fully arbitrary text
).filter(lambda s: CANONICAL_ACCOUNT_ID.match(s.strip()) is None)

# Known crafted inputs for the escaping tests. Folded into ``cell_value`` so
# the escaper properties (added to this module by later tasks) always exercise
# them, and exposed for explicit ``@example`` pinning as well.
CRAFTED_INPUTS = [
    "<img src=x onerror=alert(document.domain)>",
    "acct | Forged | Column",
    "row1\nrow2",
    "a|b\r\nc",
    "<script>alert(document.domain)</script>",
    "& < > | mixed",
]

# Arbitrary externally-sourced Markdown cell content, broadened to always include
# the known crafted inputs. Consumed by the escaper properties in later tasks.
cell_value = st.one_of(st.sampled_from(CRAFTED_INPUTS), st.text())


# --- Input builders ---------------------------------------------------------

def _write_aggregator_file(tmp_path, pairs):
    """Write a Config aggregator query-output JSON file and return its path."""
    results = [
        json.dumps({"resourceType": rt, "accountId": aid}) for rt, aid in pairs
    ]
    data = {"QueryInfo": {"SelectFields": []}, "Results": results}
    path = tmp_path / "aggregator.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def _write_csv_file(tmp_path, pairs):
    """Write a ``resourceType,accountId`` CSV file and return its path.

    Uses ``csv.writer`` with ``newline=""`` so account values containing commas,
    quotes, or newlines are quoted correctly and round-trip through the parser.
    """
    path = tmp_path / "input.csv"
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["resourceType", "accountId"])
        for rt, aid in pairs:
            writer.writerow([rt, aid])
    return str(path)


def _assert_only_canonical(account_mapping, invalid_inputs):
    """Assert the mapping holds only canonical ids and no supplied invalid value.

    When ``account_mapping`` is ``None`` (every id was invalid), the collected
    set is empty and both assertions hold trivially.
    """
    stored = {aid for ids in (account_mapping or {}).values() for aid in ids}
    # Every account id that survived validation matches the canonical format.
    for aid in stored:
        assert CANONICAL_ACCOUNT_ID.match(aid) is not None, (
            f"non-canonical account id survived validation: {aid!r}"
        )
    # No value supplied as invalid appears anywhere in the mapping.
    assert stored.isdisjoint(invalid_inputs), (
        f"invalid account id(s) leaked into mapping: {stored & invalid_inputs!r}"
    )


@st.composite
def _mixed_account_pairs(draw):
    """Generate ``(resourceType, accountId)`` rows mixing valid and invalid ids.

    Resource types are sampled from a small pool so the same type recurs with
    different account ids. Each account id is drawn from either the valid or the
    invalid strategy, so every generated example mixes canonical and malformed
    values across a shared set of resource types.
    """
    rt_pool = draw(
        st.lists(aws_resource_type, min_size=1, max_size=4, unique=True)
    )
    account = st.one_of(valid_account_id, invalid_account_id)
    return draw(
        st.lists(
            st.tuples(st.sampled_from(rt_pool), account),
            min_size=1,
            max_size=20,
        )
    )


# Only canonical account ids survive parse-time validation
# Each generated example writes an aggregator JSON file and a CSV file to tmp_path,
# so per-example wall-clock timing is unreliable (notably on Windows) even though
# correctness is unaffected; the Hypothesis per-example deadline is therefore
# disabled here and on the other file-I/O properties below (standard Hypothesis
# guidance for I/O-bound property tests).
@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(pairs=_mixed_account_pairs())
@example(
    pairs=[
        ("AWS::EC2::Instance", "123456789012"),
        ("AWS::EC2::Instance", "<img src=x onerror=alert(document.domain)>"),
        ("AWS::S3::Bucket", "12345|6789ab"),
        ("AWS::S3::Bucket", "\n"),
    ]
)
def test_only_canonical_account_ids_survive_validation(tmp_path, pairs):
    """Only ``^\\d{12}$`` (ASCII) account ids survive parse-time validation.

    Exercises both input paths that read account ids -- the Config aggregator
    path and the CSV path -- with an arbitrary mix of valid and invalid ids, and
    asserts that every id present in the returned ``account_mapping`` matches the
    canonical format and that no supplied invalid value appears anywhere. When
    every id is invalid, ``account_mapping`` is ``None`` and the property holds
    trivially.

    """
    invalid_inputs = {
        aid for _, aid in pairs if CANONICAL_ACCOUNT_ID.match(aid) is None
    }

    # Config aggregator path.
    agg_path = _write_aggregator_file(tmp_path, pairs)
    agg_result = parse_input_file(agg_path)
    _assert_only_canonical(agg_result.account_mapping, invalid_inputs)

    # CSV path (resourceType,accountId header; resource types start with "AWS::").
    csv_path = _write_csv_file(tmp_path, pairs)
    csv_result = parse_input_file(csv_path)
    _assert_only_canonical(csv_result.account_mapping, invalid_inputs)


# --- fail-open preservation of valid data -----------------------
# Reuses the module-level strategies and builders defined
# above (valid_account_id, invalid_account_id, aws_resource_type, cell_value,
# _mixed_account_pairs, _write_aggregator_file, _write_csv_file).


def _expected_valid_ids_by_rt(pairs, normalize):
    """Map each resource type to the set of canonical ids supplied for it.

    The expectation is derived from ``pairs`` independently of the parser:
    validity is decided solely with CANONICAL_ACCOUNT_ID. ``normalize`` mirrors
    the per-path normalization the parser applies to the raw value *before*
    validating it, so the expected set reflects the value each path actually
    sees. The Config aggregator path strips surrounding whitespace; the CSV path
    additionally strips surrounding quotes (its existing
    ``.strip().strip('"').strip("'").strip()`` chain), which can turn an
    otherwise-invalid value such as ``'"123456789012"'`` into a canonical id.
    """
    expected: dict[str, set[str]] = {}
    for rt, aid in pairs:
        norm = normalize(aid)
        if CANONICAL_ACCOUNT_ID.match(norm) is not None:
            expected.setdefault(rt, set()).add(norm)
    return expected


def _parse_without_error(path):
    """Parse ``path``; fail the property if it raises ``InputParserError``.

    Encodes the fail-open guarantee: a rejected account
    id must never turn into a parse error. Any other exception propagates and
    also fails the property ("does not raise at all").
    """
    try:
        return parse_input_file(path)
    except InputParserError as exc:  # pragma: no cover - property failure path
        pytest.fail(f"parse_input_file unexpectedly raised InputParserError: {exc!r}")


def _assert_preserves_valid_data(result, input_resource_types, expected_ids_by_rt):
    """Assert every resource type survives and only the valid ids are retained."""
    result_resource_types = set(result.resource_types)
    missing = input_resource_types - result_resource_types
    assert not missing, f"resource types dropped by fail-open parsing: {missing!r}"

    mapping = result.account_mapping or {}
    for rt in input_resource_types:
        retained = set(mapping.get(rt, []))
        expected = expected_ids_by_rt.get(rt, set())
        assert retained == expected, (
            f"retained ids for {rt!r} != valid ids supplied: "
            f"retained={retained!r} expected={expected!r}"
        )


# Fail-open preservation of valid data
@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(pairs=_mixed_account_pairs())
def test_fail_open_preserves_valid_data(tmp_path, pairs):
    """Valid data survives fail-open validation on both parse paths.

    For any input mixing at least one canonical (12 ASCII digit) account id with
    any number of invalid ones, both the Config aggregator path and the CSV path:
      * parse without raising ``InputParserError`` (and without raising at all);
      * preserve every resource type present in the input; and
      * retain, per resource type, exactly the set of canonical ids supplied for
        it -- invalid values never appear.

    The CSV path only keeps resource types beginning with ``AWS::``; the
    ``aws_resource_type`` strategy guarantees every generated type does, so all
    resource types are expected to survive on both paths. Expected id sets are
    computed from ``pairs`` independently via CANONICAL_ACCOUNT_ID and compared
    as sets, because the parser dedupes ids per resource type.

    """
    # Precondition for "preservation": there must be valid data to preserve, so
    # require at least one canonical id (the all-invalid -> None case is
    # covered separately). A value canonical after stripping can only originate from
    # ``valid_account_id`` -- ``invalid_account_id`` is filtered to exclude any
    # value that strips to the canonical format -- so both paths will retain it.
    assume(any(CANONICAL_ACCOUNT_ID.match(aid.strip()) is not None for _, aid in pairs))

    input_resource_types = {rt for rt, _ in pairs}

    # Each path validates the value it actually sees, so mirror its normalization
    # when deriving the expected ids (see _expected_valid_ids_by_rt).
    agg_expected = _expected_valid_ids_by_rt(pairs, lambda a: a.strip())
    csv_expected = _expected_valid_ids_by_rt(
        pairs, lambda a: a.strip().strip('"').strip("'").strip()
    )

    # Config aggregator path.
    agg_result = _parse_without_error(_write_aggregator_file(tmp_path, pairs))
    _assert_preserves_valid_data(agg_result, input_resource_types, agg_expected)

    # CSV path (resourceType,accountId; every resource type starts with "AWS::").
    csv_result = _parse_without_error(_write_csv_file(tmp_path, pairs))
    _assert_preserves_valid_data(csv_result, input_resource_types, csv_expected)


# --- all-invalid input yields a None account mapping ------------
# Reuses the module-level strategies and builders defined
# above (aws_resource_type, invalid_account_id, _write_aggregator_file,
# _write_csv_file, _parse_without_error, CANONICAL_ACCOUNT_ID).


# All-invalid input yields a None account mapping
@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    pairs=st.lists(
        st.tuples(aws_resource_type, invalid_account_id),
        min_size=1,
        max_size=20,
    )
)
@example(
    pairs=[
        ("AWS::EC2::Instance", "<img src=x onerror=alert(document.domain)>"),
        ("AWS::EC2::Instance", "12345|678901"),
        ("AWS::S3::Bucket", "1234567890"),
    ]
)
def test_all_invalid_ids_yield_none_account_mapping(tmp_path, pairs):
    """All-invalid account ids yield ``account_mapping is None`` on both paths.

    Every pair carries a valid ``AWS::``-prefixed resource type (so parsing never
    fails for lack of resource types) but an account id drawn only from
    ``invalid_account_id``. With no id passing validation, ``has_account_data``
    stays ``False`` and the returned ``ParsedInput`` has ``account_mapping is
    None`` -- routing through the same ``None`` branch as the no-account-data
    case -- and no ``InputParserError`` is raised (the resource types are still
    parsed).

    """
    # The CSV path strips surrounding quotes before validating
    # (``.strip().strip('"').strip("'").strip()``), which could turn an otherwise
    # invalid value such as ``'"123456789012"'`` into a canonical id. Require the
    # CSV-normalized value to also fail the canonical format for EVERY id so "all
    # invalid" holds on both paths. The aggregator path, which only strips
    # surrounding whitespace, is already all-invalid by ``invalid_account_id``'s
    # own ``.strip()`` filter (the same normalization subtlety applies).
    assume(
        all(
            CANONICAL_ACCOUNT_ID.match(aid.strip().strip('"').strip("'").strip())
            is None
            for _, aid in pairs
        )
    )

    # Config aggregator path: every id invalid -> account_mapping is None.
    agg_result = _parse_without_error(_write_aggregator_file(tmp_path, pairs))
    assert agg_result.account_mapping is None, (
        "aggregator account_mapping must be None when every account id is "
        f"invalid, got {agg_result.account_mapping!r}"
    )
    assert agg_result.resource_types, "aggregator dropped all resource types"

    # CSV path: same guarantee (resource types start with 'AWS::', so they survive).
    csv_result = _parse_without_error(_write_csv_file(tmp_path, pairs))
    assert csv_result.account_mapping is None, (
        "CSV account_mapping must be None when every account id is invalid, "
        f"got {csv_result.account_mapping!r}"
    )
    assert csv_result.resource_types, "CSV dropped all resource types"


# --- escaper neutralizes structural and markup characters -------
# Unlike the Layer 1 parser tests above, this exercises the Layer 2 Markdown sink
# escaper directly, so it
# imports the helper under test and reuses the module-level ``cell_value``
# strategy (which already folds the known crafted inputs in via
# CRAFTED_INPUTS alongside arbitrary ``st.text()``).

from control_tower_controls_generator.report_generator import _escape_markdown_cell


# The cell escaper neutralizes structural and markup characters
@settings(max_examples=100)
@given(value=cell_value)
@example(value="<img src=x onerror=alert(document.domain)>")
@example(value="| forged |\r\n| injected | row |")
def test_cell_escaper_neutralizes_structural_and_markup_chars(value):
    """``_escape_markdown_cell`` neutralizes every structural / markup character.

    For an arbitrary input string (including the known crafted inputs
    folded into ``cell_value``), the escaped output:

      * contains no carriage return or line feed -- both are stripped, so the
        value cannot break out of its cell onto a new row;
      * contains no unescaped pipe -- every ``|`` is immediately preceded by a
        backslash, so it cannot forge an extra table column or row;
      * contains no raw ``<`` or ``>`` -- markup angle brackets survive only in
        their ``html.escape`` entity form (``&lt;`` / ``&gt;``); and
      * contains no raw ``&`` except as part of an html entity -- since
        ``html.escape`` maps every raw ``&`` to ``&amp;``, ``<`` to ``&lt;`` and
        ``>`` to ``&gt;``, removing those three entity substrings must leave no
        residual ``&``. (``quote=False`` means ``"`` / ``'`` stay raw, so no
        ``&#x27;`` / ``&#39;`` entities appear.)

    """
    out = _escape_markdown_cell(value)

    # 5.4: carriage returns and line feeds are removed entirely.
    assert "\r" not in out, f"carriage return survived escaping: {out!r}"
    assert "\n" not in out, f"line feed survived escaping: {out!r}"

    # 5.3 / 8.3: no unescaped pipe -- every '|' is immediately preceded by '\'.
    for i, ch in enumerate(out):
        if ch == "|":
            assert i > 0 and out[i - 1] == "\\", (
                f"unescaped pipe at index {i} in {out!r}"
            )

    # 5.5 / 8.3: no raw angle brackets remain (only their &lt; / &gt; forms).
    assert "<" not in out and ">" not in out, (
        f"raw angle bracket survived escaping: {out!r}"
    )

    # 5.5: no raw '&' except as part of an html entity. Removing every
    # &amp; / &lt; / &gt; substring must leave no stray '&'.
    residual = out.replace("&amp;", "").replace("&lt;", "").replace("&gt;", "")
    assert "&" not in residual, (
        f"raw '&' remains after removing html entities: {residual!r} (from {out!r})"
    )


# --- escaper is the identity on safe values ---------------------
# This exercises the Layer 2 escaper
# directly and reuses the ``_escape_markdown_cell`` import added above. It
# is the exact converse of the neutralization guarantee: on the "safe
# alphabet" -- any string free of the six characters the escaper rewrites -- the
# escaper is a no-op, so legitimate report cells render byte-for-byte unchanged.

# Safe alphabet: every character EXCEPT the six the escaper rewrites
# (& < > | \r \n). Quotes are deliberately left IN the alphabet: the escaper
# uses ``html.escape(quote=False)``, so ``"`` and ``'`` must pass through
# untouched, and keeping them in the generated space pins that guarantee.
_safe_text = st.text(alphabet=st.characters(blacklist_characters="&<>|\r\n"))


# The cell escaper is the identity on safe values
@settings(max_examples=100)
@given(value=_safe_text)
@example(value="123456789012")  # canonical 12-digit account id
@example(value="arn:aws:controlcatalog:::control/abc123")  # realistic control ARN
@example(value="a\"b'c")  # quotes preserved (quote=False) -> never altered
def test_cell_escaper_is_identity_on_safe_values(value):
    """``_escape_markdown_cell`` is the identity on values with no special chars.

    For any string containing none of the six characters the escaper rewrites --
    ``&``, ``<``, ``>``, ``|``, ``\\r``, ``\\n`` -- every stage of the escaper is
    a no-op: ``html.escape(quote=False)`` changes nothing (no ``& < >`` present,
    and quotes are exempt), there is no ``|`` to backslash-escape, and there is
    no ``\\r``/``\\n`` to strip. The output is therefore byte-for-byte identical
    to the input, so legitimate report cells (12-digit account ids, ARNs,
    ordinary control names, values containing quotes) render exactly as they did
    before the remediation.

    """
    assert _escape_markdown_cell(value) == value, (
        f"escaper altered a safe value: {value!r} -> {_escape_markdown_cell(value)!r}"
    )


# --- rendered rows preserve table structure ---------------------
# This is the primary anti-forgery invariant. Unlike the
# escaper-helper tests above (which test it in isolation) it drives the full
# Markdown renderer through its public entry point ``generate_report`` ->
# ``_render_markdown``, so it needs the report models in addition to the
# module-level ``cell_value`` strategy (which folds the known crafted
# inputs in alongside arbitrary ``st.text()``).

from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    FrameworkAssociation,
    MappedControl,
)
from control_tower_controls_generator.report_generator import generate_report


# Entirely-safe field values used to render the "clean" baseline each arbitrary
# row is measured against. None contains a pipe, backslash, newline, or markup,
# so the baseline carries only the renderer's own structural delimiters.
_SAFE_CONTROL_NAME = "CleanControl"
_SAFE_CONTROL_ARN = "arn:aws:controlcatalog:::control/clean-baseline"
_SAFE_RESOURCE_TYPE = "AWS::EC2::Instance"
_SAFE_ACCOUNT_ID = "123456789012"
_SAFE_FRAMEWORK = ("PCI-DSS-v4.0", "7.2.2")


def _count_structural_pipes(line: str) -> int:
    r"""Count the column-delimiter (structural) pipes in one rendered table row.

    A ``|`` is counted as a structural delimiter iff it is NOT immediately
    preceded by a backslash. This is the exact dual of the Cell_Escaper contract:
    ``_escape_markdown_cell`` rewrites every
    field-content ``|`` as ``\|``, so any pipe originating from an escaped cell
    value is always immediately preceded by a backslash, whereas
    ``_render_markdown`` emits its own delimiters as ``| ``/`` |`` -- every
    structural pipe is preceded by a space (or sits at index 0), never by a
    backslash. Counting pipes that are not backslash-preceded therefore isolates
    exactly the renderer's own delimiters, independent of cell content.

    On the ``\\|`` corner case: a raw field value that already holds a backslash
    immediately before a pipe escapes to ``\\|`` (two backslashes). Consistent
    with the escaper's contract -- which treats every ``|`` "immediately preceded by ``\``"
    as escaped -- that pipe is attributed to the (escaped) cell value, not to the
    renderer's structure, and so is not counted as a forged column. The invariant
    under test is that no cell value can change how many delimiters the renderer
    itself contributes. (A stricter GFM-parser reading that treats ``\\|`` as a
    literal backslash + a live delimiter would assert something beyond the
    escaper's ``|`` -> ``\|`` contract; the escaper does not escape pre-existing
    backslashes, so this test scopes to the same guarantee the escaper provides.)
    """
    return sum(
        1
        for i, ch in enumerate(line)
        if ch == "|" and not (i > 0 and line[i - 1] == "\\")
    )


def _table_body_rows(markdown: str) -> list[str]:
    r"""Return the table's body rows: the lines after the ``|---`` separator.

    ``_render_markdown`` joins its output with ``"\n"`` and the Cell_Escaper
    strips every ``\r``/``\n`` from cell content, so splitting on ``"\n"``
    recovers exactly the physical lines the renderer emitted -- no cell can
    inject an extra one (this is the "one line per entry" guarantee under
    test). We split on ``"\n"`` deliberately rather than using
    ``str.splitlines()`` so that other Unicode line boundaries a cell might carry
    (e.g. ``\v``, ``\f``, ``\u2028``) -- which are not Markdown table-row
    delimiters and which the escaper is not required to strip -- cannot
    masquerade as forged rows. The single trailing blank line the renderer
    appends is dropped.
    """
    lines = markdown.split("\n")
    sep_index = next(i for i, line in enumerate(lines) if line.startswith("|---"))
    body = lines[sep_index + 1 :]
    while body and not body[-1].strip():
        body.pop()
    return body


def _render_entry_body_rows(
    control_name,
    control_arn,
    resource_type,
    account_id,
    framework=None,
):
    """Render a one-entry Markdown report and return its table body rows.

    The four externally-sourced cell fields (control name, ARN, the single
    matched resource type, and the single account id) come from the caller; the
    account id is wired in through ``account_mapping`` keyed by that same
    resource type, exactly as the real pipeline populates it. ``behavior``,
    ``severity`` and the enablement status are fixed, safe, tool-derived values
    (not externally sourced, hence not escaped by the renderer). When
    ``framework`` is a ``(name, item)`` tuple, framework attribution is enabled
    and a single association carrying that pair is attached.
    """
    include_fw = framework is not None
    associations = (
        [FrameworkAssociation(name=framework[0], item=framework[1])]
        if include_fw
        else []
    )
    control = Control(
        arn=control_arn,
        name=control_name,
        description="",
        behavior="Preventive",
        severity="HIGH",
        implementation=ControlImplementation(type="SERVICE_CONTROL_POLICY"),
    )
    mapped = MappedControl(
        control=control,
        matched_resource_types=[resource_type],
        framework_associations=associations,
    )
    markdown = generate_report(
        [mapped],
        enabled_controls=[],
        account_mapping={resource_type: [account_id]},
        output_format="markdown",
        include_framework_attribution=include_fw,
    )
    return _table_body_rows(markdown)


# Rendered rows preserve table structure
@settings(max_examples=100)
@given(
    control_name=cell_value,
    control_arn=cell_value,
    resource_type=cell_value,
    account_id=cell_value,
)
@example(  # exact HTML-injection payload, as the account id
    control_name=_SAFE_CONTROL_NAME,
    control_arn=_SAFE_CONTROL_ARN,
    resource_type=_SAFE_RESOURCE_TYPE,
    account_id="<img src=x onerror=alert(document.domain)>",
)
@example(  # pipe + newline payload shaped like a fully forged extra row
    control_name=_SAFE_CONTROL_NAME,
    control_arn=_SAFE_CONTROL_ARN,
    resource_type=_SAFE_RESOURCE_TYPE,
    account_id="a|b\nc|d|e|f|g|already enabled|",
)
@example(  # pipes / markup pushed through the control name, ARN and resource type too
    control_name="name|with|pipes",
    control_arn="<script>alert(1)</script>",
    resource_type="AWS::S3::Bucket|forged",
    account_id="123456789012",
)
def test_rendered_rows_preserve_table_structure(
    control_name, control_arn, resource_type, account_id
):
    r"""Arbitrary cell content cannot forge extra rows or columns.

    For a single report entry whose externally-sourced fields (control name,
    ARN, matched resource type, account id) hold arbitrary content -- including
    pipes, newlines, and HTML markup drawn from ``cell_value`` -- the Markdown
    renderer must:

      * emit exactly ONE table body line for the entry, so a newline in
        any field cannot break the entry onto a forged second row; and
      * emit exactly the same number of structural ``|`` column delimiters as an
        entry rendered from entirely safe values, so a
        pipe in any field cannot forge an extra column.

    Structural delimiters are counted as pipes not immediately preceded by a
    backslash -- the dual of the Cell_Escaper's ``|`` -> ``\|`` contract
    -- which isolates the renderer's own delimiters
    from escaped cell content. The invariant is checked both without framework
    attribution (7 columns) and with it (8 columns), each arbitrary row compared
    against a clean baseline rendered with identical parameters.

    """
    # --- Without framework attribution (7 columns -> 8 structural pipes) -----
    arbitrary = _render_entry_body_rows(
        control_name, control_arn, resource_type, account_id
    )
    assert len(arbitrary) == 1, (
        f"entry did not render as exactly one line: {arbitrary!r}"
    )
    baseline = _render_entry_body_rows(
        _SAFE_CONTROL_NAME, _SAFE_CONTROL_ARN, _SAFE_RESOURCE_TYPE, _SAFE_ACCOUNT_ID
    )
    assert len(baseline) == 1  # sanity: the safe baseline is itself a single row
    arbitrary_pipes = _count_structural_pipes(arbitrary[0])
    baseline_pipes = _count_structural_pipes(baseline[0])
    assert arbitrary_pipes == baseline_pipes, (
        "arbitrary cell content changed the structural column count "
        f"({arbitrary_pipes} != {baseline_pipes}); row={arbitrary[0]!r}"
    )

    # --- With framework attribution (8 columns -> 9 structural pipes) --------
    # Push arbitrary content through the framework name and item as well; the
    # intentional literal ``<br/>`` separator only appears between multiple
    # associations, so a single association exercises the escaped name/item path.
    arbitrary_fw = _render_entry_body_rows(
        control_name,
        control_arn,
        resource_type,
        account_id,
        framework=(control_name, account_id),
    )
    assert len(arbitrary_fw) == 1, (
        f"framework entry did not render as exactly one line: {arbitrary_fw!r}"
    )
    baseline_fw = _render_entry_body_rows(
        _SAFE_CONTROL_NAME,
        _SAFE_CONTROL_ARN,
        _SAFE_RESOURCE_TYPE,
        _SAFE_ACCOUNT_ID,
        framework=_SAFE_FRAMEWORK,
    )
    arbitrary_fw_pipes = _count_structural_pipes(arbitrary_fw[0])
    baseline_fw_pipes = _count_structural_pipes(baseline_fw[0])
    assert arbitrary_fw_pipes == baseline_fw_pipes, (
        "arbitrary cell content changed the structural column count with "
        f"framework attribution ({arbitrary_fw_pipes} != {baseline_fw_pipes}); "
        f"row={arbitrary_fw[0]!r}"
    )


# --- JSON output is byte-identical ------------------------------
# Like the ordering test, this drives the full report generator
# through its public entry point ``generate_report`` -- but exercises the JSON
# path (``_render_json`` / ``_control_to_json``), which the remediation
# deliberately leaves untouched. It reuses the report models
# (adding ``EnabledControl``) and the module-level ``cell_value`` strategy (which
# folds the known crafted inputs in alongside arbitrary ``st.text()``), and
# it constructs the expected serialization INDEPENDENTLY -- mirroring the
# documented JSON contract by hand rather than calling the renderer -- so the
# assertion proves the renderer's exact bytes, not merely that it agrees with
# itself. The Markdown escaper is never on the JSON path, so arbitrary/crafted
# content must survive verbatim (json-encoded), with no ``\|`` / ``&lt;`` leakage.

from control_tower_controls_generator.models import EnabledControl

# behavior/severity are tool-derived enum-like fields (never externally-sourced
# free text, never escaped); a small sampled pool keeps them realistic while
# still varying across examples.
_JSON_BEHAVIORS = ["Preventive", "Detective", "Proactive"]
_JSON_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# One generated control's raw field data. control name, ARN, each resource type,
# and each framework (name, item) are drawn from ``cell_value`` so arbitrary and
# crafted-input content flows into every externally-sourced JSON field.
_json_control_spec = st.fixed_dictionaries(
    {
        "name": cell_value,
        "arn": cell_value,
        "behavior": st.sampled_from(_JSON_BEHAVIORS),
        "severity": st.sampled_from(_JSON_SEVERITIES),
        "resource_types": st.lists(cell_value, max_size=3),
        "enabled": st.booleans(),
        "assocs": st.lists(st.tuples(cell_value, cell_value), max_size=3),
    }
)


@st.composite
def _json_report_cases(draw):
    """Generate a whole-report case: controls, attribution flag, account map.

    ``account_mapping`` is either ``None`` (accounts render as ``null`` per
    entry) or a dict keyed by a subset of the resource types actually used by the
    generated controls -- keyed off the real types so the renderer's aggregation
    path (the sorted-unique union over ``matched_resource_types``) is genuinely
    exercised -- mapping each to a small list of arbitrary account-value strings.
    Those values may themselves carry payloads; ``generate_report`` does not
    validate account ids (that is Layer 1's job at parse time), so whatever is
    supplied must survive verbatim in the JSON output.
    """
    controls = draw(st.lists(_json_control_spec, min_size=1, max_size=5))
    include_fw = draw(st.booleans())

    rt_pool = sorted({rt for c in controls for rt in c["resource_types"]})
    if rt_pool and draw(st.booleans()):
        keys = draw(
            st.lists(
                st.sampled_from(rt_pool),
                min_size=1,
                max_size=len(rt_pool),
                unique=True,
            )
        )
        account_mapping = {key: draw(st.lists(cell_value, max_size=3)) for key in keys}
    else:
        account_mapping = None

    return {
        "controls": controls,
        "include_fw": include_fw,
        "account_mapping": account_mapping,
    }


def _build_json_report_inputs(case):
    """Build the ``generate_report`` arguments from a raw ``case`` dict.

    Constructs the model objects in the case's control order (the renderer sorts
    them itself). ``enabled_controls`` carries the ARN of every control flagged
    ``enabled`` so enablement is resolved by ARN membership, exactly as
    ``generate_report`` does.
    """
    mapped = [
        MappedControl(
            control=Control(
                arn=c["arn"],
                name=c["name"],
                description="",
                behavior=c["behavior"],
                severity=c["severity"],
                implementation=ControlImplementation(type="SERVICE_CONTROL_POLICY"),
            ),
            matched_resource_types=list(c["resource_types"]),
            framework_associations=[
                FrameworkAssociation(name=n, item=i) for n, i in c["assocs"]
            ],
        )
        for c in case["controls"]
    ]
    enabled_controls = [
        EnabledControl(control_arn=c["arn"]) for c in case["controls"] if c["enabled"]
    ]
    return mapped, enabled_controls, case["account_mapping"]


def _expected_json_output(case):
    """Independently construct the expected JSON-ready dict for ``case``.

    Mirrors ``generate_report`` + ``_render_json`` + ``_control_to_json`` by hand
    (NOT by calling them): controls sorted by name (Python's stable sort, as the
    renderer uses), enablement by ARN membership in the enabled set, per-entry
    accounts aggregated from ``account_mapping`` as the sorted-unique union over
    the entry's resource types (``None`` when the mapping is ``None``, ``[]`` when
    the union is empty), camelCase keys inserted in the exact order the renderer
    uses, the ``frameworks`` key present iff attribution is on, and ``message``
    null when controls exist. Building this by hand -- rather than reusing the
    renderer -- is what makes the byte-for-byte assertion meaningful.
    """
    controls = case["controls"]
    include_fw = case["include_fw"]
    account_mapping = case["account_mapping"]

    enabled_arns = {c["arn"] for c in controls if c["enabled"]}
    sorted_controls = sorted(controls, key=lambda c: c["name"])

    entries = []
    for c in sorted_controls:
        status = "already enabled" if c["arn"] in enabled_arns else "not enabled"
        if account_mapping is None:
            accounts = None
        else:
            account_set: set[str] = set()
            for rt in c["resource_types"]:
                if rt in account_mapping:
                    account_set.update(account_mapping[rt])
            accounts = sorted(account_set) if account_set else []
        entry = {
            "controlName": c["name"],
            "controlArn": c["arn"],
            "behavior": c["behavior"],
            "severity": c["severity"],
            "matchedResourceTypes": list(c["resource_types"]),
            "accounts": accounts,
            "enablementStatus": status,
        }
        if include_fw:
            entry["frameworks"] = [{"name": n, "item": i} for n, i in c["assocs"]]
        entries.append(entry)

    already_enabled = sum(
        1 for e in entries if e["enablementStatus"] == "already enabled"
    )
    total_recommended = len(entries)
    return {
        "summary": {
            "totalRecommended": total_recommended,
            "alreadyEnabled": already_enabled,
            "gaps": total_recommended - already_enabled,
        },
        "controls": entries,
        "message": None,
    }


# JSON output is byte-identical
@settings(max_examples=100)
@given(case=_json_report_cases())
@example(  # HTML-injection payload as a control name AND an account
    case={
        "controls": [
            {
                "name": "<img src=x onerror=alert(document.domain)>",
                "arn": "arn:aws:controlcatalog:::control/payload",
                "behavior": "Preventive",
                "severity": "HIGH",
                "resource_types": ["AWS::S3::Bucket"],
                "enabled": False,
                "assocs": [],
            }
        ],
        "include_fw": False,
        "account_mapping": {
            "AWS::S3::Bucket": [
                "123456789012",
                "<img src=x onerror=alert(document.domain)>",
            ]
        },
    }
)
@example(  # pipe + newline payloads through control name, ARN, and account values (with attribution)
    case={
        "controls": [
            {
                "name": "name|with|pipes\nsecond line",
                "arn": "a|b\r\nc",
                "behavior": "Detective",
                "severity": "LOW",
                "resource_types": ["AWS::EC2::Instance"],
                "enabled": True,
                "assocs": [("PCI-DSS-v4.0", "7.2.2")],
            }
        ],
        "include_fw": True,
        "account_mapping": {
            "AWS::EC2::Instance": ["acct | Forged | Column", "row1\nrow2"]
        },
    }
)
@example(  # multiple controls (exercises name sort), markup in framework name/item, accounts None
    case={
        "controls": [
            {
                "name": "zeta-control",
                "arn": "arn:aws:controlcatalog:::control/zeta",
                "behavior": "Proactive",
                "severity": "CRITICAL",
                "resource_types": [],
                "enabled": False,
                "assocs": [("<script>alert(1)</script>", "a|b")],
            },
            {
                "name": "alpha-control",
                "arn": "arn:aws:controlcatalog:::control/alpha",
                "behavior": "Preventive",
                "severity": "MEDIUM",
                "resource_types": [],
                "enabled": True,
                "assocs": [],
            },
        ],
        "include_fw": True,
        "account_mapping": None,
    }
)
def test_json_output_is_byte_identical(case):
    r"""JSON render equals an independently constructed byte-for-byte reference.

    For arbitrary generated report data -- control names, ARNs, resource types,
    accounts, and framework name/item all drawn from ``cell_value`` (including
    the ``<img .../>``, pipe, and newline crafted inputs) -- the JSON string
    produced by ``generate_report(..., output_format="json")`` must be
    byte-for-byte identical to a reference serialization built here by hand from
    the same data. The reference mirrors the documented JSON contract exactly
    (camelCase keys in insertion order, controls sorted by name, per-entry
    accounts as the sorted-unique union over the entry's resource types or
    ``null`` when unmapped, ``frameworks`` present only under attribution,
    ``message`` null when controls exist) but is constructed WITHOUT calling the
    renderer, so agreement proves the renderer's bytes rather than mere internal
    consistency.

    Because the Markdown Cell_Escaper is never applied on the JSON path, this
    also proves there is no escaping leakage: every externally-sourced value
    round-trips verbatim (json-encoded), never in the escaper's ``\|`` / ``&lt;``
    / ``&gt;`` / ``&amp;`` form. The explicit ``@example``s pin the crafted
    inputs through both a control name and an account value, with and without
    framework attribution, to make that guarantee concrete.

    """
    mapped, enabled_controls, account_mapping = _build_json_report_inputs(case)

    output = generate_report(
        mapped,
        enabled_controls=enabled_controls,
        account_mapping=account_mapping,
        output_format="json",
        include_framework_attribution=case["include_fw"],
    )
    expected = _expected_json_output(case)

    # (1) Byte-for-byte identical to the independent reference serialization.
    assert output == json.dumps(expected, indent=2), (
        "JSON renderer output diverged from the independent reference "
        f"serialization:\n{output!r}\n!=\n{json.dumps(expected, indent=2)!r}"
    )

    # (2) Output is valid JSON that round-trips back to the expected structure.
    parsed = json.loads(output)
    assert parsed == expected, (
        f"JSON output did not round-trip to the expected structure: {parsed!r}"
    )

    # (3) No Markdown-escaping leakage: each externally-sourced value is stored
    #     verbatim, never in the escaper's form. ``_escape_markdown_cell`` is used
    #     only as an oracle for "what escaping WOULD produce" -- the JSON value
    #     must differ from it whenever escaping would have changed the value.
    raw_accounts = {a for vals in (account_mapping or {}).values() for a in vals}
    for spec, rendered in zip(
        sorted(case["controls"], key=lambda c: c["name"]), parsed["controls"]
    ):
        for key, raw in (("controlName", spec["name"]), ("controlArn", spec["arn"])):
            assert rendered[key] == raw, (
                f"JSON altered {key}: {rendered[key]!r} != raw {raw!r}"
            )
            escaped = _escape_markdown_cell(raw)
            if escaped != raw:
                assert rendered[key] != escaped, (
                    f"{key} carries Markdown-escaping artifacts in JSON: "
                    f"{rendered[key]!r}"
                )
        if isinstance(rendered["accounts"], list):
            assert set(rendered["accounts"]) <= raw_accounts, (
                "JSON accounts contain a value not present verbatim in the input "
                f"(markdown-escaping leakage): {rendered['accounts']!r}"
            )
