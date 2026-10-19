"""Property-based test for the OU-id parameter case-sensitivity bugfix.

Covers camelCase response-key collection: for any successful ``ListEnabledControls`` response,
exactly one ``EnabledControl`` is returned per non-empty ``controlIdentifier``
found under each page's ``enabledControls`` key, in page-then-item order, and
nothing is printed.

The unit under test is the pure helper
``control_tower_controls_generator.enabled_controls_retriever._collect_enabled_controls``,
which ``retrieve_enabled_controls`` calls with the paginator. Exercising the
pure helper keeps the property fast: no boto3 client and no stubbing is needed
per Hypothesis example.

Generation is deliberately wide-ranging rather than nominal. It spans empty page
sequences, pages with zero items, items whose ``controlIdentifier`` is absent or
present-but-empty, repeated identifiers within and across pages, unrelated
sibling keys on both pages and items, and -- the regression guard for this
bugfix -- the PascalCase ``EnabledControls`` / ``ControlIdentifier`` keys that
unfixed code read, which must now be ignored entirely.

All Hypothesis strategies are defined locally in this module by design so the
file stays self-contained and does not collide with other parallel test tasks.
"""

import io
from contextlib import redirect_stderr, redirect_stdout

from hypothesis import example, given, settings
from hypothesis import strategies as st

from control_tower_controls_generator.enabled_controls_retriever import (
    _collect_enabled_controls,
)
from control_tower_controls_generator.models import EnabledControl


# --- Keys under test ---------------------------------------------------------

# The camelCase keys the `controltower` service model defines. These are the
# only two keys the helper is allowed to read.
_PAGE_KEY = "enabledControls"
_ITEM_KEY = "controlIdentifier"

# The PascalCase keys unfixed code read, which the service model does not
# define. Nothing beneath them may ever be collected; generating them is what
# stops the old behavior creeping back.
_PASCAL_PAGE_KEY = "EnabledControls"
_PASCAL_ITEM_KEY = "ControlIdentifier"

# Sibling keys the real service returns alongside the ones under test. None of
# them may influence the result.
_ITEM_SIBLING_KEYS = ("arn", "statusSummary", "driftStatusSummary", "parentIdentifier")
_PAGE_SIBLING_KEYS = ("nextToken", "ResponseMetadata")


# --- Local Hypothesis strategies --------------------------------------------

# A small pool of realistic identifiers, drawn from repeatedly so the same ARN
# recurs within and across pages without being contrived. Both the Control
# Tower and the Control Catalog ARN namespaces appear, because the helper copies
# whatever string it finds and makes no claim about which namespace it is in.
_ARN_POOL = (
    "arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES",
    "arn:aws:controltower:us-west-2::control/AWS-GR_RESTRICTED_SSH",
    "arn:aws:controlcatalog:::control/1a2b3c4d5e6f7g8h9i0j",
)
_pooled_arn = st.sampled_from(_ARN_POOL)

# Widen well past realistic ARNs: the helper copies the value verbatim, so any
# non-empty string must come back unchanged. Whitespace-only text is included
# deliberately -- it is non-empty, so the contract says it is collected.
_arbitrary_arn = st.text(min_size=1, max_size=40)

_non_empty_identifier = st.one_of(_pooled_arn, _arbitrary_arn)

# Values for the unrelated sibling keys. Shapes vary (the real service returns
# a dict for `statusSummary` and a string for `nextToken`) because the point is
# that the helper never looks at them.
_sibling_value = st.one_of(
    st.none(),
    st.text(max_size=20),
    st.integers(),
    st.dictionaries(st.text(min_size=1, max_size=8), st.text(max_size=8), max_size=2),
)

# How a single `enabledControls` entry is shaped:
#   camel                  -- the well-formed case, collected
#   camel_empty            -- present but empty, skipped
#   absent                 -- no identifier key at all, skipped
#   pascal_only            -- only the PascalCase key, skipped (regression guard)
#   both_keys              -- both keys present, only the camelCase one collected
#   pascal_with_camel_empty -- camelCase empty next to a populated PascalCase
#                              key, which must NOT be used as a fallback
_ITEM_KINDS = (
    "camel",
    "camel_empty",
    "absent",
    "pascal_only",
    "both_keys",
    "pascal_with_camel_empty",
)

# How a single response page is shaped:
#   camel       -- carries `enabledControls`
#   camel_empty -- carries `enabledControls: []`, a page with zero items
#   pascal      -- carries only `EnabledControls` (regression guard)
#   both        -- carries both page keys, only the camelCase one is read
#   missing     -- carries no controls key at all
_PAGE_KINDS = ("camel", "camel_empty", "pascal", "both", "missing")


@st.composite
def _items(draw):
    """Generate an ``(item, expected_arns)`` pair for one ``enabledControls`` entry.

    ``expected_arns`` is the contribution this item makes to the collected
    result -- a one-element list for a well-formed item and an empty list for
    every skipped shape. Building it here, from the values as drawn, keeps the
    assertions comparing against an independent source of truth rather than
    re-reading the item under test.
    """
    kind = draw(st.sampled_from(_ITEM_KINDS))
    item: dict = {}
    expected: list[str] = []

    if kind == "camel":
        arn = draw(_non_empty_identifier)
        item[_ITEM_KEY] = arn
        expected.append(arn)
    elif kind == "camel_empty":
        item[_ITEM_KEY] = ""
    elif kind == "absent":
        pass
    elif kind == "pascal_only":
        item[_PASCAL_ITEM_KEY] = draw(_non_empty_identifier)
    elif kind == "both_keys":
        arn = draw(_non_empty_identifier)
        item[_ITEM_KEY] = arn
        item[_PASCAL_ITEM_KEY] = draw(_non_empty_identifier)
        expected.append(arn)
    elif kind == "pascal_with_camel_empty":
        item[_ITEM_KEY] = ""
        item[_PASCAL_ITEM_KEY] = draw(_non_empty_identifier)

    sibling_keys = draw(
        st.lists(st.sampled_from(_ITEM_SIBLING_KEYS), unique=True, max_size=4)
    )
    for key in sibling_keys:
        item[key] = draw(_sibling_value)

    return item, expected


@st.composite
def _pages(draw):
    """Generate a ``(page, expected_arns)`` pair for one response page."""
    kind = draw(st.sampled_from(_PAGE_KINDS))
    page: dict = {}
    expected: list[str] = []

    if kind in ("camel", "both"):
        drawn = draw(st.lists(_items(), max_size=5))
        page[_PAGE_KEY] = [item for item, _ in drawn]
        for _, arns in drawn:
            expected.extend(arns)

    if kind in ("pascal", "both"):
        # Items beneath the PascalCase page key are invisible to the helper, so
        # their identifiers never join `expected`.
        pascal_items = draw(st.lists(_items(), max_size=3))
        page[_PASCAL_PAGE_KEY] = [item for item, _ in pascal_items]

    if kind == "camel_empty":
        page[_PAGE_KEY] = []

    # kind == "missing" leaves the page with no controls key at all.

    sibling_keys = draw(
        st.lists(st.sampled_from(_PAGE_SIBLING_KEYS), unique=True, max_size=2)
    )
    for key in sibling_keys:
        page[key] = draw(_sibling_value)

    return page, expected


@st.composite
def _page_sequences(draw):
    """Generate a ``(pages, expected_arns)`` pair for a whole paginated response.

    ``max_size`` starts at zero, so the empty page sequence is part of the
    generated space rather than a separate case.
    """
    drawn = draw(st.lists(_pages(), max_size=5))
    pages = [page for page, _ in drawn]
    expected = [arn for _, arns in drawn for arn in arns]
    return pages, expected


@st.composite
def _pascal_only_page_sequences(draw):
    """Generate page sequences whose only controls keys are PascalCase.

    Every such sequence must collect nothing, whatever it carries beneath those
    keys. This is the same property on the subspace where the pre-fix behavior would
    have been indistinguishable from the fixed behavior only by returning the
    wrong values.
    """
    pages = []
    for _ in range(draw(st.integers(min_value=1, max_value=4))):
        drawn = draw(st.lists(_items(), min_size=1, max_size=4))
        page: dict = {_PASCAL_PAGE_KEY: [item for item, _ in drawn]}
        sibling_keys = draw(
            st.lists(st.sampled_from(_PAGE_SIBLING_KEYS), unique=True, max_size=2)
        )
        for key in sibling_keys:
            page[key] = draw(_sibling_value)
        pages.append(page)
    return pages


@st.composite
def _repeated_identifier_page_sequences(draw):
    """Generate page sequences guaranteed to repeat at least one identifier.

    The repeat is appended by construction rather than left to chance, so the
    no-de-duplication assertion can never go vacuous. Identifiers are then
    distributed across pages at generated boundaries, with zero-item pages
    interleaved, so repeats land both within a single page and across pages.
    """
    arns = draw(st.lists(_pooled_arn, min_size=1, max_size=5))
    arns = arns + [draw(st.sampled_from(arns))]

    pages: list[dict] = []
    remaining = list(arns)
    while remaining:
        if draw(st.booleans()):
            pages.append({_PAGE_KEY: []})
        take = draw(st.integers(min_value=1, max_value=len(remaining)))
        chunk, remaining = remaining[:take], remaining[take:]
        pages.append({_PAGE_KEY: [{_ITEM_KEY: arn} for arn in chunk]})

    return pages, arns


# --- Explicit examples -------------------------------------------------------

# The empty page sequence: a paginator that yielded nothing at all.
_NO_PAGES: tuple[list[dict], list[str]] = ([], [])

# Pages with zero items, in both shapes: an empty list and an absent key.
_ZERO_ITEM_PAGES = (
    [{_PAGE_KEY: [], "nextToken": "t"}, {"ResponseMetadata": {}}],
    [],
)

# Only PascalCase keys, at both levels. Collecting anything here is the exact
# regression this bugfix guards against.
_PASCAL_ONLY = (
    [
        {_PASCAL_PAGE_KEY: [{_PASCAL_ITEM_KEY: _ARN_POOL[0]}]},
        {_PAGE_KEY: [{_PASCAL_ITEM_KEY: _ARN_POOL[1]}]},
    ],
    [],
)

# A populated PascalCase identifier sitting beside an empty camelCase one: the
# PascalCase value must not be used as a fallback.
_PASCAL_NOT_A_FALLBACK = (
    [{_PAGE_KEY: [{_ITEM_KEY: "", _PASCAL_ITEM_KEY: _ARN_POOL[0]}]}],
    [],
)

# Absent and empty identifiers beside a well-formed one, with sibling keys on
# every item.
_ABSENT_AND_EMPTY = (
    [
        {
            _PAGE_KEY: [
                {"arn": "arn:aws:controltower:us-east-1:111122223333:enabledcontrol/x"},
                {_ITEM_KEY: "", "statusSummary": {"status": "SUCCEEDED"}},
                {_ITEM_KEY: _ARN_POOL[2], "driftStatusSummary": {"driftStatus": "IN_SYNC"}},
                {"parentIdentifier": "ou-abcd-11111111"},
            ]
        }
    ],
    [_ARN_POOL[2]],
)

# Descending lexicographic order across pages, so a sorted or set-based
# implementation cannot satisfy the assertion.
_ORDER_SENSITIVE = (
    [
        {_PAGE_KEY: [{_ITEM_KEY: "zzz-second"}, {_ITEM_KEY: "yyy-third"}]},
        {_PAGE_KEY: [{_ITEM_KEY: "aaa-fourth"}]},
    ],
    ["zzz-second", "yyy-third", "aaa-fourth"],
)

# The same identifier twice inside one page and once more in a later page.
# Aggregation appends; de-duplication belongs downstream in report_generator.
_DUPLICATES_WITHIN_AND_ACROSS = (
    [
        {_PAGE_KEY: [{_ITEM_KEY: _ARN_POOL[0]}, {_ITEM_KEY: _ARN_POOL[0]}]},
        {_PAGE_KEY: [{_ITEM_KEY: _ARN_POOL[1]}]},
        {_PAGE_KEY: [{_ITEM_KEY: _ARN_POOL[0]}]},
    ],
    [_ARN_POOL[0], _ARN_POOL[0], _ARN_POOL[1], _ARN_POOL[0]],
)


# ---


# camelCase Response Keys Are Collected
@settings(max_examples=100)
@given(pages_and_expected=_page_sequences())
@example(pages_and_expected=_NO_PAGES)
@example(pages_and_expected=_ZERO_ITEM_PAGES)
@example(pages_and_expected=_PASCAL_ONLY)
@example(pages_and_expected=_PASCAL_NOT_A_FALLBACK)
@example(pages_and_expected=_ABSENT_AND_EMPTY)
@example(pages_and_expected=_ORDER_SENSITIVE)
@example(pages_and_expected=_DUPLICATES_WITHIN_AND_ACROSS)
def test_collect_returns_non_empty_camel_case_identifiers_in_page_then_item_order(
    pages_and_expected,
):
    """Collection reads the camelCase keys and preserves page-then-item order."""
    pages, expected = pages_and_expected

    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        result = _collect_enabled_controls(pages)

    assert isinstance(result, list)
    assert all(isinstance(control, EnabledControl) for control in result)

    # Positional equality: sequences are compared as sequences, deliberately
    # not as sets and not sorted, so page-then-item order is what is pinned.
    assert [control.control_arn for control in result] == expected

    # One EnabledControl per occurrence, so a repeated identifier is returned
    # once per occurrence and nothing is dropped.
    assert len(result) == len(expected)

    # An absent or empty identifier is skipped rather than yielding an
    # EnabledControl with an empty ARN, which would match nothing downstream.
    assert all(control.control_arn for control in result)

    # A successful collection says nothing.
    assert stderr.getvalue() == ""
    assert stdout.getvalue() == ""


# camelCase Response Keys Are Collected
@settings(max_examples=100)
@given(pages=_pascal_only_page_sequences())
@example(pages=[{_PASCAL_PAGE_KEY: [{_PASCAL_ITEM_KEY: _ARN_POOL[0]}]}])
@example(pages=[{_PASCAL_PAGE_KEY: [{_ITEM_KEY: _ARN_POOL[1]}]}])
def test_pascal_case_keys_are_never_collected(pages):
    """Nothing beneath ``EnabledControls`` is read, however it is shaped.

    The same property on the subspace where only the PascalCase keys the service model
    does not define are present. The pre-fix code read exactly these, so a
    non-empty result here means the old behavior has crept back.
    """
    result = _collect_enabled_controls(pages)

    assert result == []


# camelCase Response Keys Are Collected
@settings(max_examples=100)
@given(pages_and_expected=_repeated_identifier_page_sequences())
@example(pages_and_expected=_DUPLICATES_WITHIN_AND_ACROSS)
def test_repeated_identifiers_are_returned_once_per_occurrence(pages_and_expected):
    """Aggregation appends; it does not de-duplicate.

    The same property on the subspace where identifiers repeat within and across pages.
    ``_collect_enabled_controls`` returns one ``EnabledControl`` per occurrence;
    de-duplication happens downstream in ``report_generator``.
    """
    pages, expected = pages_and_expected

    result = _collect_enabled_controls(pages)
    result_arns = [control.control_arn for control in result]

    assert result_arns == expected

    # Non-vacuous by construction: the drawn sequence always repeats at least
    # one identifier, so a de-duplicating implementation returns a shorter list.
    assert len(result_arns) > len(set(result_arns))
