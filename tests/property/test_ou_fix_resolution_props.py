"""Property-based test for OU identifier resolution.

Over generated
identifier strings spanning valid OU IDs, valid OU ARNs, and neither,
``_resolve_target_identifier`` resolves *exactly* the OU-ID-shaped values --
calling ``organizations:DescribeOrganizationalUnit`` and returning the ARN that
call reports -- and returns everything else verbatim with no Organizations
client constructed at all. The value it hands back is then validated against the
real ``ListEnabledControls`` input shape, which is what "the request reaches the
API" means concretely.

The helper under test is
``control_tower_controls_generator.enabled_controls_retriever._resolve_target_identifier``.
Exercising it directly keeps the property fast: one mocked boto3 per Hypothesis
example, no paginator, no CLI run.

``moto`` does not support ``controltower`` and the clients are constructed
*inside* the module under test, so boto3 is mocked with ``unittest.mock.patch``
on the module's own reference, mirroring
``tests/unit/test_enabled_controls_retriever.py``.

Two facts about the generators are worth stating up front, because both bit
during authoring:

* Appending a character drawn from ``[a-z0-9]`` to an OU ID does **not** make a
  near-miss -- it makes a *different* valid OU ID, since the suffix is
  ``{8,32}`` rather than fixed-width. Trailing-character near-misses therefore
  have to be drawn from outside that alphabet.
* ``_is_bare_ou_id`` below is a hand-written structural check rather than a
  reuse of ``OU_ID_PATTERN``. Asserting the implementation against its own
  regex would be tautological; asserting it against an independent reading of
  the OU ID pattern is not.

All Hypothesis strategies are defined locally in this module by design so the
file stays self-contained and does not collide with other parallel test tasks.
"""

import string
from unittest.mock import MagicMock, patch

import botocore.session
from botocore.validate import ParamValidator
from hypothesis import example, given, settings
from hypothesis import strategies as st

from control_tower_controls_generator.enabled_controls_retriever import (
    _resolve_target_identifier,
)


BOTO3_TARGET = "control_tower_controls_generator.enabled_controls_retriever.boto3"

#: The OU from the bug report and the ARN form the design uses for it.
BUG_REPORT_OU_ID = "ou-tito-abcd1234"
BUG_REPORT_OU_ARN = "arn:aws:organizations::111122223333:ou/o-abc123/ou-tito-abcd1234"

#: ``[0-9a-z]`` and ``[a-z0-9]`` from the OU ID pattern are the same set.
OU_CHARS = string.ascii_lowercase + string.digits

#: Both ends of the pattern's range, so the boundaries are always exercised
#: rather than merely reachable: ``{4,32}`` middle and ``{8,32}`` suffix.
MIN_OU_ID = f"ou-{'a' * 4}-{'b' * 8}"
MAX_OU_ID = f"ou-{'a' * 32}-{'b' * 32}"


# --- the real service model ---------------------------------------------------

#: The shipped ``ListEnabledControls`` input shape, so the acceptance check is
#: the one the SDK actually enforces.
LIST_ENABLED_CONTROLS_INPUT_SHAPE = (
    botocore.session.get_session()
    .get_service_model("controltower")
    .operation_model("ListEnabledControls")
    .input_shape
)


def _validation_report(params: dict) -> str:
    """botocore's own validation report for ``params``; empty when acceptable."""
    return (
        ParamValidator()
        .validate(params, LIST_ENABLED_CONTROLS_INPUT_SHAPE)
        .generate_report()
    )


# --- the independent oracle ---------------------------------------------------

def _is_bare_ou_id(value: str) -> bool:
    """Structural reading of the OU ID pattern ``^ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}$``.

    Deliberately does not reuse ``OU_ID_PATTERN``, so the property compares the
    implementation against an independent source of truth instead of against
    itself. Anchoring is expressed by requiring exactly three ``-``-separated
    segments with nothing outside them.
    """
    parts = value.split("-")
    if len(parts) != 3:
        return False

    prefix, middle, suffix = parts
    return (
        prefix == "ou"
        and 4 <= len(middle) <= 32
        and 8 <= len(suffix) <= 32
        and all(char in OU_CHARS for char in middle)
        and all(char in OU_CHARS for char in suffix)
    )


# --- local Hypothesis strategies ----------------------------------------------

# The pattern's full range, not just the bug report's shape.
_middles = st.text(alphabet=OU_CHARS, min_size=4, max_size=32)
_suffixes = st.text(alphabet=OU_CHARS, min_size=8, max_size=32)

_ou_ids = st.builds(lambda m, s: f"ou-{m}-{s}", _middles, _suffixes)

# Every partition here starts with "aws", which the shape's own
# `pattern: arn:aws[0-9a-zA-Z_\-:\/]+` requires.
_partitions = st.sampled_from(("aws", "aws-us-gov", "aws-cn"))
_account_ids = st.text(alphabet=string.digits, min_size=12, max_size=12)
_org_ids = st.builds(
    lambda s: f"o-{s}", st.text(alphabet=OU_CHARS, min_size=10, max_size=32)
)

#: ``arn:{partition}:organizations::{management-account-id}:ou/{o-id}/{ou-id}``.
_ou_arns = st.builds(
    lambda partition, account, org, ou: (
        f"arn:{partition}:organizations::{account}:ou/{org}/{ou}"
    ),
    _partitions,
    _account_ids,
    _org_ids,
    _ou_ids,
)

#: Characters that break the pattern when appended, i.e. outside ``[a-z0-9]``.
#: ``\n`` is excluded on purpose -- see
#: ``test_pattern_as_written_admits_a_trailing_newline``.
_BREAKING_CHARS = st.sampled_from(list(" XZ_.,/:*+@#-"))

_NEAR_MISS_KINDS = (
    "wrong_prefix",
    "uppercase_prefix",
    "short_middle",
    "long_middle",
    "short_suffix",
    "long_suffix",
    "uppercase_middle",
    "uppercase_suffix",
    "embedded_space",
    "leading_chars",
    "trailing_chars",
    "contained_in_text",
    "extra_segment",
    "missing_separator",
)


@st.composite
def _near_miss_ou_ids(draw):
    """Strings shaped almost like an OU ID that must NOT be resolved.

    Each mutation is constructed so the independent oracle rejects it, covering
    the near-miss classes: wrong prefix, out-of-range segment
    lengths, uppercase, embedded whitespace, and an OU ID carrying leading or
    trailing characters (including one merely *contained* in a longer string,
    which the anchoring in the pattern is what excludes).
    """
    middle = draw(_middles)
    suffix = draw(_suffixes)
    kind = draw(st.sampled_from(_NEAR_MISS_KINDS))

    if kind == "wrong_prefix":
        prefix = draw(st.sampled_from(("o", "uo", "oou", "ouu", "r", "acct")))
        return f"{prefix}-{middle}-{suffix}"
    if kind == "uppercase_prefix":
        return f"{draw(st.sampled_from(('OU', 'Ou', 'oU')))}-{middle}-{suffix}"
    if kind == "short_middle":
        return f"ou-{draw(st.text(alphabet=OU_CHARS, max_size=3))}-{suffix}"
    if kind == "long_middle":
        return f"ou-{draw(st.text(alphabet=OU_CHARS, min_size=33, max_size=40))}-{suffix}"
    if kind == "short_suffix":
        return f"ou-{middle}-{draw(st.text(alphabet=OU_CHARS, max_size=7))}"
    if kind == "long_suffix":
        return f"ou-{middle}-{draw(st.text(alphabet=OU_CHARS, min_size=33, max_size=40))}"
    if kind == "uppercase_middle":
        # Inserted rather than upper-cased in place: an all-digit middle is
        # unchanged by .upper() and would still be a valid OU ID.
        upper = draw(st.sampled_from(list(string.ascii_uppercase)))
        return f"ou-{middle[:1]}{upper}{middle[1:]}-{suffix}"
    if kind == "uppercase_suffix":
        upper = draw(st.sampled_from(list(string.ascii_uppercase)))
        return f"ou-{middle}-{suffix[:1]}{upper}{suffix[1:]}"
    if kind == "embedded_space":
        return f"ou-{middle[:1]} {middle[1:]}-{suffix}"
    if kind == "leading_chars":
        return f"{draw(_BREAKING_CHARS)}ou-{middle}-{suffix}"
    if kind == "trailing_chars":
        return f"ou-{middle}-{suffix}{draw(_BREAKING_CHARS)}"
    if kind == "contained_in_text":
        return f"target is ou-{middle}-{suffix} today"
    if kind == "extra_segment":
        return f"ou-{middle}-{suffix}-{suffix}"
    # missing_separator
    return f"ou{middle}-{suffix}"


#: Identifier forms unrelated to the OU ID shape. ``ListEnabledControls`` targets
#: accounts too, so these must reach the API unrewritten.
_other_identifiers = st.one_of(
    st.just(""),
    st.just("arn:aws:organizations::111122223333:account/o-abc123/444455556666"),
    st.just("arn:aws:controltower:us-west-2::control/AWS-GR_RESTRICT_ROOT_USER"),
    st.builds(lambda s: f"r-{s}", st.text(alphabet=OU_CHARS, min_size=4, max_size=32)),
    st.text(alphabet=string.digits, min_size=12, max_size=12),
    st.text(max_size=40),
)


def _labelled(identifier: str) -> tuple[str, str]:
    """Label an identifier the generators did not construct as an OU ID.

    The broad text strategy can in principle land on a well-formed OU ID, so the
    label is derived from the independent oracle rather than assumed.
    """
    return identifier, "ou_id" if _is_bare_ou_id(identifier) else "neither"


#: ``(identifier, kind)`` pairs spanning the input classes, as four balanced
#: branches so near-misses get real generated coverage rather than only the
#: explicit ``@example`` cases. ``kind`` is the class the identifier was
#: *constructed* as, so the assertions compare behavior against the generator's
#: intent instead of re-deriving the expectation from the value under test; it is
#: cross-checked against ``_is_bare_ou_id`` in the property body, so a generator
#: that drifts is caught rather than silently weakening the test.
_identifiers = st.one_of(
    _ou_ids.map(lambda v: (v, "ou_id")),
    _ou_arns.map(lambda v: (v, "ou_arn")),
    _near_miss_ou_ids().map(_labelled),
    _other_identifiers.map(_labelled),
)


# --- the mocked boto3 ---------------------------------------------------------

class _Boto3Recorder:
    """Records how ``_resolve_target_identifier`` used its ``boto3`` reference."""

    def __init__(self, reported_arn: str) -> None:
        self.client_calls: list[tuple[tuple, dict]] = []
        self.organizations = MagicMock(name="organizations_client")
        self.organizations.describe_organizational_unit.side_effect = (
            lambda **kwargs: {
                "OrganizationalUnit": {
                    "Id": kwargs.get("OrganizationalUnitId"),
                    "Arn": reported_arn,
                    "Name": "Sandbox",
                }
            }
        )

    @property
    def services(self) -> list[str]:
        """Service names passed to ``boto3.client``, in construction order."""
        return [args[0] for args, _ in self.client_calls if args]


def _wire(mock_boto3: MagicMock, reported_arn: str) -> _Boto3Recorder:
    """Point a mocked ``boto3`` at a recorder reporting ``reported_arn``."""
    recorder = _Boto3Recorder(reported_arn)

    def _client(*args, **kwargs):
        recorder.client_calls.append((args, dict(kwargs)))
        return recorder.organizations

    mock_boto3.client.side_effect = _client
    return recorder


def _reported_arn_for(identifier: str) -> str:
    """The ARN ``DescribeOrganizationalUnit`` is stubbed to report back.

    Derived from the identifier so a resolved value is traceable to its input,
    and always distinct from that input so ``resolved == reported_arn`` is a
    real assertion rather than an accident of equality.
    """
    return f"arn:aws:organizations::111122223333:ou/o-abc1234567/{identifier}"


# --- the two halves of the resolution contract --------------------------------

def _assert_resolved_through_organizations(ou_id: str) -> None:
    """An OU ID is resolved to the ARN ``DescribeOrganizationalUnit`` reports.

    The ARN is read from the response rather than assembled locally, which would
    require separately discovering the organization ID, the management account
    ID, and the partition.
    """
    reported_arn = _reported_arn_for(ou_id)

    with patch(BOTO3_TARGET) as mock_boto3:
        recorder = _wire(mock_boto3, reported_arn)
        resolved = _resolve_target_identifier(ou_id)

    assert recorder.services == ["organizations"], (
        "a bare OU ID cannot satisfy targetIdentifier's ARN typing, so it must "
        f"be resolved; clients built: {recorder.services}"
    )
    recorder.organizations.describe_organizational_unit.assert_called_once_with(
        OrganizationalUnitId=ou_id
    )
    assert resolved == reported_arn, (
        "the ARN the API reports is what must be bound, not one assembled "
        f"locally; got {resolved!r}"
    )
    assert _validation_report({"targetIdentifier": resolved}) == "", (
        "the resolved value has to survive botocore's client-side validation "
        f"or the request never leaves the process: {resolved!r}"
    )

    if len(ou_id) < 20:
        # The measured reason resolution is required at all. botocore validates
        # `min` but not `pattern`, so a bare OU ID is only caught client-side
        # while it is shorter than 20 characters; a longer one would leave the
        # process and be rejected by the service instead.
        assert "valid min length: 20" in _validation_report(
            {"targetIdentifier": ou_id}
        ), f"expected the unresolved OU ID {ou_id!r} to fail the min check"


def _assert_passed_through_verbatim(identifier: str) -> None:
    """Anything that is not a bare OU ID reaches the API unrewritten.

    No Organizations client is constructed at all, so no identifier form the API
    accepts is rewritten and no needless permission is exercised.
    """
    with patch(BOTO3_TARGET) as mock_boto3:
        recorder = _wire(mock_boto3, _reported_arn_for(identifier))
        resolved = _resolve_target_identifier(identifier)

    assert mock_boto3.client.call_count == 0, (
        f"{identifier!r} is not a bare OU ID, so nothing should be resolved; "
        f"clients built: {recorder.services}"
    )
    assert resolved == identifier, (
        "an identifier the pattern does not recognise must reach the API "
        f"unrewritten; got {resolved!r}"
    )


# ---
#
# Split across two test functions covering the same property from both sides:
# the one below generates only OU IDs, so the pattern's full ``{4,32}`` /
# ``{8,32}`` range is covered by every example rather than by whichever share of
# a mixed draw happens to land there; the one after it generates across all
# three input classes, which is what establishes that resolution fires for
# *exactly* the OU-ID-shaped values.


# Request Reaches the API With a
# Valid targetIdentifier (full-range half)
@settings(max_examples=100)
@given(ou_id=_ou_ids)
# The bug report's own OU, and both ends of the pattern's range.
@example(ou_id=BUG_REPORT_OU_ID)
@example(ou_id=MIN_OU_ID)
@example(ou_id=MAX_OU_ID)
@example(ou_id=f"ou-{'a' * 4}-{'b' * 32}")
@example(ou_id=f"ou-{'a' * 32}-{'b' * 8}")
# All-digit and mixed segments: the alphabet is [0-9a-z], not just letters.
@example(ou_id="ou-1234-56789012")
@example(ou_id="ou-a1b2-c3d4e5f6")
def test_every_ou_id_in_the_pattern_range_is_resolved(ou_id):
    """Across the pattern's full range, an OU ID is resolved to its ARN."""
    assert _is_bare_ou_id(ou_id), f"generator produced a non-OU-ID: {ou_id!r}"

    _assert_resolved_through_organizations(ou_id)

# Request Reaches the API With a
# Valid targetIdentifier (discrimination half)
@settings(max_examples=100)
@given(labelled=_identifiers)
# The bug report's own OU, both forms, always covered.
@example(labelled=(BUG_REPORT_OU_ID, "ou_id"))
@example(labelled=(BUG_REPORT_OU_ARN, "ou_arn"))
# Both ends of the pattern's range.
@example(labelled=(MIN_OU_ID, "ou_id"))
@example(labelled=(MAX_OU_ID, "ou_id"))
# Appending an in-alphabet character widens the suffix instead of breaking the
# match, so this is a *different valid OU ID* rather than a near-miss.
@example(labelled=(f"{BUG_REPORT_OU_ID}x", "ou_id"))
# Anchoring: an OU ID with anything around it is not an OU ID.
@example(labelled=(f"{BUG_REPORT_OU_ID}/", "neither"))
@example(labelled=(f"x{BUG_REPORT_OU_ID}", "neither"))
@example(labelled=(f"ou for comparison: {BUG_REPORT_OU_ID}", "neither"))
# Out-of-range segments, uppercase, and whitespace.
@example(labelled=("ou-tito-abcd123", "neither"))
@example(labelled=("ou-tit-abcd1234", "neither"))
@example(labelled=("OU-tito-abcd1234", "neither"))
@example(labelled=("ou-TITO-abcd1234", "neither"))
@example(labelled=("ou-tito abcd1234", "neither"))
@example(labelled=("o-tito-abcd1234", "neither"))
def test_resolution_matches_the_identifier_form(labelled):
    """Exactly the OU-ID-shaped values are resolved; everything else passes through.

    Three things are asserted per example:

    1. An OU ID is resolved through ``organizations:DescribeOrganizationalUnit``
       and the ARN that call *reports* is what comes back.
    2. Anything else comes back verbatim with no Organizations client
       constructed at all.
    3. Whenever the input was an OU ID or a valid OU ARN, the value bound to
       ``targetIdentifier`` passes botocore's validation against the real
       ``ListEnabledControls`` input shape -- which is what makes the
       "reaches the API" behavior reachable.
    """
    identifier, kind = labelled

    assert _is_bare_ou_id(identifier) is (kind == "ou_id"), (
        f"generator and oracle disagree about {identifier!r} (labelled {kind!r})"
    )

    if kind == "ou_id":
        _assert_resolved_through_organizations(identifier)
    else:
        _assert_passed_through_verbatim(identifier)

    if kind == "ou_arn":
        # A valid OU ARN already satisfies the parameter's typing, which is why
        # passing it through verbatim is correct rather than merely tolerated.
        assert _validation_report({"targetIdentifier": identifier}) == "", (
            f"a well-formed OU ARN must validate clean: {identifier!r}"
        )


def test_pattern_as_written_admits_a_trailing_newline():
    """Records where the pattern and the "anchored" reading of it diverge.

    The requirement specifies the trigger as the literal pattern
    ``^ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}$``. In Python, ``$`` also matches just
    *before* a trailing newline, so ``"ou-tito-abcd1234\\n"`` matches the
    pattern as written even though it is not structurally an OU ID. Resolution
    therefore fires for it.

    This is pinned rather than asserted away because it follows from the
    requirement's own text, and because the consequence is benign: AWS
    Organizations rejects the newline-bearing ID with ``InvalidInputException``,
    which the fix surfaces as a ``RuntimeError`` -- a loud failure, not a wrong
    comparison. Switching the anchor to ``\\Z`` would close it, which is a
    requirement change and so out of scope here.
    """
    identifier = f"{BUG_REPORT_OU_ID}\n"

    assert not _is_bare_ou_id(identifier), (
        "structurally this is not an OU ID: the suffix carries a newline"
    )

    with patch(BOTO3_TARGET) as mock_boto3:
        recorder = _wire(mock_boto3, _reported_arn_for(identifier))
        resolved = _resolve_target_identifier(identifier)

    assert recorder.services == ["organizations"]
    assert resolved == _reported_arn_for(identifier)
