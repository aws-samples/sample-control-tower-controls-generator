"""Property-based test for the OU-id parameter case-sensitivity bugfix.

Failure Is Loud, Not Silent.

_For any_ invocation where the bug condition holds and retrieval fails --
whether the failing call is Control Tower's ``ListEnabledControls`` or the AWS
Organizations resolution that precedes it -- the fixed code SHALL exit 3 when
the underlying cause is an authentication or authorization failure and 2
otherwise, SHALL NOT write a report, and SHALL print an error to stderr naming
the failing call, the requested Organizational Unit, and the underlying cause.
No failure path SHALL return an empty list.

Two properties, over the same generated failure space, plus three guards on the
generated space itself:

1. ``test_retrieval_failure_always_raises_naming_the_failing_call`` exercises the
   retriever directly. It asserts the raise-not-return contract, the
   ``__cause__`` chain, and the message content.
2. ``test_failing_retrieval_exit_code_is_3_for_auth_and_2_otherwise`` drives the
   whole CLI through ``CliRunner`` and asserts the exit code, the absent report
   file, and the stderr content.

Design notes:

- **"Never returns a value" is reported, not merely asserted.** ``_outcome_of``
  hands back ``("raised", exc)`` or ``("returned", value)`` so a regression that
  degrades a failure back into ``[]`` fails with ``returned []`` in the message
  rather than a bare ``DID NOT RAISE``. Returning ``[]`` is the defect itself:
  it is indistinguishable from an OU with genuinely nothing enabled, so the run
  goes on to write a report and exit 0.
- **The exit-code half is not reimplemented.** The expected 3-versus-2 split
  comes from ``cli.AUTH_ERROR_CODES`` read as data plus the specification's own
  classification of the credential-absent errors, and it is checked against two
  independent oracles: ``cli._is_auth_error``'s verdict, and the exit code the
  CLI actually produces. A test that recomputed the routing itself would prove
  nothing about the routing.
- **All 11 auth codes are covered every run, not on average.** The strategies
  read ``cli.AUTH_ERROR_CODES`` so the whole set is in the generated domain, but
  across this many dimensions a single 100-example run lands on roughly two
  thirds of it. Every code and every error class is therefore also pinned as an
  explicit example against each of the two AWS calls, so both properties run 100
  generated examples plus 63 pinned ones.
- **The ``__cause__`` chain is the point, not decoration.** ``cli._is_auth_error``
  walks ``__cause__`` to read the botocore error code, so an unchained
  ``RuntimeError`` would silently downgrade an auth failure from exit 3 to
  exit 2.
- ``moto`` does not support the ``controltower`` service and both clients are
  constructed *inside* the retriever, so boto3 is mocked with
  ``unittest.mock.patch`` on the module's own reference
  (``control_tower_controls_generator.enabled_controls_retriever.boto3``),
  mirroring ``tests/unit/test_enabled_controls_retriever.py``.

All Hypothesis strategies are defined locally in this module by design so the
file stays self-contained and does not collide with other parallel test tasks,
following ``tests/property/test_control_retriever_props.py``.
"""

import json
import os
from typing import Any, NamedTuple

import pytest
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    NoCredentialsError,
    NoRegionError,
    ParamValidationError,
    PartialCredentialsError,
    ReadTimeoutError,
)
from click.testing import CliRunner
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st
from unittest.mock import MagicMock, patch

from control_tower_controls_generator import cli
from control_tower_controls_generator.cli import main
from control_tower_controls_generator.enabled_controls_retriever import (
    OU_ID_PATTERN,
    retrieve_enabled_controls,
)
from control_tower_controls_generator.models import Control, ControlImplementation


#: The retriever module's own ``boto3`` reference: the seam both properties are
#: driven through.
BOTO3_TARGET = "control_tower_controls_generator.enabled_controls_retriever.boto3"

#: Where ``cli.py`` looks the retriever up. The CLI property puts the *real*
#: retriever here so the failure travels the actual code path.
CLI_RETRIEVER_TARGET = "control_tower_controls_generator.cli.retrieve_enabled_controls"

#: botocore's own report text for the reported failure, reproduced verbatim so
#: the ``ParamValidationError`` generated here is the one the user actually hit.
PARAM_VALIDATION_REPORT = (
    'Unknown parameter in input: "TargetIdentifier", must be one of: '
    "targetIdentifier, nextToken, maxResults, filter, includeChildren"
)

#: The two AWS calls on this path, and the phrase each one's error message must
#: carry so stderr says which of them failed.
CONTROL_TOWER = "control_tower"
ORGANIZATIONS = "organizations"
SERVICE_PHRASE = {CONTROL_TOWER: "Control Tower", ORGANIZATIONS: "Organizations"}

#: The one catalog control the CLI runs are driven with, and the ARN the healthy
#: Control Tower page carries when the Organizations call is the failing one.
CATALOG_ARN = "arn:aws:controlcatalog:::control/aaa"


# --- Local Hypothesis strategies ----------------------------------------------

_OU_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz"

# ``OU_ID_PATTERN`` is ``^ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}$``, so both segments
# are drawn from the same alphabet with no embedded hyphen. Sizes are kept near
# the real shape rather than at the pattern's limits; the branch selection is
# asserted against the pattern itself in ``_assert_identifier_form``.
_ou_ids = st.builds(
    lambda middle, suffix: f"ou-{middle}-{suffix}",
    st.text(alphabet=_OU_CHARS, min_size=4, max_size=8),
    st.text(alphabet=_OU_CHARS, min_size=8, max_size=12),
)

_account_ids = st.text(alphabet="0123456789", min_size=12, max_size=12)
_org_ids = st.builds(
    lambda s: f"o-{s}", st.text(alphabet=_OU_CHARS, min_size=10, max_size=10)
)

# The ARN form of an OU: passes through ``_resolve_target_identifier`` verbatim,
# so no Organizations call is made for it.
_ou_arns = st.builds(
    lambda account, org, ou: f"arn:aws:organizations::{account}:ou/{org}/{ou}",
    _account_ids,
    _org_ids,
    _ou_ids,
)

# Identifier forms that are neither a bare OU ID nor an OU ARN. ListEnabledControls
# accepts account targets too, and the retriever must not rewrite anything it does
# not recognize, so these belong in the space as well.
_other_identifiers = st.one_of(
    st.builds(
        lambda account, org: f"arn:aws:organizations::{account}:account/{org}/{account}",
        _account_ids,
        _org_ids,
    ),
    st.builds(lambda s: f"r-{s}", st.text(alphabet=_OU_CHARS, min_size=4, max_size=4)),
    _account_ids,
).filter(lambda value: not OU_ID_PATTERN.match(value))

#: Every code in ``cli.AUTH_ERROR_CODES``, read from the set itself rather than
#: transcribed, so a code added there is generated here without further edits.
#: These are the codes that must reach exit 3.
AUTH_ERROR_CODES = sorted(cli.AUTH_ERROR_CODES)

#: Codes outside that set, drawn from the documented failure modes of both calls:
#: ``ListEnabledControls`` and ``organizations:DescribeOrganizationalUnit``.
#: These must reach exit 2.
NON_AUTH_ERROR_CODES = [
    "ValidationException",
    "ResourceNotFoundException",
    "ThrottlingException",
    "TooManyRequestsException",
    "InternalServerException",
    "ServiceException",
    "InvalidInputException",
    "OrganizationalUnitNotFoundException",
    "AWSOrganizationsNotInUseException",
    "ConflictException",
]

# Error message text. Deliberately a small closed set containing neither "Control
# Tower" nor "Organizations": the properties assert that the *wrong* service is
# NOT named on stderr, and a message that happened to contain the other service's
# name would defeat that assertion rather than test it.
_error_messages = st.sampled_from(
    [
        "boom",
        "not authorized to perform this operation",
        "The security token included in the request is invalid",
        "Rate exceeded",
        "An unexpected error occurred",
    ]
)


class _Failure(NamedTuple):
    """A generated failure, described as plain data.

    Descriptors rather than live exception instances, so Hypothesis reports a
    legible counterexample and shrinks over the codes and class names instead of
    over exception objects. ``build()`` turns one into the botocore exception the
    mocked call raises.

    ``expect_auth`` is the *specification's* classification of the failure, not a
    recomputation of ``cli._is_auth_error``: the specification puts authentication
    and authorization failures on exit 3 and everything else on exit 2. Both
    ``_is_auth_error`` and the CLI's own exit code are then checked against it,
    so a disagreement between the spec, the predicate, and the CLI fails here.
    """

    branch: str  # "client_error" | "botocore_error"
    code: str | None  # ClientError error code
    message: str  # ClientError message, or a label for the botocore class
    expect_auth: bool

    def build(self) -> BaseException:
        """The botocore exception this descriptor stands for."""
        if self.branch == "client_error":
            return ClientError(
                {"Error": {"Code": self.code, "Message": self.message}},
                "ListEnabledControls",
            )
        return _BOTOCORE_ERRORS[self.message]()


#: ``BotoCoreError`` subclasses, with the specification's exit-code classification.
#: ``ParamValidationError`` is the exact class the reported bug produced, and it
#: is *not* an auth failure, so the reported bug lands on exit 2.
#: ``NoCredentialsError`` and ``PartialCredentialsError`` carry no error code at
#: all, yet absent credentials are an authentication failure and belong on exit 3.
_BOTOCORE_ERRORS: dict[str, Any] = {
    "ParamValidationError": lambda: ParamValidationError(
        report=PARAM_VALIDATION_REPORT
    ),
    "NoCredentialsError": NoCredentialsError,
    "PartialCredentialsError": lambda: PartialCredentialsError(
        provider="env", cred_var="aws_secret_access_key"
    ),
    "EndpointConnectionError": lambda: EndpointConnectionError(
        endpoint_url="https://controltower.us-east-1.amazonaws.com/"
    ),
    "ConnectTimeoutError": lambda: ConnectTimeoutError(
        endpoint_url="https://controltower.us-east-1.amazonaws.com/"
    ),
    "ReadTimeoutError": lambda: ReadTimeoutError(
        endpoint_url="https://controltower.us-east-1.amazonaws.com/"
    ),
    "ConnectionClosedError": lambda: ConnectionClosedError(
        endpoint_url="https://controltower.us-east-1.amazonaws.com/"
    ),
    "NoRegionError": NoRegionError,
}

#: The credential-absent classes: no error code, but an authentication failure.
_AUTH_BOTOCORE_ERRORS = ("NoCredentialsError", "PartialCredentialsError")


@st.composite
def _failures(draw) -> _Failure:
    """Generate a failure spanning both ``except`` branches of the retriever.

    ``ClientError`` codes are drawn from ``cli.AUTH_ERROR_CODES`` and from a set
    of non-auth codes; ``BotoCoreError`` subclasses are drawn from the table
    above. The expected exit-code classification travels with the draw.
    """
    if draw(st.booleans()):
        code = draw(
            st.one_of(
                st.sampled_from(AUTH_ERROR_CODES),
                st.sampled_from(NON_AUTH_ERROR_CODES),
            )
        )
        return _Failure(
            branch="client_error",
            code=code,
            message=draw(_error_messages),
            expect_auth=code in cli.AUTH_ERROR_CODES,
        )

    name = draw(st.sampled_from(sorted(_BOTOCORE_ERRORS)))
    return _Failure(
        branch="botocore_error",
        code=None,
        message=name,
        expect_auth=name in _AUTH_BOTOCORE_ERRORS,
    )


@st.composite
def _failing_invocations(draw) -> dict[str, Any]:
    """Generate a failing invocation: which call fails, on which identifier form.

    The Organizations call only happens for a bare OU ID -- anything else passes
    through with no Organizations client constructed at all -- so an invocation
    that fails there is generated with an OU-ID identifier. A Control Tower
    failure is reachable from every identifier form, so all three are generated
    for it.
    """
    failing_call = draw(st.sampled_from([CONTROL_TOWER, ORGANIZATIONS]))

    if failing_call == ORGANIZATIONS:
        identifier = draw(_ou_ids)
    else:
        identifier = draw(st.one_of(_ou_ids, _ou_arns, _other_identifiers))

    return {
        "failing_call": failing_call,
        "identifier": identifier,
        "failure": draw(_failures()),
    }


def _invocation(failing_call: str, identifier: str, failure: _Failure) -> dict[str, Any]:
    """Build an invocation dict for an ``@example``."""
    return {
        "failing_call": failing_call,
        "identifier": identifier,
        "failure": failure,
    }


#: The OU from the bug report, and the ARN form of that same OU.
REPORTED_OU_ID = "ou-tito-abcd1234"
REPORTED_OU_ARN = "arn:aws:organizations::111122223333:ou/o-abc123/ou-tito-abcd1234"


def _pinned_invocations() -> list[dict[str, Any]]:
    """Every error code and error class, on each of the two AWS calls.

    ``st.sampled_from`` gives the strategy the whole domain, but across this many
    dimensions a single 100-example run lands on roughly two thirds of the eleven
    auth codes. The exit-3 clause is stated over *all* of
    ``cli.AUTH_ERROR_CODES``, so each one is pinned as an explicit example and
    exercised every run rather than probabilistically. The bug report's own OU ID
    is used throughout, since it is a bare OU ID and therefore reaches either
    call; the other identifier forms come from the generated space.
    """
    pinned: list[dict[str, Any]] = []

    for failing_call in (CONTROL_TOWER, ORGANIZATIONS):
        for code in AUTH_ERROR_CODES + NON_AUTH_ERROR_CODES:
            pinned.append(
                _invocation(
                    failing_call,
                    REPORTED_OU_ID,
                    _Failure(
                        branch="client_error",
                        code=code,
                        message="boom",
                        expect_auth=code in cli.AUTH_ERROR_CODES,
                    ),
                )
            )
        for name in sorted(_BOTOCORE_ERRORS):
            pinned.append(
                _invocation(
                    failing_call,
                    REPORTED_OU_ID,
                    _Failure(
                        branch="botocore_error",
                        code=None,
                        message=name,
                        expect_auth=name in _AUTH_BOTOCORE_ERRORS,
                    ),
                )
            )

    return pinned


PINNED_INVOCATIONS = _pinned_invocations()


def _pin_examples(fn):
    """Apply one ``@example`` per entry in ``PINNED_INVOCATIONS``.

    Applied in a loop rather than written out as ~58 stacked decorators; the
    effect is identical, since ``example(...)`` is an ordinary decorator factory.
    """
    for invocation in PINNED_INVOCATIONS:
        fn = example(invocation=invocation)(fn)
    return fn


# The cases the design names specifically, pinned so they are always exercised
# rather than covered probabilistically: the reported bug's own class, the
# credential-absent class that routes to 3 without an error code, and
# AccessDeniedException on each of the two calls (the likeliest failure of the
# fix, since organizations:DescribeOrganizationalUnit is callable only from the
# management account or a delegated administrator).
_REPORTED_BUG = _invocation(
    CONTROL_TOWER,
    REPORTED_OU_ID,
    _Failure("botocore_error", None, "ParamValidationError", False),
)
_NO_CREDENTIALS = _invocation(
    CONTROL_TOWER,
    REPORTED_OU_ID,
    _Failure("botocore_error", None, "NoCredentialsError", True),
)
_CT_ACCESS_DENIED = _invocation(
    CONTROL_TOWER,
    REPORTED_OU_ID,
    _Failure("client_error", "AccessDeniedException", "not authorized", True),
)
_ORG_ACCESS_DENIED = _invocation(
    ORGANIZATIONS,
    REPORTED_OU_ID,
    _Failure("client_error", "AccessDeniedException", "not authorized", True),
)
# The ARN form, which reaches Control Tower with no Organizations call at all, so
# a failure there still names Control Tower and quotes the ARN as supplied.
_ARN_FORM_FAILURE = _invocation(
    CONTROL_TOWER,
    REPORTED_OU_ARN,
    _Failure("client_error", "AccessDeniedException", "not authorized", True),
)


# --- Wiring -------------------------------------------------------------------


def _resolved_arn(identifier: str) -> str:
    """The ARN a healthy ``DescribeOrganizationalUnit`` reports for ``identifier``."""
    return f"arn:aws:organizations::111122223333:ou/o-exampleorg/{identifier}"


def _assert_identifier_form(invocation: dict[str, Any]) -> None:
    """Check the generated invocation is actually reachable.

    An Organizations failure requires an identifier the retriever will resolve;
    if the generator drifted, the test would silently exercise the Control Tower
    branch twice instead of both branches once.
    """
    identifier = invocation["identifier"]
    if invocation["failing_call"] == ORGANIZATIONS:
        assert OU_ID_PATTERN.match(identifier), (
            f"{identifier!r} is not a bare OU ID, so no Organizations call would "
            "be made and this invocation cannot exercise the Organizations failure path"
        )


def _wire_failing_boto3(mock_boto3: MagicMock, invocation: dict[str, Any]) -> list[str]:
    """Point a mocked boto3 at clients where exactly one of the two calls fails.

    The call that is *not* under test is left healthy and answering, so a run
    that gets past it has demonstrably reached the failing one. Returns the list
    of service names ``boto3.client`` was asked for, in construction order.
    """
    error = invocation["failure"].build()
    identifier = invocation["identifier"]

    services: list[str] = []
    controltower = MagicMock(name="controltower_client")
    organizations = MagicMock(name="organizations_client")

    if invocation["failing_call"] == ORGANIZATIONS:
        organizations.describe_organizational_unit.side_effect = error
        # Control Tower is healthy and returns a page, so reaching it at all
        # would mean the resolution failure had been ignored.
        controltower.get_paginator.return_value.paginate.return_value = iter(
            [{"enabledControls": [{"controlIdentifier": CATALOG_ARN}]}]
        )
    else:
        organizations.describe_organizational_unit.return_value = {
            "OrganizationalUnit": {"Id": identifier, "Arn": _resolved_arn(identifier)}
        }
        controltower.get_paginator.return_value.paginate.side_effect = error

    def _client(*args, **kwargs):
        service = args[0] if args else kwargs.get("service_name")
        services.append(service)
        return organizations if service == ORGANIZATIONS else controltower

    mock_boto3.client.side_effect = _client
    return services


def _outcome_of(identifier: str) -> tuple[str, object]:
    """Call the retriever and report what came out, without asserting.

    Returns ``("raised", exception)`` or ``("returned", value)``. Reporting the
    outcome rather than asserting it is what makes the counterexample legible: a
    regression fails with ``returned []`` rather than a bare ``DID NOT RAISE``,
    which is precisely the distinction being drawn.
    """
    try:
        return ("returned", retrieve_enabled_controls(identifier))
    except Exception as exc:  # noqa: BLE001 - the outcome *is* the assertion subject
        return ("raised", exc)


def _raised_runtime_error(invocation: dict[str, Any]) -> RuntimeError:
    """Run the retriever under a failing boto3 and return the ``RuntimeError``."""
    with patch(BOTO3_TARGET) as mock_boto3:
        _wire_failing_boto3(mock_boto3, invocation)
        kind, value = _outcome_of(invocation["identifier"])

    assert kind == "raised", (
        f"a failed retrieval must not produce a value: returned {value!r}, which "
        "is indistinguishable from an OU with nothing enabled, so the run goes "
        "on to write a report and exit 0"
    )
    assert isinstance(value, RuntimeError), (
        "failures must surface as RuntimeError so cli.py's own handler routes "
        f"them to exit 3 or 2; got {type(value).__name__}: {value}"
    )
    return value


# --- CLI fixtures -------------------------------------------------------------

#: A catalog small enough to keep 100 CLI runs quick, and matching the input
#: file below so the run reaches the retrieval step with controls in hand.
FIXTURE_CATALOG = [
    Control(
        arn=CATALOG_ARN,
        name="Alpha Control",
        description="An example control.",
        behavior="PREVENTIVE",
        severity="HIGH",
        implementation=ControlImplementation(type="AWS::CloudFormation::Type::HOOK"),
        governed_resources=["AWS::EC2::Instance"],
    ),
]

FIXTURE_RESOURCE_TYPES = ["AWS::EC2::Instance"]

OUTPUT_FILE = "report.json"


def _run_cli(invocation: dict[str, Any]) -> dict[str, Any]:
    """Drive the whole CLI with the real retriever and a failing boto3.

    The catalog retrieval is stubbed (it is not the subject here), but
    ``cli.retrieve_enabled_controls`` is the real function, so the failure is
    injected at the boto3 seam exactly as the user's run produced it and travels
    the actual ``RuntimeError`` -> ``_is_auth_error`` -> ``sys.exit`` path.
    """
    runner = CliRunner()

    with runner.isolated_filesystem():
        with open("input.json", "w", encoding="utf-8") as handle:
            json.dump(FIXTURE_RESOURCE_TYPES, handle)

        with (
            patch.object(
                cli, "retrieve_control_catalog", return_value=list(FIXTURE_CATALOG)
            ),
            patch.object(cli, "retrieve_enabled_controls", retrieve_enabled_controls),
            patch(BOTO3_TARGET) as mock_boto3,
        ):
            _wire_failing_boto3(mock_boto3, invocation)
            result = runner.invoke(
                main,
                [
                    "--no-interactive",
                    "--input-file", "input.json",
                    "--output-format", "json",
                    "--organizational-unit", invocation["identifier"],
                    "--output-file", OUTPUT_FILE,
                ],
            )

        report_written = os.path.exists(OUTPUT_FILE)

    return {
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "report_written": report_written,
    }


# --- retriever side ---


# Expected Behavior - Failure Is Loud, Not Silent
@settings(max_examples=100, deadline=None)
@given(invocation=_failing_invocations())
@example(invocation=_REPORTED_BUG)
@example(invocation=_NO_CREDENTIALS)
@example(invocation=_CT_ACCESS_DENIED)
@example(invocation=_ORG_ACCESS_DENIED)
@example(invocation=_ARN_FORM_FAILURE)
@_pin_examples
def test_retrieval_failure_always_raises_naming_the_failing_call(invocation):
    """A failing retrieval raises, chains its cause, and says what failed.

    Across every ``ClientError`` code and ``BotoCoreError`` subclass, raised
    from either AWS call: ``RuntimeError`` propagates, ``__cause__`` is the
    original botocore exception, the message carries the OU as the user supplied
    it, and it names which of the two calls failed. No failure path returns a
    value.
    """
    _assert_identifier_form(invocation)

    failure = invocation["failure"]
    identifier = invocation["identifier"]
    failing_call = invocation["failing_call"]

    raised = _raised_runtime_error(invocation)

    # The chain is what lets cli._is_auth_error read the underlying error code.
    cause = raised.__cause__
    assert isinstance(cause, (ClientError, BotoCoreError)), (
        "__cause__ must be the original botocore exception, since that is what "
        f"cli._is_auth_error walks; got {cause!r}"
    )
    if failure.branch == "client_error":
        assert isinstance(cause, ClientError)
        assert cause.response["Error"]["Code"] == failure.code
    else:
        assert type(cause).__name__ == failure.message

    message = str(raised)

    # The OU as the *user* supplied it, not the resolved ARN.
    assert f"'{identifier}'" in message, (
        f"the message must quote the OU as supplied ({identifier!r}) so stderr "
        f"identifies what was asked for; got {message!r}"
    )

    # The message has to say which of the two calls failed, or
    # the reader goes looking at the wrong service's permissions.
    #
    # Asserted on the leading segment rather than as a bare substring search,
    # because an error *code* can itself contain the other service's name: this
    # test first failed on `AWSOrganizationsNotInUseException` raised from the
    # Control Tower call, where "AWS Control Tower API error for OU '...'
    # (AWSOrganizationsNotInUseException)" contains "Organizations" without
    # naming Organizations as the failing call. The retriever leads every message
    # with the failing service, so the prefix is the exact claim.
    other_call = ORGANIZATIONS if failing_call == CONTROL_TOWER else CONTROL_TOWER
    assert message.startswith(f"AWS {SERVICE_PHRASE[failing_call]} "), (
        f"the message must lead with {SERVICE_PHRASE[failing_call]!r} as the "
        f"failing call; got {message!r}"
    )
    assert not message.startswith(f"AWS {SERVICE_PHRASE[other_call]} "), (
        f"{SERVICE_PHRASE[other_call]!r} did not fail here, so naming it as the "
        f"failing call would misdirect the reader; got {message!r}"
    )

    # The underlying cause has to reach the message too.
    if failure.branch == "client_error":
        assert failure.code in message
        assert failure.message in message
    else:
        assert str(cause).splitlines()[0] in message

    # The routing predicate's verdict, checked against the specification's own
    # classification rather than against a recomputation of the predicate.
    assert cli._is_auth_error(raised) is failure.expect_auth, (
        f"{failure!r} routes the wrong way: cli._is_auth_error returned "
        f"{cli._is_auth_error(raised)!r} for {message!r}"
    )


# --- exit-code side ---


# Expected Behavior - Failure Is Loud, Not Silent
@settings(
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(invocation=_failing_invocations())
@example(invocation=_REPORTED_BUG)
@example(invocation=_NO_CREDENTIALS)
@example(invocation=_CT_ACCESS_DENIED)
@example(invocation=_ORG_ACCESS_DENIED)
@example(invocation=_ARN_FORM_FAILURE)
@_pin_examples
def test_failing_retrieval_exit_code_is_3_for_auth_and_2_otherwise(invocation):
    """A failing comparison exits 3 or 2, writes no report, and explains itself.

    Exit 3 exactly for the codes in ``cli.AUTH_ERROR_CODES`` (and for the
    credential-absent errors, which carry no code at all) and 2 otherwise. The
    exit code is read off an actual CLI run rather than recomputed, and
    cross-checked against ``cli._is_auth_error``'s verdict on the same failure.
    """
    _assert_identifier_form(invocation)

    failure = invocation["failure"]
    identifier = invocation["identifier"]
    failing_call = invocation["failing_call"]

    raised = _raised_runtime_error(invocation)
    outcome = _run_cli(invocation)

    expected_exit = 3 if failure.expect_auth else 2

    assert outcome["exit_code"] == expected_exit, (
        f"{failure!r} on the {failing_call} call must exit {expected_exit}; got "
        f"{outcome['exit_code']} with stderr {outcome['stderr']!r}"
    )
    # Second oracle: the predicate cli.py routes on, on the same failure.
    assert outcome["exit_code"] == (3 if cli._is_auth_error(raised) else 2)

    # "Already Enabled: 0" must be unreachable through a
    # swallowed failure, so nothing may be written and nothing may be printed.
    assert not outcome["report_written"], (
        "a report was written for a comparison that never happened, which is "
        "the reported outcome: 'Already Enabled: 0' with 'Gaps' equal to the "
        "total, indistinguishable from a real zero"
    )
    assert outcome["stdout"].strip() == "", (
        f"a failed comparison produced a gap analysis: {outcome['stdout']!r}"
    )

    stderr = outcome["stderr"]
    prefix = "Authentication error" if failure.expect_auth else "API error"
    assert prefix in stderr, f"expected {prefix!r} on stderr; got {stderr!r}"
    assert identifier in stderr, (
        f"stderr must identify the requested OU ({identifier!r}); got {stderr!r}"
    )

    # Same reasoning as the retriever-side assertion: matched against the
    # "{prefix}: AWS {Service} ..." shape cli.py prints, so an error code that
    # happens to contain the other service's name cannot satisfy or defeat it.
    other_call = ORGANIZATIONS if failing_call == CONTROL_TOWER else CONTROL_TOWER
    assert f": AWS {SERVICE_PHRASE[failing_call]} " in stderr, (
        f"stderr must name the failing call; got {stderr!r}"
    )
    assert f": AWS {SERVICE_PHRASE[other_call]} " not in stderr, (
        f"{SERVICE_PHRASE[other_call]!r} did not fail here; got {stderr!r}"
    )
    assert "Warning: Failed to retrieve enabled controls" not in stderr, (
        "degrading the failure to a warning is the defect itself: it lets the "
        f"run continue to write_output and exit 0; got {stderr!r}"
    )


# --- Guards on the generated space -------------------------------------------


def test_every_auth_error_code_is_exercised_on_both_aws_calls():
    """All 11 codes in ``cli.AUTH_ERROR_CODES`` are covered, not a subset.

    The exit-3 half of the contract is stated over ``cli.AUTH_ERROR_CODES``, so the
    strategy reads that set directly rather than transcribing it: a code added
    there is generated without a further edit here. This checks the reading, and
    that every code and every error class reaches both AWS calls through the
    pinned examples rather than only by chance.
    """
    assert set(AUTH_ERROR_CODES) == set(cli.AUTH_ERROR_CODES)
    assert len(AUTH_ERROR_CODES) == 11, (
        f"expected the 11 documented auth codes, got {AUTH_ERROR_CODES!r}"
    )
    assert not set(NON_AUTH_ERROR_CODES) & set(cli.AUTH_ERROR_CODES), (
        "the non-auth codes must be disjoint from AUTH_ERROR_CODES, or the "
        "exit-2 expectation contradicts the exit-3 one"
    )

    covered = {
        (inv["failing_call"], inv["failure"].code or inv["failure"].message)
        for inv in PINNED_INVOCATIONS
    }
    expected = {
        (call, key)
        for call in (CONTROL_TOWER, ORGANIZATIONS)
        for key in AUTH_ERROR_CODES + NON_AUTH_ERROR_CODES + sorted(_BOTOCORE_ERRORS)
    }
    assert covered == expected, f"pinned coverage gap: {expected - covered!r}"

    # And the auth codes are pinned with the exit-3 expectation on both calls.
    assert all(
        inv["failure"].expect_auth
        for inv in PINNED_INVOCATIONS
        if inv["failure"].code in cli.AUTH_ERROR_CODES
    )


@pytest.mark.parametrize("name", sorted(_BOTOCORE_ERRORS))
def test_generated_botocore_errors_are_botocore_error_subclasses(name):
    """Each generated class is a ``BotoCoreError``, i.e. hits that ``except`` branch.

    ``ParamValidationError`` subclassing ``BotoCoreError`` is what let the
    original ``except (ClientError, BotoCoreError)`` absorb the reported bug, so
    the subclass relationship is the premise the whole branch rests on.
    """
    error = _BOTOCORE_ERRORS[name]()
    assert isinstance(error, BotoCoreError)
    assert type(error).__name__ == name


@settings(max_examples=100, deadline=None)
@given(ou_id=_ou_ids, ou_arn=_ou_arns, other=_other_identifiers)
def test_the_identifier_strategies_land_on_the_sides_they_claim(ou_id, ou_arn, other):
    """A guard on the generators, not a property claim about the fix.

    The Organizations branch is only reachable for values matching
    ``OU_ID_PATTERN``, and the pass-through branch only for values that do not.
    If the strategies drifted across that line, the properties above would
    quietly stop covering one of the two AWS calls.
    """
    assert OU_ID_PATTERN.match(ou_id), ou_id
    assert not OU_ID_PATTERN.match(ou_arn), ou_arn
    assert not OU_ID_PATTERN.match(other), other
    assert OU_ID_PATTERN.match("ou-tito-abcd1234"), "the OU from the bug report"
