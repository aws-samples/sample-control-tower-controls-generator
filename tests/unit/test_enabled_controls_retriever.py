"""Unit tests for the enabled-controls retriever module.

Covers the request side of ``retrieve_enabled_controls``: the name the OU is
bound to on the ``ListEnabledControls`` request, and the *form* that value has
to be in before botocore will let the request leave the process.

Two things are asserted here, and they fail for different reasons on unfixed
code:

1. **Request parameter casing.** ``ListEnabledControls`` takes
   ``targetIdentifier``; the retriever passes ``TargetIdentifier``. botocore
   rejects unknown input members during client-side parameter validation, so
   the reported failure happens before any network call.
2. **Identifier form.** ``targetIdentifier`` is typed ``min: 20``,
   ``pattern: arn:aws[0-9a-zA-Z_\\-:\\/]+`` -- it is an OU *ARN*, not an OU ID.
   A bare ``ou-xxxx-xxxxxxxx`` therefore fails validation even after the
   rename, so bare OU IDs have to be resolved through
   ``organizations:DescribeOrganizationalUnit`` before the Control Tower call.

The identifier-form facts are measured against the *real* service model rather
than asserted from memory: the ``ListEnabledControls`` input shape is loaded
via ``botocore.session`` and both identifier forms are run through
``botocore.validate``. That needs no credentials and no network.

``moto`` does not support the ``controltower`` service and the clients are
constructed *inside* ``retrieve_enabled_controls`` (via the module's ``boto3``
reference), so boto3 is mocked with ``unittest.mock.patch`` on that reference --
mirroring ``tests/unit/test_control_catalog_retriever.py`` -- rather than
simulated with a fake AWS backend or a botocore Stubber. The mocked paginator
records the kwargs ``paginate`` was called with, which is what makes the
request itself observable.

Request Reaches the API With a Valid
targetIdentifier.
"""

from unittest.mock import MagicMock, patch

import botocore.session
import pytest
from botocore.validate import ParamValidator, validate_parameters

from control_tower_controls_generator.enabled_controls_retriever import (
    retrieve_enabled_controls,
)
from control_tower_controls_generator.models import EnabledControl


BOTO3_TARGET = "control_tower_controls_generator.enabled_controls_retriever.boto3"

# The OU from the bug report, and the ARN form of that same OU.
OU_ID = "ou-tito-abcd1234"
OU_ARN = "arn:aws:organizations::111122223333:ou/o-abc123/ou-tito-abcd1234"

# An identifier form that is neither a bare OU ID nor an OU ARN. ListEnabledControls
# accounts for account targets too, so this must reach the API unrewritten.
ACCOUNT_ARN = "arn:aws:organizations::111122223333:account/o-abc123/444455556666"

CONTROL_ARN1 = "arn:aws:controlcatalog:::control/2xknmxmas18xrbvvexzq9k06g"
CONTROL_ARN2 = "arn:aws:controlcatalog:::control/e2saoisw5u8xe40acfetio41w"


# --- the real service model ---------------------------------------------------

#: The shipped ``ListEnabledControls`` input shape, loaded from botocore's own
#: service model so the parameter names and the ``targetIdentifier`` constraints
#: are the ones the SDK will actually enforce.
LIST_ENABLED_CONTROLS_INPUT_SHAPE = (
    botocore.session.get_session()
    .get_service_model("controltower")
    .operation_model("ListEnabledControls")
    .input_shape
)


def _validation_report(params: dict) -> str:
    """Validate ``params`` against the real input shape.

    Returns botocore's report text, which is the empty string when the params
    are acceptable.
    """
    return (
        ParamValidator()
        .validate(params, LIST_ENABLED_CONTROLS_INPUT_SHAPE)
        .generate_report()
    )


# --- helpers ------------------------------------------------------------------

def _page(*control_arns: str) -> dict:
    """Wrap control ARNs in a paginator page shaped like the real service.

    The service model defines the page key as ``enabledControls`` and the
    per-item key as ``controlIdentifier``, so that is the shape fed here.
    """
    return {"enabledControls": [{"controlIdentifier": arn} for arn in control_arns]}


class _Boto3Recorder:
    """Records how the retriever used its ``boto3`` reference.

    Exposes the constructed clients, the ``boto3.client`` call list, and the
    kwargs each ``paginate`` call was made with, so the request the retriever
    would have put on the wire is directly assertable.
    """

    def __init__(self) -> None:
        self.client_calls: list[tuple[tuple, dict]] = []
        self.paginate_calls: list[dict] = []
        self.controltower = MagicMock(name="controltower_client")
        self.organizations = MagicMock(name="organizations_client")

    @property
    def services(self) -> list[str]:
        """Service names passed to ``boto3.client``, in construction order."""
        return [args[0] for args, _ in self.client_calls if args]

    @property
    def paginate_kwargs(self) -> dict:
        """The kwargs of the single expected ``paginate`` call."""
        assert len(self.paginate_calls) == 1, (
            f"expected exactly 1 paginate call, got {len(self.paginate_calls)}"
        )
        return self.paginate_calls[0]


def _setup_boto3_mock(
    mock_boto3: MagicMock, pages: list, *, ou_arn: str | None = None
) -> _Boto3Recorder:
    """Wire a mocked boto3 and return the recorder observing it.

    ``boto3.client`` dispatches on the service name so the Control Tower and
    AWS Organizations clients stay distinguishable, and so that constructing an
    Organizations client at all is observable. ``get_paginator(...).paginate()``
    yields ``pages`` and records the kwargs it was called with.

    ``ou_arn`` is the ARN ``DescribeOrganizationalUnit`` reports back for
    whichever OU ID it is asked about; when omitted, the Organizations client
    has no stubbed response because the call is not expected to happen.
    """
    recorder = _Boto3Recorder()

    paginator = MagicMock(name="paginator")

    def _paginate(*args, **kwargs):
        recorder.paginate_calls.append(dict(kwargs))
        return iter(pages)

    paginator.paginate.side_effect = _paginate
    recorder.controltower.get_paginator.return_value = paginator

    if ou_arn is not None:
        def _describe_ou(**kwargs):
            return {
                "OrganizationalUnit": {
                    "Id": kwargs.get("OrganizationalUnitId"),
                    "Arn": ou_arn,
                    "Name": "Sandbox",
                }
            }

        recorder.organizations.describe_organizational_unit.side_effect = _describe_ou

    def _client(*args, **kwargs):
        recorder.client_calls.append((args, dict(kwargs)))
        service = args[0] if args else kwargs.get("service_name")
        if service == "organizations":
            return recorder.organizations
        return recorder.controltower

    mock_boto3.client.side_effect = _client
    return recorder


# --- design test case 1: request parameter casing ------------------------------

class TestRequestParameterCasing:
    """The OU must be bound to ``targetIdentifier``, not ``TargetIdentifier``."""

    def test_paginator_requested_once_for_list_enabled_controls(self):
        """Exactly one paginator is requested, for ``list_enabled_controls``.

        This is the part of the request wiring that is already correct; it is
        pinned so the rename in the fix cannot quietly move it.
        """
        with patch(BOTO3_TARGET) as mock_boto3:
            recorder = _setup_boto3_mock(
                mock_boto3, [_page(CONTROL_ARN1)], ou_arn=OU_ARN
            )
            retrieve_enabled_controls(OU_ID)

        recorder.controltower.get_paginator.assert_called_once_with(
            "list_enabled_controls"
        )

    def test_paginate_binds_the_ou_to_camel_case_target_identifier(self):
        """``paginate`` is called with ``targetIdentifier`` and with no
        ``TargetIdentifier`` key."""
        with patch(BOTO3_TARGET) as mock_boto3:
            recorder = _setup_boto3_mock(
                mock_boto3, [_page(CONTROL_ARN1)], ou_arn=OU_ARN
            )
            retrieve_enabled_controls(OU_ID)

        kwargs = recorder.paginate_kwargs
        assert "targetIdentifier" in kwargs, (
            "ListEnabledControls names the OU parameter 'targetIdentifier'; "
            f"the request was built with {sorted(kwargs)}"
        )
        assert "TargetIdentifier" not in kwargs, (
            "'TargetIdentifier' is not a member of the ListEnabledControls "
            "input shape and is rejected by botocore before any network call"
        )

    def test_recorded_request_passes_boto3_parameter_validation(self):
        """The request the retriever builds survives botocore's own validation.

        This is the assertion the bug report's stack trace corresponds to:
        ``ParamValidationError`` is raised client-side, so the call never
        reaches the API.
        """
        with patch(BOTO3_TARGET) as mock_boto3:
            recorder = _setup_boto3_mock(
                mock_boto3, [_page(CONTROL_ARN1)], ou_arn=OU_ARN
            )
            retrieve_enabled_controls(OU_ID)

        # Raises ParamValidationError carrying botocore's own message, so the
        # failure output *is* the counterexample.
        validate_parameters(recorder.paginate_kwargs, LIST_ENABLED_CONTROLS_INPUT_SHAPE)

    def test_pascal_case_parameter_rejected_by_the_real_input_shape(self):
        """Measured against the shipped model: ``TargetIdentifier`` is unknown.

        This records the origin of the reported failure rather than restating
        it, and it holds independently of the retriever.
        """
        report = _validation_report({"TargetIdentifier": OU_ID})

        assert 'Unknown parameter in input: "TargetIdentifier"' in report
        assert "must be one of: targetIdentifier" in report


# --- design test case 3: targetIdentifier is an OU ARN ------------------------

class TestOUIdentifierForm:
    """``targetIdentifier`` is typed as an ARN, so a bare OU ID cannot pass.

    Both facts below are measured against the shipped ``ListEnabledControls``
    input shape, which is why they hold with no credentials and no network.
    """

    def test_target_identifier_is_typed_as_an_arn(self):
        """The shape carries the ARN constraints the rest of this class rests on."""
        metadata = LIST_ENABLED_CONTROLS_INPUT_SHAPE.members[
            "targetIdentifier"
        ].metadata

        assert metadata["min"] == 20
        assert metadata["pattern"] == r"arn:aws[0-9a-zA-Z_\-:\/]+"

    def test_bare_ou_id_rejected_for_length(self):
        """The bare OU ID from the bug report fails the ``min: 20`` check.

        Renaming the parameter alone therefore trades one
        ``ParamValidationError`` for another.
        """
        report = _validation_report({"targetIdentifier": OU_ID})

        assert report == (
            "Invalid length for parameter targetIdentifier, "
            "value: 16, valid min length: 20"
        )

    def test_ou_arn_accepted(self):
        """A well-formed OU ARN validates clean, so resolution is the way out."""
        assert _validation_report({"targetIdentifier": OU_ARN}) == ""


# --- the resolution contract root cause 3 implies -----------------------------

class TestTargetIdentifierResolution:
    """A bare OU ID is resolved; every other form is passed through untouched."""

    def test_bare_ou_id_reaches_paginate_as_the_arn_organizations_reports(self):
        """A bare OU ID is resolved via ``DescribeOrganizationalUnit`` and the
        reported ARN is what gets bound to ``targetIdentifier``.

        The ARN is read from the API response rather than assembled locally,
        which would require separately discovering the organization ID, the
        management account ID, and the partition.
        """
        with patch(BOTO3_TARGET) as mock_boto3:
            recorder = _setup_boto3_mock(
                mock_boto3, [_page(CONTROL_ARN1, CONTROL_ARN2)], ou_arn=OU_ARN
            )
            retrieve_enabled_controls(OU_ID)

        assert "organizations" in recorder.services, (
            "a bare OU ID cannot satisfy targetIdentifier's ARN typing, so an "
            f"Organizations client is required; clients built: {recorder.services}"
        )
        recorder.organizations.describe_organizational_unit.assert_called_once_with(
            OrganizationalUnitId=OU_ID
        )
        assert recorder.paginate_kwargs.get("targetIdentifier") == OU_ARN

    @pytest.mark.parametrize(
        "identifier",
        [OU_ARN, ACCOUNT_ARN],
        ids=["ou_arn", "account_arn"],
    )
    def test_other_identifier_forms_reach_paginate_verbatim(self, identifier):
        """Anything that is not a bare OU ID is bound verbatim, and no
        Organizations client is constructed at all.
        """
        with patch(BOTO3_TARGET) as mock_boto3:
            recorder = _setup_boto3_mock(mock_boto3, [_page(CONTROL_ARN1)])
            retrieve_enabled_controls(identifier)

        assert recorder.paginate_kwargs.get("targetIdentifier") == identifier
        assert "organizations" not in recorder.services, (
            "the value already satisfies the parameter's typing, so nothing "
            f"should be resolved; clients built: {recorder.services}"
        )
        assert recorder.organizations.describe_organizational_unit.call_count == 0


# ==============================================================================
# camelCase Response Keys Are Collected
#
# The response-key defect is the *latent* half of the bug: nothing reaches it
# today, because the request above never leaves the process. It fails in a
# shape worth naming precisely -- the retriever reads
# ``page.get("EnabledControls", [])`` and ``item.get("ControlIdentifier", "")``,
# neither of which the service model defines, and ``.get`` with a default turns
# both misses into an empty result with no exception raised and nothing on
# stderr. Fixing only the request parameter would therefore trade the user's
# visible warning for undetectable wrong data.
#
# Isolation: every test below supplies the OU as an **ARN**
# (``OU_ARN``/``ACCOUNT_ARN``), never a bare OU ID. That keeps the identifier
# resolution path (root causes 1 and 3, covered above) out of the picture --
# unfixed code binds the ARN verbatim to its PascalCase kwarg and the mocked
# paginator does not validate parameter names, so it yields the fed pages
# either way. Any failure below is therefore attributable to the response keys
# alone, and the same tests keep passing once ``_resolve_target_identifier``
# lands, since an ARN passes through it untouched.
#
# These drive the public ``retrieve_enabled_controls``, not the
# ``_collect_enabled_controls`` helper the fix introduces, so they are runnable
# against unfixed code and flip to passing when the fix lands.
# ==============================================================================

CONTROL_ARN3 = "arn:aws:controlcatalog:::control/5wfjxjrq2xkdmg1yy4olkuc3n"
CONTROL_ARN4 = "arn:aws:controlcatalog:::control/9k7ln0kbmr1qhxi8dpe2f9dcy"

# EnabledControlSummary carries its own ``arn`` -- the ARN of the *enablement*,
# a different namespace from the ``controlIdentifier`` this retriever wants.
# Present on the item fixtures below so picking the wrong key is detectable.
ENABLED_CONTROL_ARN = (
    "arn:aws:controltower:us-west-2:111122223333:enabledcontrol/ABCDEFGH12345678"
)


def _arns(enabled_controls: list[EnabledControl]) -> list[str]:
    """The ``control_arn`` of each returned control, in returned order."""
    return [control.control_arn for control in enabled_controls]


# --- design test case 2: response key casing ----------------------------------

class TestResponseKeyCasing:
    """camelCase pages must be collected, in page-then-item order."""

    def test_camel_case_page_is_collected(self):
        """A page shaped like the real service yields the control it carries."""
        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [_page(CONTROL_ARN1)])
            result = retrieve_enabled_controls(OU_ARN)

        assert result == [EnabledControl(control_arn=CONTROL_ARN1)], (
            "ListEnabledControls returns 'enabledControls' / "
            "'controlIdentifier'; reading the PascalCase spelling of either "
            "misses, and '.get' with a default makes that miss silent -- an "
            f"empty list, no exception, nothing on stderr. Got: {result!r}"
        )

    def test_pages_aggregate_in_page_then_item_order(self):
        """Multiple pages flatten in page order, items in within-page order."""
        pages = [
            _page(CONTROL_ARN1, CONTROL_ARN2),
            _page(CONTROL_ARN3),
            _page(CONTROL_ARN4),
        ]

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, pages)
            result = retrieve_enabled_controls(OU_ARN)

        assert _arns(result) == [
            CONTROL_ARN1,
            CONTROL_ARN2,
            CONTROL_ARN3,
            CONTROL_ARN4,
        ], (
            "every non-empty controlIdentifier across every page is expected, "
            "in page-then-item order"
        )

    def test_item_without_control_identifier_is_skipped(self):
        """An item missing ``controlIdentifier`` yields no ``EnabledControl``.

        Skipped rather than appended with an empty ARN, which would land in the
        enabled set and match nothing.
        """
        page = {
            "enabledControls": [
                {"controlIdentifier": CONTROL_ARN1},
                {"arn": ENABLED_CONTROL_ARN, "statusSummary": {"status": "SUCCEEDED"}},
                {"controlIdentifier": CONTROL_ARN2},
            ]
        }

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [page])
            result = retrieve_enabled_controls(OU_ARN)

        assert _arns(result) == [CONTROL_ARN1, CONTROL_ARN2]
        assert all(control.control_arn for control in result), (
            f"no EnabledControl may carry an empty ARN; got {_arns(result)!r}"
        )

    def test_item_with_empty_control_identifier_is_skipped(self):
        """The same holds when ``controlIdentifier`` is present but empty."""
        page = {
            "enabledControls": [
                {"controlIdentifier": ""},
                {"controlIdentifier": CONTROL_ARN1},
            ]
        }

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [page])
            result = retrieve_enabled_controls(OU_ARN)

        assert _arns(result) == [CONTROL_ARN1]
        assert "" not in _arns(result)

    def test_unrelated_keys_on_pages_and_items_are_ignored(self):
        """Only ``enabledControls`` / ``controlIdentifier`` are read.

        The other members the real response carries -- pagination state,
        response metadata, and the item's own enablement ``arn``, status, drift
        and parent identifiers -- are all present here and none of them may
        influence the result.
        """
        page = {
            "enabledControls": [
                {
                    "arn": ENABLED_CONTROL_ARN,
                    "controlIdentifier": CONTROL_ARN1,
                    "targetIdentifier": OU_ARN,
                    "statusSummary": {"status": "SUCCEEDED"},
                    "driftStatusSummary": {"driftStatus": "IN_SYNC"},
                    "parentIdentifier": OU_ARN,
                }
            ],
            "nextToken": None,
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [page])
            result = retrieve_enabled_controls(OU_ARN)

        assert _arns(result) == [CONTROL_ARN1]
        assert ENABLED_CONTROL_ARN not in _arns(result), (
            "EnabledControlSummary.arn identifies the enablement, not the "
            "control; EnabledControl.control_arn is compared against the "
            "Control Catalog ARN and must come from controlIdentifier"
        )


# --- a successful retrieval says nothing ---------------------------------------

class TestSuccessfulRetrievalIsSilent:
    """Success returns the controls and prints no warning.

    On unfixed code the stderr half of this passes and the return half fails,
    and that combination *is* the counterexample: silence plus an empty list is
    exactly what an OU with genuinely nothing enabled produces, so the reader
    has no signal that the comparison never happened.
    """

    def test_no_warning_is_printed_on_successful_retrieval(self, capsys):
        """Nothing reaches stderr, and the controls come back."""
        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [_page(CONTROL_ARN1, CONTROL_ARN2)])
            result = retrieve_enabled_controls(OU_ARN)

        captured = capsys.readouterr()
        assert captured.err == "", (
            f"a successful retrieval must print no warning; got {captured.err!r}"
        )
        assert _arns(result) == [CONTROL_ARN1, CONTROL_ARN2], (
            "silence is only correct when the data is right: an empty result "
            "with an empty stderr is indistinguishable from an OU with nothing "
            f"enabled. Got: {_arns(result)!r}"
        )


# --- design test case 7 (edge case): a genuinely empty page --------------------

class TestEmptyEnabledControlsPage:
    """A page whose ``enabledControls`` is ``[]`` returns ``[]`` without error.

    This one is expected to PASS on unfixed code, and that is the point. It
    pins the *genuine* zero -- an OU with no controls enabled -- apart from the
    failure-shaped zero the other tests in this section produce. Unfixed code
    cannot tell them apart, which is the ambiguity that made the reported gap
    analysis wrong in a way the reader could not detect.
    """

    def test_empty_page_returns_empty_list_without_error(self, capsys):
        """Zero enabled controls is a valid answer, reported quietly."""
        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [{"enabledControls": []}])
            result = retrieve_enabled_controls(ACCOUNT_ARN)

        assert result == []
        assert capsys.readouterr().err == "", (
            "an empty result reached legitimately is not an error and must not "
            "warn"
        )


# ==============================================================================
# Failure Is Loud, Not Silent
#
# This is the root cause that makes the other three invisible. The retriever
# ends in ``except (ClientError, BotoCoreError)``, which prints
# ``Warning: Failed to retrieve enabled controls for OU '...'`` and returns
# ``[]``. ``ParamValidationError`` subclasses ``BotoCoreError``, so that handler
# absorbs the *exact* failure the bug report produced: the run continues to
# ``write_output``, the report claims ``Already Enabled: 0`` with ``Gaps`` equal
# to the total, and the process exits 0. A comparison that never happened is
# reported as a comparison that found nothing, and the two are
# indistinguishable to the reader.
#
# The contract asserted below inverts that. Every failure -- from Control
# Tower's ``ListEnabledControls`` *or* from the AWS Organizations resolution
# that now precedes it -- leaves the function as a ``RuntimeError`` with
# ``__cause__`` set to the original botocore exception, carrying the OU as the
# user supplied it and naming which of the two calls failed. ``__cause__`` is
# not decoration: ``cli._is_auth_error`` walks it to choose exit 3 over exit 2,
# so the chain is what makes the exit code correct.
#
# The last clause is the one with no counterpart in the current code at all:
# **no failure path returns a value**. ``_outcome_of`` below reports "raised" or
# "returned" instead of asserting directly, so an unfixed run fails with
# ``returned []`` in the message rather than a bare ``DID NOT RAISE``.
#
# End-to-end consequences -- no report written, exit 3 or 2, the OU and the
# cause on stderr -- are asserted through ``CliRunner`` in
# ``tests/integration/test_cli_e2e.py::TestErrorScenarios``. What is asserted
# here is the retriever-side half plus the ``cli._is_auth_error`` verdict that
# routes the exit code.
# ==============================================================================

from botocore.exceptions import (  # noqa: E402 - section-local, mirrors the file's layout
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    ParamValidationError,
)

from control_tower_controls_generator import cli  # noqa: E402


#: botocore's own report text for the reported failure, reproduced verbatim so
#: the exception raised here is the one the user actually hit.
PARAM_VALIDATION_REPORT = (
    'Unknown parameter in input: "TargetIdentifier", must be one of: '
    "targetIdentifier, nextToken, maxResults, filter, includeChildren"
)


def _client_error(
    code: str, message: str = "boom", operation: str = "ListEnabledControls"
) -> ClientError:
    """A ``ClientError`` shaped the way botocore raises them."""
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


def _setup_failing_control_tower(
    mock_boto3: MagicMock, error: Exception, *, ou_arn: str | None = OU_ARN
) -> _Boto3Recorder:
    """Wire a boto3 whose ``ListEnabledControls`` pagination raises ``error``."""
    recorder = _setup_boto3_mock(mock_boto3, [], ou_arn=ou_arn)
    recorder.controltower.get_paginator.return_value.paginate.side_effect = error
    return recorder


def _setup_failing_organizations(
    mock_boto3: MagicMock, error: Exception
) -> _Boto3Recorder:
    """Wire a boto3 whose ``DescribeOrganizationalUnit`` raises ``error``.

    Control Tower is left *healthy* and returning a page, so a run that reaches
    it has demonstrably ignored the resolution failure.
    """
    recorder = _setup_boto3_mock(mock_boto3, [_page(CONTROL_ARN1)], ou_arn=OU_ARN)
    recorder.organizations.describe_organizational_unit.side_effect = error
    return recorder


def _outcome_of(identifier: str, **kwargs) -> tuple[str, object]:
    """Call the retriever and report what came out, without asserting.

    Returns ``("raised", exception)`` or ``("returned", value)``. Reporting the
    outcome rather than asserting it is what makes the counterexample legible:
    unfixed code fails these tests with ``returned []`` rather than a bare
    ``DID NOT RAISE``, which is the whole point.
    """
    try:
        return ("returned", retrieve_enabled_controls(identifier, **kwargs))
    except Exception as exc:  # noqa: BLE001 - the outcome *is* the assertion subject
        return ("raised", exc)


def _raised_runtime_error(identifier: str, **kwargs) -> RuntimeError:
    """The ``RuntimeError`` the retriever must raise for ``identifier``."""
    kind, value = _outcome_of(identifier, **kwargs)

    assert kind == "raised", (
        "a failed retrieval must not produce a value: returning "
        f"{value!r} is indistinguishable from an OU with nothing enabled, and "
        "the run goes on to write a report and exit 0"
    )
    assert isinstance(value, RuntimeError), (
        f"failures must surface as RuntimeError so cli.py's own handler routes "
        f"them to exit 3 or 2; got {type(value).__name__}: {value}"
    )
    return value


#: Every failure class the two calls can produce, spanning both ``except``
#: branches. ``ParamValidationError`` is the reported bug's class;
#: ``NoCredentialsError`` is the other ``BotoCoreError`` the design names.
FAILURE_CASES = [
    pytest.param(_client_error("AccessDeniedException", "not authorized"), id="access_denied"),
    pytest.param(_client_error("ValidationException", "bad input"), id="validation_exception"),
    pytest.param(ParamValidationError(report=PARAM_VALIDATION_REPORT), id="param_validation"),
    pytest.param(NoCredentialsError(), id="no_credentials"),
]


# --- design test case 4: loud failure on ClientError --------------------------

class TestControlTowerClientErrorIsLoud:
    """A ``ClientError`` from ``ListEnabledControls`` aborts the retrieval."""

    def test_client_error_propagates_as_runtime_error(self):
        """``AccessDeniedException`` leaves the function, it is not absorbed."""
        error = _client_error("AccessDeniedException", "not authorized")

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_control_tower(mock_boto3, error)
            _raised_runtime_error(OU_ID)

    def test_runtime_error_preserves_the_client_error_as_cause(self):
        """``__cause__`` is the original ``ClientError`` instance.

        ``raise ... from e`` is not cosmetic here: ``cli._is_auth_error`` walks
        ``__cause__`` to read the error code, so an unchained ``RuntimeError``
        would silently downgrade an auth failure from exit 3 to exit 2.
        """
        error = _client_error("AccessDeniedException", "not authorized")

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_control_tower(mock_boto3, error)
            raised = _raised_runtime_error(OU_ID)

        assert raised.__cause__ is error, (
            "the original botocore exception must be chained with 'from e'; "
            f"__cause__ was {raised.__cause__!r}"
        )

    def test_message_names_the_ou_as_the_user_supplied_it(self):
        """The message quotes the supplied OU, not the resolved ARN.

        The identification clause is about the value the user
        typed. The resolved ARN contains the OU ID as a substring, so the
        quoted form is what separates the two.
        """
        error = _client_error("ValidationException", "bad input")

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_control_tower(mock_boto3, error)
            raised = _raised_runtime_error(OU_ID)

        assert f"'{OU_ID}'" in str(raised), (
            "stderr has to identify which OU the run was asking about; got: "
            f"{str(raised)!r}"
        )

    def test_message_names_control_tower_as_the_failing_call(self):
        """The message says Control Tower, so stderr localizes the failure.

        Its counterpart is ``TestOrganizationsFailureIsLoud``, where the same
        assertion demands the *other* service name.
        """
        error = _client_error("ValidationException", "bad input")

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_control_tower(mock_boto3, error)
            raised = _raised_runtime_error(OU_ARN)

        assert "Control Tower" in str(raised), (
            f"two AWS calls can fail on this path; got: {str(raised)!r}"
        )

    def test_access_denied_satisfies_cli_is_auth_error(self):
        """The raised error routes to exit 3, via ``__cause__``.

        The exit-code clause, asserted against the predicate
        ``cli.py`` actually uses rather than a copy of its logic.
        """
        error = _client_error("AccessDeniedException", "not authorized")

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_control_tower(mock_boto3, error)
            raised = _raised_runtime_error(OU_ID)

        assert cli._is_auth_error(raised) is True, (
            "an authorization failure has to reach exit 3; _is_auth_error "
            "reads the error code off __cause__, so this fails when the chain "
            "is missing"
        )

    @pytest.mark.parametrize(
        "code", ["ValidationException", "TooManyRequestsException", "ServiceException"]
    )
    def test_non_auth_client_error_does_not_satisfy_cli_is_auth_error(self, code):
        """Everything outside ``AUTH_ERROR_CODES`` routes to exit 2 instead.

        The codes are split; this is the other half.
        """
        error = _client_error(code, "boom")

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_control_tower(mock_boto3, error)
            raised = _raised_runtime_error(OU_ID)

        assert cli._is_auth_error(raised) is False, (
            f"'{code}' is not an authentication failure and belongs on exit 2"
        )

    def test_access_denied_is_already_an_auth_error_code(self):
        """``AUTH_ERROR_CODES`` already carries ``AccessDeniedException``.

        Pinned because the Organizations permission gap surfaces under exactly
        this code, and it must reach exit 3 with no further wiring in ``cli.py``.
        """
        assert "AccessDeniedException" in cli.AUTH_ERROR_CODES

    def test_failure_is_not_degraded_into_a_warning_and_an_empty_list(self, capsys):
        """No ``Warning:`` line, and no value: the two halves of the defect.

        This is the assertion the bug report maps onto most directly. Unfixed
        code prints ``Warning: Failed to retrieve enabled controls for OU
        '...'`` and hands back ``[]``, which ``cli.py`` reads as "nothing
        enabled".
        """
        error = _client_error("AccessDeniedException", "not authorized")

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_control_tower(mock_boto3, error)
            kind, value = _outcome_of(OU_ID)

        captured = capsys.readouterr()
        assert "Warning: Failed to retrieve enabled controls" not in captured.err, (
            "the degradation warning is the defect, not the remedy: it lets the "
            "run continue to write_output and exit 0. Got: "
            f"{captured.err!r}"
        )
        assert kind == "raised", f"a failed retrieval returned {value!r}"


# --- design test case 5: loud failure on BotoCoreError ------------------------

class TestControlTowerBotoCoreErrorIsLoud:
    """The ``BotoCoreError`` branch behaves identically.

    ``ParamValidationError`` gets its own tests because it is the exact class
    the reported bug produces: raised client-side, before any network call, and
    caught by the very handler that turned the failure into a success-shaped
    run.
    """

    def test_param_validation_error_is_a_botocore_error(self):
        """The subclass relationship that makes the defect what it is.

        ``except (ClientError, BotoCoreError)`` reads as "AWS is unreachable,
        carry on". ``ParamValidationError`` arriving through that branch means
        the request was malformed and never sent -- unrecoverable, and nothing
        the caller can carry on from.
        """
        assert issubclass(ParamValidationError, BotoCoreError)

    def test_param_validation_error_propagates_as_runtime_error(self):
        """The reported failure aborts the retrieval."""
        error = ParamValidationError(report=PARAM_VALIDATION_REPORT)

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_control_tower(mock_boto3, error)
            raised = _raised_runtime_error(OU_ID)

        assert raised.__cause__ is error

    def test_param_validation_message_carries_the_ou_and_the_cause(self):
        """Both identification clauses on one message."""
        error = ParamValidationError(report=PARAM_VALIDATION_REPORT)

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_control_tower(mock_boto3, error)
            raised = _raised_runtime_error(OU_ID)

        message = str(raised)
        assert f"'{OU_ID}'" in message
        assert "Control Tower" in message
        assert "TargetIdentifier" in message, (
            "the underlying cause has to survive into the message so stderr "
            f"says *why* the call failed; got: {message!r}"
        )

    def test_param_validation_error_does_not_satisfy_cli_is_auth_error(self):
        """The reported bug lands on exit 2, not exit 3.

        Non-authentication API failures land on 2, and this is
        the case the user hit.
        """
        error = ParamValidationError(report=PARAM_VALIDATION_REPORT)

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_control_tower(mock_boto3, error)
            raised = _raised_runtime_error(OU_ID)

        assert cli._is_auth_error(raised) is False

    def test_no_credentials_error_propagates_as_runtime_error(self):
        """A missing-credentials failure aborts too."""
        error = NoCredentialsError()

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_control_tower(mock_boto3, error)
            raised = _raised_runtime_error(OU_ID)

        assert raised.__cause__ is error
        assert f"'{OU_ID}'" in str(raised)

    def test_no_credentials_error_satisfies_cli_is_auth_error(self):
        """Absent credentials route to exit 3.

        ``_is_auth_error`` special-cases ``NoCredentialsError`` directly, so
        this passes only when the chain reaches it.
        """
        error = NoCredentialsError()

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_control_tower(mock_boto3, error)
            raised = _raised_runtime_error(OU_ID)

        assert cli._is_auth_error(raised) is True


# --- the AWS Organizations side of the same contract --------------------------

class TestOrganizationsFailureIsLoud:
    """A failing ``DescribeOrganizationalUnit`` aborts before Control Tower.

    A second AWS call is introduced, and it is given
    the same error contract with one addition: its message names AWS
    Organizations rather than Control Tower, so stderr says *which* of the two
    calls failed. On unfixed code no resolution call exists at all, so these
    fail by returning a value rather than by carrying the wrong message.
    """

    def test_client_error_from_describe_ou_propagates_as_runtime_error(self):
        """A resolution failure is a run-ending failure."""
        error = _client_error(
            "OrganizationalUnitNotFoundException",
            "OU not found",
            operation="DescribeOrganizationalUnit",
        )

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_organizations(mock_boto3, error)
            raised = _raised_runtime_error(OU_ID)

        assert raised.__cause__ is error

    def test_message_names_aws_organizations_not_control_tower(self):
        """stderr identifies the failing call.

        Two AWS calls can fail on this path, and they need different
        remediations -- an Organizations permission or ARN problem versus a
        Control Tower one -- so a message naming the wrong service sends the
        reader to the wrong place.
        """
        error = _client_error(
            "AccessDeniedException",
            "not authorized to perform organizations:DescribeOrganizationalUnit",
            operation="DescribeOrganizationalUnit",
        )

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_organizations(mock_boto3, error)
            raised = _raised_runtime_error(OU_ID)

        message = str(raised)
        assert "Organizations" in message, (
            f"the resolution call is the one that failed; got: {message!r}"
        )
        assert "Control Tower" not in message, (
            "Control Tower was never reached, so naming it would misdirect the "
            f"reader; got: {message!r}"
        )
        assert f"'{OU_ID}'" in message

    def test_access_denied_from_organizations_satisfies_cli_is_auth_error(self):
        """The new permission dependency surfaces as exit 3.

        ``organizations:DescribeOrganizationalUnit`` is callable only from the
        management account or a delegated administrator, so this is the most
        likely failure of the whole fix, and it must not be reported as a
        generic API error.
        """
        error = _client_error(
            "AccessDeniedException",
            "not authorized",
            operation="DescribeOrganizationalUnit",
        )

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_organizations(mock_boto3, error)
            raised = _raised_runtime_error(OU_ID)

        assert cli._is_auth_error(raised) is True

    @pytest.mark.parametrize(
        "error",
        [
            ParamValidationError(report="Invalid length for parameter"),
            NoCredentialsError(),
        ],
        ids=["param_validation", "no_credentials"],
    )
    def test_botocore_error_from_describe_ou_propagates_as_runtime_error(self, error):
        """The ``BotoCoreError`` branch of the resolution call."""
        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_organizations(mock_boto3, error)
            raised = _raised_runtime_error(OU_ID)

        assert raised.__cause__ is error
        assert "Organizations" in str(raised)

    def test_control_tower_is_never_called_when_resolution_fails(self):
        """The run stops at the resolution failure.

        Control Tower is stubbed healthy here and returns a page, so reaching
        it would mean the retriever proceeded with an unresolved identifier --
        which is the bare-OU-ID request that cannot pass parameter validation.
        """
        error = _client_error(
            "AWSOrganizationsNotInUseException",
            "not in use",
            operation="DescribeOrganizationalUnit",
        )

        with patch(BOTO3_TARGET) as mock_boto3:
            recorder = _setup_failing_organizations(mock_boto3, error)
            _raised_runtime_error(OU_ID)

        assert recorder.paginate_calls == [], (
            "resolution failed, so there is no valid targetIdentifier to send; "
            f"ListEnabledControls was called with {recorder.paginate_calls!r}"
        )

    def test_no_report_shaped_success_when_resolution_fails(self, capsys):
        """No warning, no value, from the resolution call either.

        The Organizations call is new, so this pins that it does not repeat the
        pattern being removed.
        """
        error = _client_error(
            "InvalidInputException", "bad OU id", operation="DescribeOrganizationalUnit"
        )

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_failing_organizations(mock_boto3, error)
            kind, value = _outcome_of(OU_ID)

        assert "Warning:" not in capsys.readouterr().err
        assert kind == "raised", f"a failed resolution returned {value!r}"


# --- no failure path produces a value -----------------------------------------

class TestNoFailurePathReturnsAValue:
    """Across every failing call and every error class: raise, never return.

    This is a universal claim, so it is asserted as one. The
    ``returned`` half of each failure message is the counterexample: ``[]`` is
    what ``cli.py`` turns into ``Already Enabled: 0``, a report, and exit 0 --
    the run the user reported.
    """

    @pytest.mark.parametrize(
        "failing_call", ["control_tower", "organizations"]
    )
    @pytest.mark.parametrize("error", FAILURE_CASES)
    def test_failure_raises_and_returns_nothing(self, failing_call, error):
        with patch(BOTO3_TARGET) as mock_boto3:
            if failing_call == "organizations":
                _setup_failing_organizations(mock_boto3, error)
            else:
                _setup_failing_control_tower(mock_boto3, error)

            kind, value = _outcome_of(OU_ID)

        assert kind == "raised", (
            f"{type(error).__name__} from the {failing_call} call produced "
            f"{value!r} instead of an error; a value here means the run writes "
            "a report and exits 0 on a comparison that never happened"
        )
        assert isinstance(value, RuntimeError)
        assert value.__cause__ is error
        assert f"'{OU_ID}'" in str(value)


# ==============================================================================
# Rounding out this file's coverage - the gaps the rest of the suite leaves
#
# Most of what a coverage sweep of this module would list is asserted already,
# and restating it here would only create a second place for the same fact to
# drift:
#
# - Response parsing -- single page, multi-page, empty page, and an item whose
#   ``controlIdentifier`` is absent or empty -- ``TestResponseKeyCasing`` and
#   ``TestEmptyEnabledControlsPage`` above, plus
#   ``tests/property/test_ou_fix_collection_props.py`` over generated page
#   sequences.
# - Error mapping, including ``AccessDeniedException`` from *either* call
#   satisfying ``cli._is_auth_error`` -- ``TestControlTowerClientErrorIsLoud``,
#   ``TestControlTowerBotoCoreErrorIsLoud`` and
#   ``TestOrganizationsFailureIsLoud`` above, plus
#   ``tests/property/test_ou_fix_failure_props.py``.
# - No warning printed on success -- ``TestSuccessfulRetrievalIsSilent`` and
#   ``TestEmptyEnabledControlsPage`` above, both asserting on ``capsys``.
# - No path returning ``[]`` on failure --
#   ``TestNoFailurePathReturnsAValue.test_failure_raises_and_returns_nothing``
#   above, across every error class and both failing calls.
#
# Two gaps are genuine, and both are gaps of *discrimination* rather than of
# absence: an assertion exists, but it holds vacuously for the case it looks
# like it covers.
# ==============================================================================

from botocore.config import Config  # noqa: E402 - section-local, mirrors the file's layout

from control_tower_controls_generator.enabled_controls_retriever import (  # noqa: E402
    OU_ID_PATTERN,
)


# --- gap 1: each client asserted on its own, by service name -------------------

#: The two clients this path constructs when the OU arrives as a bare ID.
BOTH_SERVICES = ["controltower", "organizations"]


def _kwargs_for_service(recorder: _Boto3Recorder, service: str) -> dict:
    """The kwargs of the one ``boto3.client`` call that built ``service``.

    Selecting by service name is the whole point: an assertion written over
    *all* client calls cannot fail when one of the clients was never built.
    """
    calls = [
        kwargs for args, kwargs in recorder.client_calls if args and args[0] == service
    ]

    assert len(calls) == 1, (
        f"expected exactly one {service!r} client to be constructed; clients "
        f"built: {recorder.services}"
    )
    return calls[0]


class TestClientConstructionPerService:
    """Both clients carry the same retry, timeout and region contract.

    ``tests/unit/test_ou_fix_downstream_contract.py::TestRegionAndClientConfig``
    records this contract as a walk over every ``boto3.client`` call. That is
    the right shape for a baseline recorded *before* the Organizations client
    existed, and it does cover the new client -- but a walk cannot tell "the
    Organizations client carries the contract" apart from "no Organizations
    client was built". Its only presence assertion names ``controltower``, so
    the Organizations half of that contract passes there for either
    reason.

    Each client is looked up here *by service name* and asserted on its own, so
    an Organizations client that goes missing, or one built with a bare
    ``boto3.client("organizations")`` and no config, fails instead of passing
    quietly.
    """

    def test_a_bare_ou_id_constructs_both_clients_in_resolution_order(self):
        """Resolution builds Organizations, then retrieval builds Control Tower.

        The presence half the uniform walk cannot state. Order is asserted
        because it is load-bearing: the ARN has to exist before the request that
        carries it is built.
        """
        with patch(BOTO3_TARGET) as mock_boto3:
            recorder = _setup_boto3_mock(
                mock_boto3, [_page(CONTROL_ARN1)], ou_arn=OU_ARN
            )
            retrieve_enabled_controls(OU_ID)

        assert recorder.services == ["organizations", "controltower"], (
            "a bare OU ID needs resolving before ListEnabledControls can be "
            f"called with a valid targetIdentifier; clients built: "
            f"{recorder.services}"
        )

    @pytest.mark.parametrize("service", BOTH_SERVICES)
    def test_client_carries_adaptive_retries_and_timeouts(self, service):
        """Adaptive retries capped at 3, 30-second connect and read timeouts.

        Asserted on the ``Config`` object's resolved attributes rather than on
        object identity, so the contract is about the values botocore will
        actually use.
        """
        with patch(BOTO3_TARGET) as mock_boto3:
            recorder = _setup_boto3_mock(
                mock_boto3, [_page(CONTROL_ARN1)], ou_arn=OU_ARN
            )
            retrieve_enabled_controls(OU_ID)

        config = _kwargs_for_service(recorder, service)["config"]

        assert isinstance(config, Config)
        assert config.retries == {"max_attempts": 3, "mode": "adaptive"}
        assert config.connect_timeout == 30
        assert config.read_timeout == 30

    @pytest.mark.parametrize("service", BOTH_SERVICES)
    def test_region_name_reaches_each_client_when_supplied(self, service):
        """A supplied region reaches both clients.

        Organizations resolves to the partition-global endpoint, so the region
        does not steer *its* endpoint within a partition; passing it is what
        keeps behavior correct across partitions.
        """
        with patch(BOTO3_TARGET) as mock_boto3:
            recorder = _setup_boto3_mock(
                mock_boto3, [_page(CONTROL_ARN1)], ou_arn=OU_ARN
            )
            retrieve_enabled_controls(OU_ID, region="us-west-2")

        assert _kwargs_for_service(recorder, service)["region_name"] == "us-west-2"

    @pytest.mark.parametrize("service", BOTH_SERVICES)
    @pytest.mark.parametrize("region", [None, ""], ids=["none", "empty"])
    def test_region_name_omitted_from_each_client_when_not_supplied(
        self, service, region
    ):
        """No region means the kwarg is absent, not present and empty.

        The second clause is about *default* AWS region
        resolution still applying, which is why absence is the assertion rather
        than a falsy value.
        """
        with patch(BOTO3_TARGET) as mock_boto3:
            recorder = _setup_boto3_mock(
                mock_boto3, [_page(CONTROL_ARN1)], ou_arn=OU_ARN
            )
            retrieve_enabled_controls(OU_ID, region=region)

        kwargs = _kwargs_for_service(recorder, service)
        assert "region_name" not in kwargs, (
            f"no region was supplied, so the {service!r} client must fall back "
            f"to default resolution; got region_name={kwargs['region_name']!r}"
        )


# --- gap 2: a value that is neither a bare OU ID nor an ARN --------------------

#: Identifier forms matching neither the OU ID pattern nor an ARN. ``paginate``
#: is mocked, so botocore never validates these -- which is the point. What is
#: under test is whether the retriever *rewrites* a value it does not recognize,
#: not whether the service would go on to accept it.
NEITHER_FORM_IDENTIFIERS = [
    pytest.param("r-abcd", id="root_id"),
    pytest.param("444455556666", id="bare_account_id"),
    pytest.param("", id="empty_string"),
]


class TestIdentifierMatchingNeitherFormPassesThrough:
    """Pass-through turns on the OU ID pattern, not on being an ARN.

    ``TestTargetIdentifierResolution.test_other_identifier_forms_reach_paginate_verbatim``
    covers pass-through with ``OU_ARN`` and ``ACCOUNT_ARN`` -- both ARNs. That
    leaves two conditions conflated: an implementation that resolved everything
    *non-ARN* would satisfy it while violating the rule "does not
    match the Organizational Unit ID pattern". The values below separate the
    two. They reach the request unrewritten because the pattern does not match,
    not because they look like ARNs.

    ``tests/property/test_ou_fix_resolution_props.py`` states the same
    discrimination over generated identifiers, but against
    ``_resolve_target_identifier``. What is added here is the step after it:
    that the public retrieval binds the unrewritten value to the request it
    actually builds.
    """

    @pytest.mark.parametrize("identifier", NEITHER_FORM_IDENTIFIERS)
    def test_premise_the_identifier_is_neither_an_ou_id_nor_an_arn(self, identifier):
        """Pins what makes each case a case, so the parametrization cannot drift.

        Without this, a value edited into an ARN or into a well-formed OU ID
        would keep the class green while testing something else entirely.
        """
        assert OU_ID_PATTERN.match(identifier) is None, (
            f"{identifier!r} matches the OU ID pattern, so it belongs with the "
            "resolution cases, not the pass-through ones"
        )
        assert not identifier.startswith("arn:"), (
            f"{identifier!r} is an ARN, which is the case "
            "test_other_identifier_forms_reach_paginate_verbatim already covers"
        )

    @pytest.mark.parametrize("identifier", NEITHER_FORM_IDENTIFIERS)
    def test_identifier_reaches_paginate_unchanged_with_no_resolution(
        self, identifier
    ):
        """Bound verbatim, no Organizations client, retrieval still runs.

        The "SHALL NOT call AWS Organizations" rule is asserted as no
        client being constructed at all, which is stronger than no call being
        made on one.
        """
        with patch(BOTO3_TARGET) as mock_boto3:
            recorder = _setup_boto3_mock(mock_boto3, [_page(CONTROL_ARN1)])
            result = retrieve_enabled_controls(identifier)

        kwargs = recorder.paginate_kwargs
        assert kwargs.get("targetIdentifier") == identifier, (
            "a value the OU ID pattern does not recognise must reach the API "
            f"unrewritten; the request was built with {kwargs!r}"
        )
        assert "organizations" not in recorder.services, (
            "nothing here matches the OU ID pattern, so no resolution should be "
            f"attempted and no permission exercised; clients built: "
            f"{recorder.services}"
        )
        assert _arns(result) == [CONTROL_ARN1], (
            "pass-through is not a short circuit: the retrieval itself still "
            f"runs and returns what the API reported. Got: {_arns(result)!r}"
        )
