"""Integration tests for the enabled-controls retriever using botocore Stubber.

``tests/unit/test_enabled_controls_retriever.py`` drives
``retrieve_enabled_controls`` through a ``MagicMock`` boto3. These tests swap in
*real* botocore clients with a ``Stubber`` attached instead, so three things the
mock cannot check are exercised for real:

- the ``ListEnabledControls`` paginator from botocore's own paginator model,
  following ``nextToken`` across pages until the service stops returning one;
- client-side parameter validation of every request against the shipped
  service model, plus Stubber's ``expected_params`` check on each call;
- response-shape validation of every stubbed page against the real output
  shape, so the fixtures cannot drift away from what AWS actually returns.

The clients are constructed inside the retriever through its module-level
``boto3`` reference, so that reference is patched to hand back the stubbed
clients by service name. That also records which services were requested,
which is how "no Organizations call for an ARN" is asserted.

Failure contract: a retrieval failure raises ``RuntimeError`` (chaining the
botocore exception as ``__cause__``) and prints nothing. The original wording
of "print a warning and return an empty list" was reclassified as a defect by
the OU-id parameter case-sensitivity bugfix, because an empty list is
indistinguishable from an OU with genuinely nothing enabled and yields a
report claiming zero enabled controls for a comparison that never happened.
Reporting the error to stderr and choosing the exit code is ``cli.py``'s job.
"""

from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError, ParamValidationError
from botocore.stub import Stubber

from control_tower_controls_generator.enabled_controls_retriever import (
    retrieve_enabled_controls,
)


BOTO3_TARGET = "control_tower_controls_generator.enabled_controls_retriever.boto3"

REGION = "us-east-1"

OU_ID = "ou-tito-abcd1234"
OU_ARN = "arn:aws:organizations::111122223333:ou/o-abc123def4/ou-tito-abcd1234"

CONTROL_ARNS = [
    "arn:aws:controlcatalog:::control/2xknmxmas18xrbvvexzq9k06g",
    "arn:aws:controlcatalog:::control/e2saoisw5u8xe40acfetio41w",
    "arn:aws:controlcatalog:::control/7rrde1yjxvdp8hyfina89c07z",
    "arn:aws:controlcatalog:::control/aqlp8x1a2xq0y5r7vq5ttb9ja",
    "arn:aws:controlcatalog:::control/5f2pm0x9o4ik4q2m3rlgbb2y1",
]


# --- helpers ------------------------------------------------------------------

def _summary(control_arn: str, index: int) -> dict:
    """One ``EnabledControlSummary`` item as the service returns it."""
    return {
        "arn": f"arn:aws:controltower:{REGION}:111122223333:enabledcontrol/EC{index:010d}",
        "controlIdentifier": control_arn,
        "targetIdentifier": OU_ARN,
        "statusSummary": {"status": "SUCCEEDED"},
    }


def _page(control_arns: list[str], next_token: str | None = None) -> dict:
    """A ``ListEnabledControls`` response page, optionally pointing at another."""
    page: dict = {
        "enabledControls": [
            _summary(arn, CONTROL_ARNS.index(arn)) for arn in control_arns
        ]
    }
    if next_token is not None:
        page["nextToken"] = next_token
    return page


class _StubbedAWS:
    """Real botocore clients with Stubbers, handed out in place of ``boto3.client``."""

    def __init__(self) -> None:
        session = boto3.session.Session(
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
            region_name=REGION,
        )
        self.clients = {
            "controltower": session.client("controltower"),
            "organizations": session.client("organizations"),
        }
        self.controltower = Stubber(self.clients["controltower"])
        self.organizations = Stubber(self.clients["organizations"])
        self.requested_services: list[str] = []

    def client(self, service_name: str, **_kwargs):
        self.requested_services.append(service_name)
        return self.clients[service_name]

    def assert_no_pending_responses(self) -> None:
        self.controltower.assert_no_pending_responses()
        self.organizations.assert_no_pending_responses()


@pytest.fixture
def aws(monkeypatch):
    """Patch the retriever's boto3 with stubbed clients for the test's duration."""
    # A stray profile in the environment would make Session() look it up.
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_PROFILE", raising=False)

    stubbed = _StubbedAWS()
    mock_boto3 = MagicMock(name="boto3")
    mock_boto3.client.side_effect = stubbed.client

    with patch(BOTO3_TARGET, mock_boto3), stubbed.controltower, stubbed.organizations:
        yield stubbed


def _arns(enabled_controls) -> list[str]:
    return [control.control_arn for control in enabled_controls]


# --- successful retrieval -----------------------------------------------------

class TestSuccessfulRetrieval:
    """Every page is read, in order, with no output on stdout or stderr."""

    def test_paginates_through_every_page_in_order(self, aws, capsys):
        aws.controltower.add_response(
            "list_enabled_controls",
            _page(CONTROL_ARNS[0:2], next_token="token-1"),
            expected_params={"targetIdentifier": OU_ARN},
        )
        aws.controltower.add_response(
            "list_enabled_controls",
            _page(CONTROL_ARNS[2:4], next_token="token-2"),
            expected_params={"targetIdentifier": OU_ARN, "nextToken": "token-1"},
        )
        aws.controltower.add_response(
            "list_enabled_controls",
            _page(CONTROL_ARNS[4:5]),
            expected_params={"targetIdentifier": OU_ARN, "nextToken": "token-2"},
        )

        result = retrieve_enabled_controls(OU_ARN)

        assert _arns(result) == CONTROL_ARNS
        aws.assert_no_pending_responses()
        # An ARN is used verbatim, so AWS Organizations is never consulted.
        assert aws.requested_services == ["controltower"]
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_bare_ou_id_is_resolved_through_organizations_first(self, aws, capsys):
        aws.organizations.add_response(
            "describe_organizational_unit",
            {"OrganizationalUnit": {"Id": OU_ID, "Arn": OU_ARN, "Name": "Sandbox"}},
            expected_params={"OrganizationalUnitId": OU_ID},
        )
        aws.controltower.add_response(
            "list_enabled_controls",
            _page(CONTROL_ARNS[0:1]),
            expected_params={"targetIdentifier": OU_ARN},
        )

        result = retrieve_enabled_controls(OU_ID)

        assert _arns(result) == CONTROL_ARNS[0:1]
        aws.assert_no_pending_responses()
        assert aws.requested_services == ["organizations", "controltower"]
        assert capsys.readouterr().err == ""

    def test_ou_with_nothing_enabled_returns_empty_list_silently(self, aws, capsys):
        aws.controltower.add_response(
            "list_enabled_controls",
            {"enabledControls": []},
            expected_params={"targetIdentifier": OU_ARN},
        )

        result = retrieve_enabled_controls(OU_ARN)

        assert result == []
        aws.assert_no_pending_responses()
        assert capsys.readouterr().err == ""


# --- failure handling ---------------------------------------------------------

class TestFailureHandling:
    """Failures raise ``RuntimeError`` and are never degraded into ``[]``.

    Nothing is printed by the retriever itself: ``cli.py`` turns the raised
    error into the stderr message and the exit code.
    """

    @pytest.mark.parametrize(
        ("error_code", "http_status"),
        [
            ("AccessDeniedException", 403),
            ("ResourceNotFoundException", 404),
            ("ThrottlingException", 429),
            ("InternalServerException", 500),
        ],
    )
    def test_client_error_raises_runtime_error_and_prints_nothing(
        self, aws, capsys, error_code, http_status
    ):
        aws.controltower.add_client_error(
            "list_enabled_controls",
            service_error_code=error_code,
            service_message="stubbed failure",
            http_status_code=http_status,
            expected_params={"targetIdentifier": OU_ARN},
        )

        with pytest.raises(RuntimeError) as excinfo:
            retrieve_enabled_controls(OU_ARN)

        message = str(excinfo.value)
        assert "AWS Control Tower" in message
        assert OU_ARN in message
        assert error_code in message
        cause = excinfo.value.__cause__
        assert isinstance(cause, ClientError)
        assert cause.response["Error"]["Code"] == error_code
        aws.assert_no_pending_responses()
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_failure_on_a_later_page_does_not_return_partial_results(self, aws):
        aws.controltower.add_response(
            "list_enabled_controls",
            _page(CONTROL_ARNS[0:2], next_token="token-1"),
            expected_params={"targetIdentifier": OU_ARN},
        )
        aws.controltower.add_client_error(
            "list_enabled_controls",
            service_error_code="InternalServerException",
            service_message="stubbed failure",
            http_status_code=500,
            expected_params={"targetIdentifier": OU_ARN, "nextToken": "token-1"},
        )

        with pytest.raises(RuntimeError) as excinfo:
            retrieve_enabled_controls(OU_ARN)

        assert isinstance(excinfo.value.__cause__, ClientError)
        aws.assert_no_pending_responses()

    def test_organizations_failure_raises_before_control_tower_is_called(
        self, aws, capsys
    ):
        aws.organizations.add_client_error(
            "describe_organizational_unit",
            service_error_code="AccessDeniedException",
            service_message="stubbed failure",
            http_status_code=403,
            expected_params={"OrganizationalUnitId": OU_ID},
        )

        with pytest.raises(RuntimeError) as excinfo:
            retrieve_enabled_controls(OU_ID)

        message = str(excinfo.value)
        assert "AWS Organizations" in message
        assert OU_ID in message
        assert isinstance(excinfo.value.__cause__, ClientError)
        aws.assert_no_pending_responses()
        assert aws.requested_services == ["organizations"]
        assert capsys.readouterr().err == ""

    def test_request_rejected_by_real_parameter_validation_raises(self, aws, capsys):
        # Neither a bare OU ID nor an ARN, so it is passed through verbatim and
        # botocore's validation of the real input shape rejects it (min: 20).
        identifier = "ou-short"
        # Stubber checks call order before validation runs, so a response must
        # be queued; it is never consumed because the request never goes out.
        aws.controltower.add_response(
            "list_enabled_controls", {"enabledControls": []}
        )

        with pytest.raises(RuntimeError) as excinfo:
            retrieve_enabled_controls(identifier)

        assert identifier in str(excinfo.value)
        assert isinstance(excinfo.value.__cause__, ParamValidationError)
        with pytest.raises(AssertionError):
            aws.controltower.assert_no_pending_responses()
        assert capsys.readouterr().err == ""
