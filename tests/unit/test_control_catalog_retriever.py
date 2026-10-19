"""Unit tests for the control catalog retriever module.

Covers retriever wiring for the ListControls API: multi-page pagination and
field preservation, the boto3 client Config (adaptive retries + timeouts),
region pass-through, and error handling (ClientError -> descriptive
RuntimeError, and the BotoCoreError/credential path).

``moto`` does not support the ``controlcatalog`` service and the client is
constructed *inside* ``control_retriever`` (via the module's ``boto3``
reference), so boto3 is mocked with ``unittest.mock.patch`` on that reference
-- mirroring the established pattern in
``tests/unit/test_control_mappings_retriever.py`` -- rather than simulated with
a fake AWS backend or a botocore Stubber.
"""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError, NoCredentialsError

from control_tower_controls_generator.control_retriever import (
    retrieve_control_catalog,
)
from control_tower_controls_generator.models import Control, ControlImplementation


BOTO3_TARGET = "control_tower_controls_generator.control_retriever.boto3"

ARN1 = "arn:aws:controlcatalog:::control/2xknmxmas18xrbvvexzq9k06g"
ARN2 = "arn:aws:controlcatalog:::control/e2saoisw5u8xe40acfetio41w"
ARN3 = "arn:aws:controlcatalog:::control/aaaabbbbccccddddeeeeffff00"


# --- helpers -----------------------------------------------------------------

def _api_control(
    arn: str,
    name: str,
    *,
    description: str = "A control.",
    behavior: str = "PREVENTIVE",
    severity: str = "MEDIUM",
    impl_type: str = "AWS::Config::ConfigRule",
    impl_identifier=None,
    governed_resources=None,
) -> dict:
    """Build a single ListControls API response item.

    ``impl_identifier`` and ``governed_resources`` default to *absent* keys so
    the optional-field branches (Identifier -> None, GovernedResources -> [])
    can be exercised through the real pagination path.
    """
    implementation: dict = {"Type": impl_type}
    if impl_identifier is not None:
        implementation["Identifier"] = impl_identifier

    item: dict = {
        "Arn": arn,
        "Name": name,
        "Description": description,
        "Behavior": behavior,
        "Severity": severity,
        "Implementation": implementation,
    }
    if governed_resources is not None:
        item["GovernedResources"] = governed_resources
    return item


def _page(*controls: dict) -> dict:
    """Wrap controls in a paginator page dict shaped like ListControls."""
    return {"Controls": list(controls)}


def _setup_boto3_mock(mock_boto3: MagicMock, pages: list) -> MagicMock:
    """Wire a mocked boto3 so client.get_paginator(...).paginate() -> pages."""
    mock_client = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = pages
    mock_client.get_paginator.return_value = mock_paginator
    mock_boto3.client.return_value = mock_client
    return mock_client


def _throttling_error() -> ClientError:
    """A transient throttling ClientError (HTTP 429)."""
    return ClientError(
        {
            "Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"},
            "ResponseMetadata": {"HTTPStatusCode": 429},
        },
        "ListControls",
    )


def _server_error() -> ClientError:
    """A transient server-side ClientError (HTTP 500)."""
    return ClientError(
        {
            "Error": {
                "Code": "InternalServerException",
                "Message": "Internal server error",
            },
            "ResponseMetadata": {"HTTPStatusCode": 500},
        },
        "ListControls",
    )


# --- pagination + field preservation -----------------------------------------

class TestRetrieverPagination:
    """Multi-page aggregation and field preservation."""

    def test_multi_page_pagination_aggregates_controls_in_order(self):
        """Controls from every page are aggregated in page-then-item order and
        every field is preserved on the returned Control objects; the paginator
        is requested once for ``list_controls``."""
        pages = [
            _page(
                _api_control(
                    ARN1,
                    "S3 Block Public Access",
                    description="Blocks public access to S3 buckets.",
                    behavior="PREVENTIVE",
                    severity="HIGH",
                    impl_type="AWS::Config::ConfigRule",
                    impl_identifier="s3-account-level-public-access-blocks",
                    governed_resources=["AWS::S3::Bucket"],
                ),
                _api_control(
                    ARN2,
                    "EC2 IMDSv2 Required",
                    description="Requires IMDSv2 on EC2 instances.",
                    behavior="DETECTIVE",
                    severity="MEDIUM",
                    impl_type="AWS::Config::ConfigRule",
                    impl_identifier="ec2-imdsv2-check",
                    governed_resources=["AWS::EC2::Instance", "AWS::EC2::LaunchTemplate"],
                ),
            ),
            _page(
                # Optional fields absent: Identifier -> None, GovernedResources -> [].
                _api_control(
                    ARN3,
                    "RDS Encryption",
                    description="Ensures RDS storage encryption.",
                    behavior="PROACTIVE",
                    severity="CRITICAL",
                    impl_type="AWS::CloudFormation::Hook",
                ),
            ),
        ]

        with patch(BOTO3_TARGET) as mock_boto3:
            mock_client = _setup_boto3_mock(mock_boto3, pages)
            controls = retrieve_control_catalog(region=None)

        mock_client.get_paginator.assert_called_once_with("list_controls")

        # Order preserved across pages and within each page.
        assert [c.arn for c in controls] == [ARN1, ARN2, ARN3]
        assert all(isinstance(c, Control) for c in controls)

        # Page 1, control 1: fully populated.
        first = controls[0]
        assert first.name == "S3 Block Public Access"
        assert first.description == "Blocks public access to S3 buckets."
        assert first.behavior == "PREVENTIVE"
        assert first.severity == "HIGH"
        assert isinstance(first.implementation, ControlImplementation)
        assert first.implementation.type == "AWS::Config::ConfigRule"
        assert first.implementation.identifier == "s3-account-level-public-access-blocks"
        assert first.governed_resources == ["AWS::S3::Bucket"]

        # Page 1, control 2: multiple governed resources preserved in order.
        second = controls[1]
        assert second.behavior == "DETECTIVE"
        assert second.severity == "MEDIUM"
        assert second.implementation.identifier == "ec2-imdsv2-check"
        assert second.governed_resources == [
            "AWS::EC2::Instance",
            "AWS::EC2::LaunchTemplate",
        ]

        # Page 2, control 3: optional fields defaulted (identifier None, [] resources).
        third = controls[2]
        assert third.behavior == "PROACTIVE"
        assert third.severity == "CRITICAL"
        assert third.implementation.type == "AWS::CloudFormation::Hook"
        assert third.implementation.identifier is None
        assert third.governed_resources == []

    def test_empty_catalog_returns_empty_list(self):
        """A single empty page (no Controls) yields an empty catalog without
        error."""
        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [_page()])
            controls = retrieve_control_catalog(region=None)

        assert controls == []


# --- client Config: retries, timeouts, region --------------------------------

class TestClientConfig:
    """boto3 client Config and region handling."""

    def test_client_configured_for_adaptive_retries_and_timeouts(self):
        """The controlcatalog client is built with adaptive retries
        (max_attempts=3) and 30s connect/read timeouts -- i.e. retry/backoff is
        delegated to botocore via Config."""
        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [_page()])
            retrieve_control_catalog(region="us-east-1")

        args, kwargs = mock_boto3.client.call_args
        assert args[0] == "controlcatalog"

        config = kwargs["config"]
        assert config.retries == {"max_attempts": 3, "mode": "adaptive"}
        assert config.connect_timeout == 30
        assert config.read_timeout == 30

    def test_region_name_passed_when_region_provided(self):
        """region_name is forwarded to boto3.client when a region is given."""
        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [_page()])
            retrieve_control_catalog(region="us-west-2")

        _, kwargs = mock_boto3.client.call_args
        assert kwargs.get("region_name") == "us-west-2"

    def test_region_name_omitted_when_region_none(self):
        """region_name is NOT passed when region is None so the default
        credential/region chain is used."""
        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [_page()])
            retrieve_control_catalog(region=None)

        _, kwargs = mock_boto3.client.call_args
        assert "region_name" not in kwargs


# --- error handling ----------------------------------------------------------

class TestErrorHandling:
    """Terminal failure and credential handling."""

    def test_throttling_client_error_surfaced_as_runtime_error(self):
        """A transient throttling error (429) that survives botocore's retries
        surfaces as a descriptive RuntimeError naming the code and message, with
        the original ClientError chained."""
        with patch(BOTO3_TARGET) as mock_boto3:
            mock_client = _setup_boto3_mock(mock_boto3, [_page()])
            mock_client.get_paginator.return_value.paginate.side_effect = (
                _throttling_error()
            )

            with pytest.raises(RuntimeError) as excinfo:
                retrieve_control_catalog(region=None)

        assert str(excinfo.value) == (
            "AWS Control Catalog API error (ThrottlingException): Rate exceeded"
        )
        assert isinstance(excinfo.value.__cause__, ClientError)

    def test_server_client_error_surfaced_as_runtime_error(self):
        """A 5xx server error after retries are exhausted surfaces as a
        descriptive RuntimeError."""
        with patch(BOTO3_TARGET) as mock_boto3:
            mock_client = _setup_boto3_mock(mock_boto3, [_page()])
            mock_client.get_paginator.return_value.paginate.side_effect = (
                _server_error()
            )

            with pytest.raises(RuntimeError) as excinfo:
                retrieve_control_catalog(region=None)

        assert str(excinfo.value) == (
            "AWS Control Catalog API error (InternalServerException): "
            "Internal server error"
        )
        assert isinstance(excinfo.value.__cause__, ClientError)

    def test_no_credentials_error_surfaced_as_connection_error(self):
        """Missing credentials raise NoCredentialsError, a BotoCoreError
        subclass. The retriever has no dedicated credential branch, so it is
        caught by ``except BotoCoreError`` and re-raised as a RuntimeError whose
        message starts with the connection-error prefix."""
        with patch(BOTO3_TARGET) as mock_boto3:
            mock_client = _setup_boto3_mock(mock_boto3, [_page()])
            mock_client.get_paginator.return_value.paginate.side_effect = (
                NoCredentialsError()
            )

            with pytest.raises(RuntimeError) as excinfo:
                retrieve_control_catalog(region=None)

        assert str(excinfo.value).startswith("AWS Control Catalog connection error:")
        assert isinstance(excinfo.value.__cause__, NoCredentialsError)
