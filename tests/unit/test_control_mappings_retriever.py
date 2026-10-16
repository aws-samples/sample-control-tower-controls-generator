"""Unit tests for the control mappings retriever module.

Covers retriever wiring: pagination, boto3 client Config, and region handling.
``moto`` does not support the ``controlcatalog`` service, so boto3 is mocked via
``unittest.mock.patch`` on the module's ``boto3`` reference rather than
simulated with a fake AWS backend.
"""

from unittest.mock import MagicMock, patch

from control_tower_controls_generator.control_mappings_retriever import (
    retrieve_control_mappings,
)
from control_tower_controls_generator.models import FrameworkAssociation


BOTO3_TARGET = "control_tower_controls_generator.control_mappings_retriever.boto3"

ARN1 = "arn:aws:controlcatalog:::control/2xknmxmas18xrbvvexzq9k06g"
ARN2 = "arn:aws:controlcatalog:::control/e2saoisw5u8xe40acfetio41w"
ARN3 = "arn:aws:controlcatalog:::control/aaaabbbbccccddddeeeeffff00"


# --- helpers -----------------------------------------------------------------

def _framework_mapping(arn: str, name: str, item: str) -> dict:
    """Build a FRAMEWORK ControlMapping dict shaped like ListControlMappings."""
    return {
        "ControlArn": arn,
        "MappingType": "FRAMEWORK",
        "Mapping": {"Framework": {"Name": name, "Item": item}},
    }


def _common_control_mapping(arn: str) -> dict:
    """Build a COMMON_CONTROL ControlMapping dict (must be excluded)."""
    return {
        "ControlArn": arn,
        "MappingType": "COMMON_CONTROL",
        "Mapping": {"CommonControl": {"Name": "some-common-control"}},
    }


def _page(*mappings: dict) -> dict:
    """Wrap mappings in a paginator page dict."""
    return {"ControlMappings": list(mappings)}


def _setup_boto3_mock(mock_boto3: MagicMock, pages: list) -> MagicMock:
    """Wire a mocked boto3 so client.get_paginator(...).paginate() -> pages."""
    mock_client = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = pages
    mock_client.get_paginator.return_value = mock_paginator
    mock_boto3.client.return_value = mock_client
    return mock_client


# --- retriever wiring --------------------------------------------------------

class TestRetrieverWiring:
    """Pagination, boto3 client Config, and region handling."""

    def test_multi_page_pagination_aggregates_all_mappings(self):
        """All FRAMEWORK mappings across multiple pages are aggregated; a
        repeated ARN accumulates associations and COMMON_CONTROL is excluded."""
        pages = [
            _page(
                _framework_mapping(ARN1, "PCI-DSS-v4.0", "7.2.2"),
                _framework_mapping(ARN2, "NIST-SP-800-53-r5", "CM-5"),
            ),
            _page(
                _framework_mapping(ARN3, "CIS-v8.0", "3.1"),
                _common_control_mapping(ARN1),  # excluded
                _framework_mapping(ARN1, "NIST-SP-800-53-r5", "AC-3"),  # spans pages
            ),
        ]

        with patch(BOTO3_TARGET) as mock_boto3:
            mock_client = _setup_boto3_mock(mock_boto3, pages)
            index = retrieve_control_mappings(region=None)

        mock_client.get_paginator.assert_called_once_with("list_control_mappings")
        assert set(index.keys()) == {ARN1, ARN2, ARN3}
        assert index[ARN1] == [
            FrameworkAssociation("PCI-DSS-v4.0", "7.2.2"),
            FrameworkAssociation("NIST-SP-800-53-r5", "AC-3"),
        ]
        assert index[ARN2] == [FrameworkAssociation("NIST-SP-800-53-r5", "CM-5")]
        assert index[ARN3] == [FrameworkAssociation("CIS-v8.0", "3.1")]

    def test_client_constructed_with_retry_and_timeout_config(self):
        """boto3.client is built for controlcatalog with adaptive retries
        (max_attempts=3) and 30s connect/read timeouts."""
        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [_page()])
            retrieve_control_mappings(region="us-east-1")

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
            retrieve_control_mappings(region="us-west-2")

        _, kwargs = mock_boto3.client.call_args
        assert kwargs.get("region_name") == "us-west-2"

    def test_region_name_omitted_when_region_none(self):
        """region_name is NOT passed when region is None so the default
        credential/region chain is used."""
        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [_page()])
            retrieve_control_mappings(region=None)

        _, kwargs = mock_boto3.client.call_args
        assert "region_name" not in kwargs
