"""Control catalog retriever module.

Retrieves the full AWS Control Catalog by paginating through the ListControls API.
"""

from typing import Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError

from control_tower_controls_generator.models import Control, ControlImplementation


def retrieve_control_catalog(region: Optional[str] = None) -> list[Control]:
    """Retrieve the complete control catalog from the ListControls API.

    Args:
        region: Optional AWS region override. Uses default region if not specified.

    Returns:
        A list of Control objects representing all controls in the catalog.

    Raises:
        RuntimeError: If the API call fails after retries are exhausted.
    """
    return _fetch_from_api(region)


def _map_api_item_to_control(item: dict) -> Control:
    """Map a single ListControls API response item to the internal Control model.

    Pure function (no I/O, no side effects) so the field-preservation property
    can be exercised without a boto3 client. All fields are copied verbatim; a
    missing ``Implementation.Identifier`` maps to ``None`` and a missing
    ``GovernedResources`` maps to an empty list.
    """
    implementation_data = item.get("Implementation", {})
    implementation = ControlImplementation(
        type=implementation_data.get("Type", ""),
        identifier=implementation_data.get("Identifier"),
    )

    return Control(
        arn=item["Arn"],
        name=item["Name"],
        description=item["Description"],
        behavior=item["Behavior"],
        severity=item["Severity"],
        implementation=implementation,
        governed_resources=item.get("GovernedResources", []),
    )


def _fetch_from_api(region: Optional[str] = None) -> list[Control]:
    """Fetch the complete control catalog from the ListControls API."""
    retry_config = Config(
        retries={
            "max_attempts": 3,
            "mode": "adaptive",
        },
        connect_timeout=30,
        read_timeout=30,
    )

    client_kwargs: dict = {"config": retry_config}
    if region:
        client_kwargs["region_name"] = region

    try:
        client = boto3.client("controlcatalog", **client_kwargs)
        paginator = client.get_paginator("list_controls")
        controls: list[Control] = []

        for page in paginator.paginate():
            for item in page.get("Controls", []):
                controls.append(_map_api_item_to_control(item))

        return controls

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        raise RuntimeError(
            f"AWS Control Catalog API error ({error_code}): {error_message}"
        ) from e
    except BotoCoreError as e:
        raise RuntimeError(
            f"AWS Control Catalog connection error: {e}"
        ) from e
