"""Control mappings retriever module.

Retrieves control-to-framework mappings by paginating through the Control
Catalog ListControlMappings API and builds an index keyed by control ARN.

Mirrors ``control_retriever.py``: a ``controlcatalog`` boto3 client with a
paginator, adaptive retries (``max_attempts=3``), 30-second connect/read
timeouts, and ``RuntimeError`` on API failure.

Framework associations are many-to-many: a single control ARN can appear in
several FRAMEWORK mappings, so each ARN maps to a list of associations.
COMMON_CONTROL mappings are excluded from the index.
"""

from collections.abc import Iterable
from typing import Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError

from control_tower_controls_generator.models import FrameworkAssociation


# Index of every FRAMEWORK association per control ARN (many-to-many).
FrameworkAssociationIndex = dict[str, list[FrameworkAssociation]]


def retrieve_control_mappings(region: Optional[str] = None) -> FrameworkAssociationIndex:
    """Retrieve control-to-framework mappings from the ListControlMappings API.

    Indexes *every* framework association per control ARN regardless of what
    frameworks the caller intends to filter by; requested-framework selection
    is applied downstream by ``framework_filter``.

    Args:
        region: Optional AWS region override. Uses the default region if not
            specified.

    Returns:
        A ``FrameworkAssociationIndex`` mapping each control ARN to the list of
        its FRAMEWORK associations.

    Raises:
        RuntimeError: If the API call fails after retries are exhausted.
    """
    return _fetch_from_api(region)


def _fetch_from_api(region: Optional[str] = None) -> FrameworkAssociationIndex:
    """Paginate ListControlMappings and build the framework-association index.

    Uses the default AWS credential chain and passes ``region_name`` only
    when a region is supplied. On API or connection failure, wraps the
    underlying error as the ``__cause__`` of a ``RuntimeError`` so the CLI's
    ``_is_auth_error`` can unwrap it and route to exit code 2 (API) or 3
    (auth).
    """
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
        paginator = client.get_paginator("list_control_mappings")
        # Iteration of the paginator triggers the (lazy) API calls; any
        # ClientError/BotoCoreError raised during iteration propagates through
        # _index_mappings (which does no error handling) to the handlers below.
        return _index_mappings(paginator.paginate())

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


def _index_mappings(pages: Iterable[dict]) -> FrameworkAssociationIndex:
    """Build a framework-association index from ListControlMappings pages.

    Pure page-processing with no boto3 dependency: accepts any iterable of page
    dicts (as produced by the ListControlMappings paginator) so it can be
    exercised in unit and property tests without live AWS calls.

    For each control mapping:
      * ``MappingType == "FRAMEWORK"``: append ``FrameworkAssociation(name, item)``
        to ``index[ControlArn]``, preserving many-to-many associations for a
        repeated ARN.
      * any other ``MappingType`` (including ``COMMON_CONTROL``): skipped.
      * a FRAMEWORK mapping missing its ControlArn, Name, or Item is skipped.
    """
    index: FrameworkAssociationIndex = {}
    for page in pages:
        for mapping in page.get("ControlMappings", []):
            if mapping.get("MappingType") != "FRAMEWORK":
                continue

            control_arn = mapping.get("ControlArn")
            framework = mapping.get("Mapping", {}).get("Framework", {})
            name = framework.get("Name")
            item = framework.get("Item")

            # Skip incomplete FRAMEWORK mappings rather than indexing partial
            # or unusable associations.
            if not control_arn or name is None or item is None:
                continue

            index.setdefault(control_arn, []).append(
                FrameworkAssociation(name=name, item=item)
            )
    return index
