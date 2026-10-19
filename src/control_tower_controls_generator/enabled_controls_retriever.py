"""Existing controls retriever module.

Retrieves controls already enabled on a specified Organizational Unit
via the AWS Control Tower API.
"""

import re
from collections.abc import Iterable
from typing import Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError

from control_tower_controls_generator.models import EnabledControl


#: The bare Organizational Unit ID form, using the pattern AWS Organizations
#: itself defines for ``OrganizationalUnitId``. ``ListEnabledControls`` types
#: ``targetIdentifier`` as an ARN (``min: 20``, ``pattern: arn:aws...``), so a
#: value matching this has to be resolved before the request can be sent.
OU_ID_PATTERN = re.compile(r"^ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}$")


def _client_kwargs(region: Optional[str] = None) -> dict:
    """Build the boto3 client kwargs shared by every client on this path.

    Adaptive retries capped at 3 attempts with 30-second connect and read
    timeouts, and ``region_name`` only when a region was actually supplied so
    default AWS region resolution still applies when it was not.
    """
    retry_config = Config(
        retries={
            "max_attempts": 3,
            "mode": "adaptive",
        },
        connect_timeout=30,
        read_timeout=30,
    )

    kwargs: dict = {"config": retry_config}
    if region:
        kwargs["region_name"] = region

    return kwargs


def _collect_enabled_controls(pages: Iterable[dict]) -> list[EnabledControl]:
    """Map ListEnabledControls response pages to the internal EnabledControl model.

    Pure page-processing with no boto3 dependency: accepts any iterable of page
    dicts (as produced by the ListEnabledControls paginator) so the response key
    names and the aggregation order can be exercised in unit and property tests
    without a client.

    The keys read are the ones the ``controltower`` service model defines:
    ``enabledControls`` on each page, and ``controlIdentifier`` on each item.
    An item whose ``controlIdentifier`` is absent or empty is skipped rather
    than yielding an ``EnabledControl`` with an empty ARN, which would land in
    the enabled set and match nothing.

    Controls are appended in page-then-item order with no de-duplication, so a
    repeated ARN is returned once per occurrence.
    """
    enabled_controls: list[EnabledControl] = []

    for page in pages:
        for item in page.get("enabledControls", []):
            control_arn = item.get("controlIdentifier", "")
            if control_arn:
                enabled_controls.append(EnabledControl(control_arn=control_arn))

    return enabled_controls


def _resolve_target_identifier(ou_id: str, region: Optional[str] = None) -> str:
    """Resolve an OU identifier to a value ``targetIdentifier`` can be bound to.

    ``ListEnabledControls`` types ``targetIdentifier`` as an ARN, so a bare OU
    ID is resolved to that OU's ARN via ``organizations:DescribeOrganizationalUnit``.
    The ARN is read from the API response rather than assembled locally, which
    would require separately discovering the organization ID, the management
    account ID, and the partition.

    A value that does not match ``OU_ID_PATTERN`` is returned verbatim and no
    Organizations client is constructed at all, so OU ARNs and any other
    identifier form the API accepts reach it unrewritten.

    Args:
        ou_id: The Organizational Unit ID or ARN supplied by the caller.
        region: Optional AWS region override. Organizations resolves to the
            partition-global endpoint, so the region does not steer the endpoint
            within a partition but does keep behavior correct across partitions.

    Returns:
        The OU's ARN when ``ou_id`` is a bare OU ID, otherwise ``ou_id`` itself.

    Raises:
        RuntimeError: If the AWS Organizations call fails. The message names AWS
            Organizations so stderr identifies which of the two AWS calls on
            this path failed, and carries ``ou_id`` as the user supplied it.
    """
    if not OU_ID_PATTERN.match(ou_id):
        return ou_id

    try:
        client = boto3.client("organizations", **_client_kwargs(region))
        response = client.describe_organizational_unit(OrganizationalUnitId=ou_id)
        return response["OrganizationalUnit"]["Arn"]

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        raise RuntimeError(
            f"AWS Organizations API error resolving OU '{ou_id}' "
            f"({error_code}): {error_message}"
        ) from e
    except BotoCoreError as e:
        raise RuntimeError(
            f"AWS Organizations connection error resolving OU '{ou_id}': {e}"
        ) from e


def retrieve_enabled_controls(
    ou_id: str, region: Optional[str] = None
) -> list[EnabledControl]:
    """Retrieve the list of controls already enabled on the given OU.

    Uses the Control Tower ListEnabledControls API to fetch all controls
    enabled on the specified Organizational Unit, across every page.

    A retrieval failure is *not* degraded into an empty list: an empty list is
    how an OU with genuinely nothing enabled is reported, so returning it on
    failure would let the run write a report claiming "Already Enabled: 0" and
    exit 0 for a comparison that never happened. Failures propagate instead.

    Args:
        ou_id: The Organizational Unit ID (e.g., "ou-xxxx-xxxxxxxx") or the OU
            ARN (e.g., "arn:aws:organizations::111122223333:ou/o-abc123/ou-xxxx-xxxxxxxx").
            ``targetIdentifier`` is typed as an ARN, so a bare OU ID is first
            resolved via ``organizations:DescribeOrganizationalUnit``, which
            requires the ``organizations:DescribeOrganizationalUnit``
            permission; an ARN is used verbatim and makes no Organizations call.
        region: Optional AWS region override. Uses default region if not specified.

    Returns:
        A list of EnabledControl objects representing controls enabled on the OU,
        in page-then-item order. Empty only when the OU has no enabled controls.

    Raises:
        RuntimeError: If the AWS Organizations resolution call or the Control
            Tower API call fails. The message identifies the failing service and
            the OU as supplied, and the underlying botocore exception is chained
            as ``__cause__`` so ``cli.py`` can route to exit 3 for
            authentication or authorization failures and exit 2 otherwise.
    """
    # Resolved outside the try block below so that a resolution failure cannot
    # be shadowed by the Control Tower error handling.
    target_identifier = _resolve_target_identifier(ou_id, region)

    try:
        client = boto3.client("controltower", **_client_kwargs(region))
        paginator = client.get_paginator("list_enabled_controls")

        # Iteration of the paginator triggers the (lazy) API calls; any
        # ClientError/BotoCoreError raised during iteration propagates through
        # _collect_enabled_controls (which does no error handling) to the
        # handlers below.
        return _collect_enabled_controls(
            paginator.paginate(targetIdentifier=target_identifier)
        )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        raise RuntimeError(
            f"AWS Control Tower API error for OU '{ou_id}' "
            f"({error_code}): {error_message}"
        ) from e
    except BotoCoreError as e:
        raise RuntimeError(
            f"AWS Control Tower connection error for OU '{ou_id}': {e}"
        ) from e
