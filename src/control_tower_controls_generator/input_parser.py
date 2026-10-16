"""Input file parser for the Control Tower Controls Generator.

Handles three input formats:
1. Simple JSON array of resource type strings
2. Config aggregator query output with Results containing JSON-stringified rows
3. CSV export from AWS Config (with resourceType column)
"""

import csv
import json
import os
import re
import sys
from typing import Any

from control_tower_controls_generator.models import ParsedInput

# Canonical AWS account identifier: exactly twelve ASCII digits, nothing else.
# re.ASCII constrains \d to [0-9] so Unicode digits (e.g. Arabic-Indic) never match.
ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$", re.ASCII)

# Bound the echoed value so a hostile or oversized id cannot flood the terminal.
_MAX_WARN_VALUE_LEN = 64


def _is_valid_account_id(value: str) -> bool:
    """Return True iff ``value`` matches the canonical 12-digit account format.

    ``value`` is expected to already be stripped by the caller.
    """
    return ACCOUNT_ID_PATTERN.match(value) is not None


def _warn_invalid_account_id(value: str) -> None:
    """Emit a fail-open warning for a rejected account id to stderr.

    The rejected value is echoed as a bounded ``repr`` so control characters are
    made visible and an oversized or untrusted string cannot dump unbounded data
    to the terminal.
    """
    shown = value if len(value) <= _MAX_WARN_VALUE_LEN else value[:_MAX_WARN_VALUE_LEN] + "..."
    print(
        f"Warning: skipping invalid account id (expected 12 digits): {shown!r}",
        file=sys.stderr,
    )


class InputParserError(Exception):
    """Raised when input parsing fails."""

    pass


def parse_input_file(file_path: str) -> ParsedInput:
    """Parse a resource type input file in JSON, Config aggregator, or CSV format.

    Args:
        file_path: Path to the input file (JSON or CSV).

    Returns:
        ParsedInput with deduplicated resource types and optional account mapping.

    Raises:
        InputParserError: If the file cannot be read, is invalid,
            or yields no valid resource types.
    """
    if not os.path.exists(file_path):
        raise InputParserError(f"Input file not found: {file_path}")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError as e:
        raise InputParserError(f"Cannot read input file: {file_path} ({e})")

    # Detect CSV by file extension or content heuristic
    if file_path.lower().endswith(".csv") or _looks_like_csv(content):
        return _parse_csv(content)

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise InputParserError(f"Invalid JSON in input file: {file_path} ({e})")

    if isinstance(data, list):
        return _parse_simple_array(data)
    elif isinstance(data, dict) and "Results" in data:
        return _parse_config_aggregator_output(data)
    else:
        raise InputParserError(
            "Invalid input format: expected a JSON array of resource types, "
            "a Config aggregator query output with a 'Results' field, "
            "or a CSV file with a 'resourceType' column"
        )


def _parse_simple_array(data: list[Any]) -> ParsedInput:
    """Parse a simple JSON array of resource type strings.

    Args:
        data: A list that should contain resource type strings.

    Returns:
        ParsedInput with deduplicated resource types, no account mapping.

    Raises:
        InputParserError: If no valid resource types are found.
    """
    resource_types: list[str] = []
    for item in data:
        if isinstance(item, str) and item.strip():
            resource_types.append(item.strip())

    resource_types = _deduplicate(resource_types)

    if not resource_types:
        raise InputParserError("No valid resource types found in input file")

    return ParsedInput(resource_types=resource_types, account_mapping=None)


def _parse_config_aggregator_output(data: dict[str, Any]) -> ParsedInput:
    """Parse Config aggregator query output format.

    Expected format:
    {
        "QueryInfo": {...},
        "Results": [
            "{\"resourceType\":\"AWS::EC2::Instance\",\"accountId\":\"123456789012\"}",
            ...
        ]
    }

    Args:
        data: Dict with a "Results" key containing JSON-stringified rows.

    Returns:
        ParsedInput with deduplicated resource types and account mapping
        (if accountId data is present).

    Raises:
        InputParserError: If no valid resource types are found.
    """
    results = data.get("Results", [])
    if not isinstance(results, list):
        raise InputParserError("Invalid Config aggregator format: 'Results' must be an array")

    resource_types: list[str] = []
    account_mapping: dict[str, list[str]] = {}
    has_account_data = False

    for row in results:
        if not isinstance(row, str):
            continue

        try:
            parsed_row = json.loads(row)
        except json.JSONDecodeError:
            continue

        if not isinstance(parsed_row, dict):
            continue

        resource_type = parsed_row.get("resourceType")
        if not isinstance(resource_type, str) or not resource_type.strip():
            continue

        resource_type = resource_type.strip()
        resource_types.append(resource_type)

        account_id = parsed_row.get("accountId")
        if isinstance(account_id, str) and account_id.strip():
            account_id = account_id.strip()
            if not _is_valid_account_id(account_id):
                _warn_invalid_account_id(account_id)
                continue  # skip: do not set has_account_data, do not append
            has_account_data = True
            if resource_type not in account_mapping:
                account_mapping[resource_type] = []
            if account_id not in account_mapping[resource_type]:
                account_mapping[resource_type].append(account_id)

    resource_types = _deduplicate(resource_types)

    if not resource_types:
        raise InputParserError("No valid resource types found in input file")

    return ParsedInput(
        resource_types=resource_types,
        account_mapping=account_mapping if has_account_data else None,
    )


def _deduplicate(items: list[str]) -> list[str]:
    """Remove duplicates from a list while preserving order.

    Args:
        items: List of strings possibly containing duplicates.

    Returns:
        List with duplicates removed, original order preserved.
    """
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _looks_like_csv(content: str) -> bool:
    """Heuristic to detect if content is CSV rather than JSON.

    Checks if the first line looks like a CSV header containing 'resourceType'.
    """
    first_line = content.strip().split("\n")[0] if content.strip() else ""
    # Check for common CSV patterns: quoted headers or resourceType keyword
    lower_line = first_line.lower().replace('"', "").replace("'", "")
    return "resourcetype" in lower_line and not first_line.strip().startswith(("{", "["))


def _parse_csv(content: str) -> ParsedInput:
    """Parse a CSV file exported from AWS Config.

    Supports formats like:
    - "resourceType","COUNT(*)"
    - resourceType,accountId
    - resourceType

    The first column matching 'resourceType' (case-insensitive) is used
    to extract resource types. If an 'accountId' column is present,
    account mapping is built.

    Args:
        content: The CSV file content as a string.

    Returns:
        ParsedInput with deduplicated resource types and optional account mapping.

    Raises:
        InputParserError: If no valid resource types are found.
    """
    import io

    reader = csv.DictReader(io.StringIO(content))

    # Find the resourceType column (case-insensitive)
    if reader.fieldnames is None:
        raise InputParserError("CSV file has no headers")

    rt_column = None
    account_column = None
    for field in reader.fieldnames:
        clean = field.strip().strip('"').strip("'").lower()
        if clean == "resourcetype":
            rt_column = field
        elif clean == "accountid":
            account_column = field

    if rt_column is None:
        raise InputParserError(
            "CSV file must have a 'resourceType' column. "
            f"Found columns: {', '.join(reader.fieldnames)}"
        )

    resource_types: list[str] = []
    account_mapping: dict[str, list[str]] = {}
    has_account_data = False

    for row in reader:
        rt_value = row.get(rt_column, "")
        if not rt_value:
            continue

        # Strip quotes and whitespace
        resource_type = rt_value.strip().strip('"').strip("'").strip()
        if not resource_type or not resource_type.startswith("AWS::"):
            continue

        resource_types.append(resource_type)

        if account_column:
            account_id = row.get(account_column, "").strip().strip('"').strip("'").strip()
            if account_id:
                if not _is_valid_account_id(account_id):
                    _warn_invalid_account_id(account_id)
                else:
                    has_account_data = True
                    if resource_type not in account_mapping:
                        account_mapping[resource_type] = []
                    if account_id not in account_mapping[resource_type]:
                        account_mapping[resource_type].append(account_id)

    resource_types = _deduplicate(resource_types)

    if not resource_types:
        raise InputParserError("No valid resource types found in CSV file")

    return ParsedInput(
        resource_types=resource_types,
        account_mapping=account_mapping if has_account_data else None,
    )
