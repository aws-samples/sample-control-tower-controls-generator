"""Severity filter module for the Control Tower Controls Generator."""

from control_tower_controls_generator.models import (
    MappedControl,
    SeverityFilterConfig,
    SEVERITY_ORDER,
)


def filter_by_severity(
    controls: list[MappedControl],
    filter_config: SeverityFilterConfig,
) -> list[MappedControl]:
    """Filter controls by severity, returning only those that satisfy the filter criteria.

    Supports two filtering modes:
    - Minimum severity level: includes controls at or above the specified level
    - Specific severity levels: includes only controls matching one of the listed levels

    When no filter is specified (both minimum and specific are None), all controls pass through.

    Args:
        controls: List of mapped controls to filter.
        filter_config: Configuration specifying the severity filter criteria.

    Returns:
        Filtered list of mapped controls satisfying the severity criteria.
    """
    if filter_config.minimum is None and filter_config.specific is None:
        return list(controls)

    if filter_config.specific is not None:
        allowed = {level.upper() for level in filter_config.specific}
        return [c for c in controls if c.control.severity.upper() in allowed]

    # Minimum severity filtering
    min_order = SEVERITY_ORDER.get(filter_config.minimum.upper(), 0)
    return [
        c
        for c in controls
        if SEVERITY_ORDER.get(c.control.severity.upper(), 0) >= min_order
    ]
