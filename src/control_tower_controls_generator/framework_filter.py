"""Framework filter module for the Control Tower Controls Generator."""

from control_tower_controls_generator.models import (
    FrameworkAssociation,
    FrameworkFilterConfig,
    MappedControl,
)


def filter_by_framework(
    controls: list[MappedControl],
    mapping_index: dict[str, list[FrameworkAssociation]],
    config: FrameworkFilterConfig,
) -> list[MappedControl]:
    """Filter controls by compliance framework association, attaching attribution.

    Retains only controls associated with at least one requested Framework and
    annotates each surviving control with the matching associations so the
    report generator can render framework attribution.

    When no framework is requested (``config.frameworks is None``), the filter
    is opt-out: every control passes through unchanged with no attribution
    attached, preserving the tool's default behavior.

    The ``mapping_index`` is intentionally annotated with a plain
    ``dict[str, list[FrameworkAssociation]]`` type rather than importing the
    ``FrameworkAssociationIndex`` alias, keeping this pure filter decoupled from
    the control-mappings retriever.

    Args:
        controls: List of mapped controls to filter.
        mapping_index: Framework associations keyed by control ARN.
        config: Configuration specifying the requested Framework names.

    Returns:
        A new list of mapped controls associated with at least one requested
        Framework. Each returned control is a fresh ``MappedControl`` carrying
        only the matched associations; the input controls are never mutated.
    """
    if config.frameworks is None:
        return list(controls)

    requested = {name.lower() for name in config.frameworks}

    filtered: list[MappedControl] = []
    for mapped in controls:
        associations = mapping_index.get(mapped.control.arn, [])
        matched = [
            association
            for association in associations
            if association.name.lower() in requested
        ]
        if matched:
            filtered.append(
                MappedControl(
                    control=mapped.control,
                    matched_resource_types=list(mapped.matched_resource_types),
                    framework_associations=matched,
                )
            )

    return filtered


def find_unrecognized_frameworks(
    config: FrameworkFilterConfig,
    mapping_index: dict[str, list[FrameworkAssociation]],
) -> list[str]:
    """Return the requested Framework names absent from every association name.

    Identifies the Framework names requested in ``config`` that match no
    association name anywhere in ``mapping_index`` under case-insensitive exact
    comparison, consistent with :func:`filter_by_framework`'s matching. The CLI
    prints a warning to standard error for each returned name and continues
    processing the recognized Frameworks; this function
    itself performs no I/O and prints nothing.

    Requested names are compared against the set of all association names
    present across every value list in ``mapping_index``. Returned names keep
    their original form and casing and preserve the requested order, so the CLI
    can echo them back to the user verbatim.

    Args:
        config: Configuration specifying the requested Framework names.
        mapping_index: Framework associations keyed by control ARN.

    Returns:
        The requested Framework names that do not case-insensitively match any
        association name present in the index, in their original casing and
        request order. Returns an empty list when no Framework is requested
        (``config.frameworks is None``).
    """
    if config.frameworks is None:
        return []

    known = {
        association.name.lower()
        for associations in mapping_index.values()
        for association in associations
    }

    return [name for name in config.frameworks if name.lower() not in known]
