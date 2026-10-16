"""Resource-to-Control mapper module for the Control Tower Controls Generator."""

from control_tower_controls_generator.models import Control, MappedControl


def map_resource_types_to_controls(
    resource_types: list[str],
    controls: list[Control],
) -> list[MappedControl]:
    """Map input resource types to controls whose GovernedResources contain a match.

    For each control, checks if its governed_resources list contains any of the
    input resource types (exact string match). Controls with empty governed_resources
    are excluded. Each control appears at most once, with all matching resource types
    aggregated in matched_resource_types.

    Args:
        resource_types: List of AWS resource type strings to match against.
        controls: List of Control objects from the control catalog.

    Returns:
        List of MappedControl objects for controls that match at least one
        input resource type.
    """
    resource_type_set = set(resource_types)
    result: list[MappedControl] = []

    for control in controls:
        # Exclude controls with empty governed_resources
        if not control.governed_resources:
            continue

        # Find all input resource types that match this control's governed resources
        matched = [
            rt for rt in control.governed_resources if rt in resource_type_set
        ]

        if matched:
            result.append(MappedControl(control=control, matched_resource_types=matched))

    return result
