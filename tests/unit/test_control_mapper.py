"""Unit tests for the resource-to-control mapper module.

Plain example-based pytest tests covering the core mapping behavior of
``map_resource_types_to_controls``: single matches, deduplication with
aggregation of every triggering resource type, exclusion of controls with an
empty GovernedResources array, and exclusion of resource types / controls that
have no match.
"""

from control_tower_controls_generator.control_mapper import (
    map_resource_types_to_controls,
)
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
)


def _make_control(
    arn: str,
    governed_resources: list[str],
    name: str = "Control",
) -> Control:
    """Build a Control with the given ARN and governed resources."""
    return Control(
        arn=arn,
        name=name,
        description="desc",
        behavior="Preventive",
        severity="HIGH",
        implementation=ControlImplementation(type="SERVICE_CONTROL_POLICY"),
        governed_resources=list(governed_resources),
    )


class TestBasicMapping:
    """A single resource type matching a single control."""

    def test_single_resource_type_matches_single_control(self):
        control = _make_control(
            "arn:1", governed_resources=["AWS::S3::Bucket"], name="S3 control"
        )

        result = map_resource_types_to_controls(["AWS::S3::Bucket"], [control])

        assert len(result) == 1
        mapped = result[0]
        # The original control instance is carried through unchanged.
        assert mapped.control is control
        assert mapped.matched_resource_types == ["AWS::S3::Bucket"]


class TestDeduplicationAndAggregation:
    """One control triggered by several resource types."""

    def test_multiple_resource_types_matching_same_control_dedup(self):
        # A control that governs two resource types, both of which are present
        # in the input, must appear exactly once with BOTH triggering resource
        # types preserved (deduplicated control, aggregated resource types).
        control = _make_control(
            "arn:1",
            governed_resources=["AWS::S3::Bucket", "AWS::EC2::Instance"],
            name="Multi control",
        )

        result = map_resource_types_to_controls(
            ["AWS::EC2::Instance", "AWS::S3::Bucket"], [control]
        )

        # Deduplication: the control is emitted at most once.
        assert len(result) == 1
        matched = result[0].matched_resource_types
        # All triggering resource types are preserved, with no duplicates.
        assert sorted(matched) == ["AWS::EC2::Instance", "AWS::S3::Bucket"]
        assert len(matched) == len(set(matched))


class TestEmptyGovernedResourcesExcluded:
    """Controls with an empty GovernedResources array are dropped."""

    def test_control_with_empty_governed_resources_excluded(self):
        empty_control = _make_control(
            "arn:empty", governed_resources=[], name="Empty"
        )
        matching_control = _make_control(
            "arn:match", governed_resources=["AWS::S3::Bucket"], name="Match"
        )

        result = map_resource_types_to_controls(
            ["AWS::S3::Bucket"], [empty_control, matching_control]
        )

        # Only the control with a matching governed resource survives.
        assert len(result) == 1
        assert result[0].control.arn == "arn:match"
        returned_arns = {m.control.arn for m in result}
        assert "arn:empty" not in returned_arns


class TestNoMatchExcluded:
    """Resource types / controls without a match are excluded."""

    def test_resource_type_with_no_matching_controls_excluded(self):
        # Catalog only governs EC2; the input also contains Lambda (no control)
        # and there is an RDS control that nothing in the input references.
        ec2_control = _make_control(
            "arn:ec2", governed_resources=["AWS::EC2::Instance"], name="EC2"
        )
        rds_control = _make_control(
            "arn:rds", governed_resources=["AWS::RDS::DBInstance"], name="RDS"
        )

        result = map_resource_types_to_controls(
            ["AWS::EC2::Instance", "AWS::Lambda::Function"],
            [ec2_control, rds_control],
        )

        # Only the EC2 control is returned; the RDS control (no input match) is
        # excluded, and no error is raised for the unmatched Lambda input.
        assert len(result) == 1
        assert result[0].control.arn == "arn:ec2"
        assert result[0].matched_resource_types == ["AWS::EC2::Instance"]

        # The unmatched Lambda resource type never appears in any output.
        all_matched = [
            rt for m in result for rt in m.matched_resource_types
        ]
        assert "AWS::Lambda::Function" not in all_matched
