"""Core data models for the Control Tower Controls Generator."""

from dataclasses import dataclass, field
from typing import Optional


# Severity ordering constant: LOW < MEDIUM < HIGH < CRITICAL
SEVERITY_ORDER: dict[str, int] = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class CLIOptions:
    """Command-line options for the Control Tower Controls Generator."""

    input_file: str
    output_format: str = "json"
    output_file: Optional[str] = None
    severity_filter: Optional[str] = None
    region: Optional[str] = None
    organizational_unit: Optional[str] = None


@dataclass
class ParsedInput:
    """Parsed input containing resource types and optional account mapping."""

    resource_types: list[str]
    account_mapping: Optional[dict[str, list[str]]] = None


@dataclass
class ControlImplementation:
    """Implementation details for a control."""

    type: str
    identifier: Optional[str] = None


@dataclass
class Control:
    """A control from the AWS Control Catalog."""

    arn: str
    name: str
    description: str
    behavior: str
    severity: str
    implementation: ControlImplementation
    governed_resources: list[str] = field(default_factory=list)


@dataclass
class FrameworkAssociation:
    """A single control-to-framework association from ListControlMappings."""

    name: str  # Mapping.Framework.Name, e.g. "PCI-DSS-v4.0"
    item: str  # Mapping.Framework.Item, e.g. "7.2.2"


@dataclass
class MappedControl:
    """A control matched to input resource types."""

    control: Control
    matched_resource_types: list[str] = field(default_factory=list)
    # Populated by filter_by_framework with the requested frameworks this
    # control is associated with. Empty when no framework filter is active.
    framework_associations: list[FrameworkAssociation] = field(default_factory=list)


@dataclass
class SeverityFilterConfig:
    """Configuration for severity-based filtering."""

    minimum: Optional[str] = None
    specific: Optional[list[str]] = None


@dataclass
class FrameworkFilterConfig:
    """Configuration for framework-based filtering.

    ``frameworks`` is None when unset (opt-out); otherwise a list of one or
    more requested Framework names, already trimmed of surrounding whitespace.
    """

    frameworks: Optional[list[str]] = None


@dataclass
class EnabledControl:
    """A control already enabled on an Organizational Unit."""

    control_arn: str


@dataclass
class ReportEntry:
    """A single entry in the output report."""

    control_name: str
    control_arn: str
    behavior: str
    severity: str
    matched_resource_types: list[str] = field(default_factory=list)
    accounts: Optional[list[str]] = None
    enablement_status: str = "not enabled"
    # None => attribution omitted (no framework filter). A list (possibly
    # empty) => attribution rendered.
    framework_associations: Optional[list[FrameworkAssociation]] = None


@dataclass
class ReportSummary:
    """Summary statistics for the output report."""

    total_recommended: int
    already_enabled: int
    gaps: int


@dataclass
class Report:
    """The complete output report."""

    summary: ReportSummary
    controls: list[ReportEntry] = field(default_factory=list)
    message: Optional[str] = None
