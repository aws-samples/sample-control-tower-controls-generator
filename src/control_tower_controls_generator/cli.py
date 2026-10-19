"""CLI entry point for the Control Tower Controls Generator.

Uses click to define command-line parameters and wires together the
full pipeline: parse → retrieve catalog → map → filter → compare → report → write.
"""

import os
import sys
from datetime import datetime
from typing import Optional

import click

from control_tower_controls_generator.input_parser import parse_input_file, InputParserError
from control_tower_controls_generator.control_retriever import retrieve_control_catalog
from control_tower_controls_generator.control_mappings_retriever import retrieve_control_mappings
from control_tower_controls_generator.control_mapper import map_resource_types_to_controls
from control_tower_controls_generator.severity_filter import filter_by_severity
from control_tower_controls_generator.framework_filter import (
    filter_by_framework,
    find_unrecognized_frameworks,
)
from control_tower_controls_generator.enabled_controls_retriever import retrieve_enabled_controls
from control_tower_controls_generator.report_generator import generate_report
from control_tower_controls_generator.output_writer import write_output
from control_tower_controls_generator.models import SeverityFilterConfig, FrameworkFilterConfig


VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_BEHAVIORS = {"PREVENTIVE", "PROACTIVE", "DETECTIVE"}

AUTH_ERROR_CODES = {
    "InvalidIdentityToken",
    "ExpiredToken",
    "ExpiredTokenException",
    "InvalidClientTokenId",
    "AccessDeniedException",
    "UnauthorizedAccess",
    "AuthFailure",
    "SignatureDoesNotMatch",
    "IncompleteSignature",
    "MissingAuthenticationToken",
    "InvalidSignatureException",
}


def validate_severity_filter(
    ctx: click.Context, param: click.Parameter, value: Optional[str]
) -> Optional[str]:
    """Validate the severity filter value on input.

    Allowed values:
    - A single severity level (treated as minimum): LOW, MEDIUM, HIGH, CRITICAL
    - A comma-separated list of specific severity levels: e.g., HIGH,CRITICAL
    """
    if value is None:
        return None

    parts = [p.strip().upper() for p in value.split(",")]
    for part in parts:
        if part not in VALID_SEVERITIES:
            raise click.BadParameter(
                f"Invalid severity value '{part}'. "
                f"Allowed values: {', '.join(sorted(VALID_SEVERITIES))}"
            )

    return value


def validate_framework_filter(
    ctx: click.Context, param: click.Parameter, value: Optional[str]
) -> Optional[str]:
    """Validate the framework filter value on input.

    Accepts any non-empty value; splitting into individual Framework names and
    trimming whitespace happens later in ``parse_framework_filter``. Returns
    None for empty or whitespace-only input so downstream treats it as unset.
    """
    if value is None:
        return None
    if not value.strip():
        return None
    return value


def parse_severity_filter(value: Optional[str]) -> SeverityFilterConfig:
    """Parse a severity filter string into a SeverityFilterConfig.

    If the value contains a comma, treat as a specific list of severities.
    Otherwise, treat as a minimum severity level.
    """
    if value is None:
        return SeverityFilterConfig()

    parts = [p.strip().upper() for p in value.split(",")]
    if len(parts) > 1:
        return SeverityFilterConfig(specific=parts)
    else:
        return SeverityFilterConfig(minimum=parts[0])


def parse_framework_filter(value: Optional[str]) -> FrameworkFilterConfig:
    """Parse a framework filter string into a FrameworkFilterConfig.

    Splits on commas, strips leading/trailing whitespace from each name,
    and drops empty tokens. Returns
    ``FrameworkFilterConfig(frameworks=None)`` when the value is None, blank,
    or resolves to no names, so downstream treats it as unset.
    """
    if value is None:
        return FrameworkFilterConfig()

    names = [p.strip() for p in value.split(",")]
    names = [n for n in names if n]
    if not names:
        return FrameworkFilterConfig()
    return FrameworkFilterConfig(frameworks=names)


def _is_auth_error(exc: BaseException) -> bool:
    """Check if an exception is an authentication/authorization error."""
    # Check botocore ClientError codes
    from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

    if isinstance(exc, (NoCredentialsError, PartialCredentialsError)):
        return True

    if isinstance(exc, ClientError):
        error_code = exc.response.get("Error", {}).get("Code", "")
        if error_code in AUTH_ERROR_CODES:
            return True

    # Check wrapped exceptions (RuntimeError from control_retriever)
    if isinstance(exc, RuntimeError) and exc.__cause__:
        return _is_auth_error(exc.__cause__)

    return False


@click.command()
@click.option(
    "--input-file",
    default=None,
    type=click.Path(exists=False),
    help="Path to the resource type input file (JSON array or Config aggregator output).",
)
@click.option(
    "--output-format",
    default=None,
    type=click.Choice(["json", "markdown"], case_sensitive=False),
    help="Output report format.",
)
@click.option(
    "--output-file",
    default=None,
    type=click.Path(),
    help="Path to write the output report. Defaults to stdout.",
)
@click.option(
    "--severity-filter",
    default=None,
    callback=validate_severity_filter,
    help="Severity filter: single level as minimum (e.g., HIGH) or comma-separated list (e.g., HIGH,CRITICAL).",
)
@click.option(
    "--behavior-filter",
    default=None,
    help="Behavior filter: comma-separated list (e.g., PREVENTIVE or PREVENTIVE,PROACTIVE). Valid: PREVENTIVE, PROACTIVE, DETECTIVE.",
)
@click.option(
    "--framework",
    default=None,
    callback=validate_framework_filter,
    help=(
        "Framework filter: comma-separated Framework names "
        "(e.g., PCI-DSS-v4.0 or PCI-DSS-v4.0,NIST-SP-800-53-r5). "
        "When omitted, controls are not filtered by framework."
    ),
)
@click.option(
    "--region",
    default=None,
    help="AWS region override for API calls.",
)
@click.option(
    "--organizational-unit",
    default=None,
    help="OU ID or ARN for comparing against already-enabled controls.",
)
@click.option(
    "--no-interactive",
    is_flag=True,
    default=False,
    help="Disable interactive prompts (requires --input-file).",
)
def main(
    input_file: Optional[str],
    output_format: Optional[str],
    output_file: Optional[str],
    severity_filter: Optional[str],
    behavior_filter: Optional[str],
    framework: Optional[str],
    region: Optional[str],
    organizational_unit: Optional[str],
    no_interactive: bool,
) -> None:
    """Control Tower Controls Generator - map resource types to recommended controls."""
    # Interactive prompting when arguments are not provided
    if not no_interactive:
        if not input_file:
            input_file = click.prompt(
                "Path to resource type input file",
                type=str,
            )

        if output_format is None:
            output_format = click.prompt(
                "Output format",
                type=click.Choice(["json", "markdown"], case_sensitive=False),
                default="json",
            )

        if output_file is None:
            # Generate default output path
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ext = "md" if output_format and output_format.lower() == "markdown" else "json"
            default_output = os.path.join("output", f"report_{timestamp}.{ext}")
            output_file_input = click.prompt(
                f"Output file path",
                default=default_output,
            )
            output_file = output_file_input if output_file_input else default_output

        if severity_filter is None:
            sev_input = click.prompt(
                "Severity filter (e.g., HIGH or HIGH,CRITICAL; leave empty for all)",
                default="",
                show_default=False,
            )
            if sev_input:
                # Validate the interactive input
                parts = [p.strip().upper() for p in sev_input.split(",")]
                for part in parts:
                    if part not in VALID_SEVERITIES:
                        click.echo(
                            f"Warning: Invalid severity '{part}', ignoring filter.",
                            err=True,
                        )
                        sev_input = ""
                        break
                severity_filter = sev_input if sev_input else None

        if behavior_filter is None:
            beh_input = click.prompt(
                "Behavior filter (PREVENTIVE, PROACTIVE, DETECTIVE; leave empty for all)",
                default="",
                show_default=False,
            )
            if beh_input:
                parts = [p.strip().upper() for p in beh_input.split(",")]
                for part in parts:
                    if part not in VALID_BEHAVIORS:
                        click.echo(
                            f"Warning: Invalid behavior '{part}', ignoring filter.",
                            err=True,
                        )
                        beh_input = ""
                        break
                behavior_filter = beh_input if beh_input else None

        if framework is None:
            framework_input = click.prompt(
                "Framework filter (comma-separated, e.g. PCI-DSS-v4.0; leave empty for all)",
                default="",
                show_default=False,
            )
            framework = framework_input if framework_input else None

        if region is None:
            region_input = click.prompt(
                "AWS region (leave empty for default)",
                default="",
                show_default=False,
            )
            region = region_input if region_input else None

        if organizational_unit is None:
            ou_input = click.prompt(
                "Organizational Unit ID or ARN for comparison (leave empty to skip)",
                default="",
                show_default=False,
            )
            organizational_unit = ou_input if ou_input else None
    else:
        # Non-interactive mode requires input-file
        if not input_file:
            click.echo("Error: --input-file is required in non-interactive mode.", err=True)
            sys.exit(1)

    # Apply defaults for non-prompted values
    if output_format is None:
        output_format = "json"
    try:
        # Step 1: Parse input file
        parsed_input = parse_input_file(input_file)

        # Step 2: Retrieve control catalog
        controls = retrieve_control_catalog(region=region)

        # Step 3: Map resource types to controls
        mapped_controls = map_resource_types_to_controls(
            parsed_input.resource_types, controls
        )

        # Step 3b: Filter by framework (opt-in). Runs before the severity and
        # behavior filters so filter composition is AND
        # and the framework-specific "zero matches" condition can be detected
        # distinctly.
        framework_config = parse_framework_filter(framework)
        framework_active = framework_config.frameworks is not None
        framework_zeroed = False
        if framework_active:
            # Only reached when a framework is requested, so the mappings API is
            # never called on the opt-out path.
            mapping_index = retrieve_control_mappings(region=region)

            # Warn on each unrecognized framework and continue.
            for name in find_unrecognized_frameworks(framework_config, mapping_index):
                click.echo(
                    f"Warning: Framework '{name}' matched no control mappings; ignoring.",
                    err=True,
                )

            mapped_controls = filter_by_framework(
                mapped_controls, mapping_index, framework_config
            )
            framework_zeroed = len(mapped_controls) == 0

        # Step 4: Filter by severity
        filter_config = parse_severity_filter(severity_filter)
        mapped_controls = filter_by_severity(mapped_controls, filter_config)

        # Step 4b: Filter by behavior
        if behavior_filter:
            allowed_behaviors = {b.strip().upper() for b in behavior_filter.split(",")}
            mapped_controls = [
                mc for mc in mapped_controls
                if mc.control.behavior.upper() in allowed_behaviors
            ]

        # Step 5: Retrieve enabled controls if OU specified
        enabled_controls = []
        if organizational_unit:
            enabled_controls = retrieve_enabled_controls(
                organizational_unit, region=region
            )

        # Step 6: Generate report
        report_content = generate_report(
            mapped_controls=mapped_controls,
            enabled_controls=enabled_controls,
            account_mapping=parsed_input.account_mapping,
            output_format=output_format,
            include_framework_attribution=framework_active,
            no_match_message=(
                "No controls matched the requested frameworks"
                if framework_zeroed
                else "No matching controls found"
            ),
        )

        # Step 7: Write output
        write_output(report_content, output_file)

    except InputParserError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as e:
        if _is_auth_error(e):
            print(f"Authentication error: {e}", file=sys.stderr)
            sys.exit(3)
        print(f"API error: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        if _is_auth_error(e):
            print(f"Authentication error: {e}", file=sys.stderr)
            sys.exit(3)
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
