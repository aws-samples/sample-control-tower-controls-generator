# Control Tower Controls Generator

![AWS](https://img.shields.io/badge/AWS-Control%20Tower-E7157B)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Interface](https://img.shields.io/badge/Interface-CLI-orange)
![License](https://img.shields.io/badge/License-MIT--0-green)
![Version](https://img.shields.io/badge/Version-1.0.0-informational)

A CLI tool that maps AWS resource types deployed in your organization to recommended AWS Control Tower controls. It retrieves the full control catalog via the [ListControls](https://docs.aws.amazon.com/controlcatalog/latest/APIReference/API_ListControls.html) API, matches controls to your resources using the `GovernedResources` field, and produces a report of what you should enable. It can also optionally filter the recommended controls by compliance framework (for example, PCI-DSS-v4.0), determined via the [ListControlMappings](https://docs.aws.amazon.com/controlcatalog/latest/APIReference/API_ListControlMappings.html) API.

## What It Does

1. You provide a list of resource types (from an AWS Config aggregator query export)
2. The tool fetches the full AWS Control Tower control catalog
3. It maps your resource types to applicable controls (exact match on `GovernedResources`)
4. Filters by compliance framework if requested (via ListControlMappings)
5. It filters by severity if requested
6. Optionally compares against already-enabled controls on an OU to identify gaps
7. Produces a JSON or Markdown report

## Prerequisites

- [Python 3.11+](https://www.python.org/downloads/)
- [AWS credentials configured](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html) (environment variables, `~/.aws/credentials`, or instance profile)
- Permission to call `controlcatalog:ListControls`
- (Optional) Permission to call `controlcatalog:ListControlMappings` if using the framework filter (`--framework`). This is only needed when the framework filter is used; without `--framework` the tool never calls that API and needs no such permission.
- (Optional) Permission to call `controltower:ListEnabledControls` if using OU comparison
- (Optional) Permission to call `organizations:DescribeOrganizationalUnit` if using OU comparison (`--organizational-unit`) with the OU-ID form. `ListEnabledControls` takes an OU ARN, so a bare `ou-xxxx-xxxxxxxx` is resolved to its ARN through this call; supplying the OU ARN directly skips it. This API is callable only from the organization's management account or from a delegated administrator account.

## Installation

Clone the repository, then install it into a virtual environment:

```bash
git clone https://github.com/aws-samples/sample-control-tower-controls-generator.git
cd sample-control-tower-controls-generator
python -m venv .venv
source .venv/Scripts/activate   # Windows
# source .venv/bin/activate     # macOS/Linux
pip install -e .
```

## Quick Start

1. Install the tool (see [Installation](#installation)).
2. Produce an input file. In AWS Config, run this query against your organization aggregator and export the results as CSV (full details in [Getting Your Resource Type List](#getting-your-resource-type-list)):

   ```sql
   SELECT resourceType, COUNT(*) WHERE resourceType LIKE 'AWS::%' GROUP BY resourceType
   ```

3. Generate a Markdown report:

   ```bash
   python -m control_tower_controls_generator \
     --input-file input/resources.csv \
     --output-format markdown \
     --no-interactive
   ```

   Or run `python -m control_tower_controls_generator` with no arguments to be prompted for each option.

## Getting Your Resource Type List

Run these queries in AWS Config (advanced query). See [Query Using the SQL Query Editor for AWS Config (Console)](https://docs.aws.amazon.com/config/latest/developerguide/query-using-sql-editor-console.html).

To span multiple accounts you query an organization **configuration aggregator**. In an AWS Control Tower environment this aggregator already exists; you just need to find it and select it as the query scope.

### Finding the Control Tower aggregator

1. **Sign in to the Audit account**, where Control Tower deploys the organization aggregator on landing zone 4.0. (On landing zone 3.x and earlier, the organization aggregator was in the management account instead.)
2. **Switch to your Control Tower home Region** (for example, `us-east-1`). The aggregator exists only in the home Region. If you open AWS Config in any other Region, the aggregator will not appear in the scope list.
3. In the AWS Config console, open **Advanced queries**, then under **Query scope** choose the aggregator named **`aws-controltower-ConfigAggregatorForOrganization`** rather than "This account and Region only".
4. Enter one of the queries below and run it.

Account-level filtering (the `accountId` examples below) only works against an aggregator; a single-account scope ("This account and Region only") has no `accountId` to filter on.

### All accounts in the organization

```sql
SELECT resourceType, COUNT(*) WHERE resourceType LIKE 'AWS::%' GROUP BY resourceType
```

### A specific account

Add an `accountId` filter:

```sql
SELECT resourceType, COUNT(*) WHERE resourceType LIKE 'AWS::%' AND accountId = '123456789012' GROUP BY resourceType
```

### A specific set of accounts

Use `IN` with a comma-separated list of account IDs:

```sql
SELECT resourceType, COUNT(*) WHERE resourceType LIKE 'AWS::%' AND accountId IN ('123456789012', '987654321098', '555555555555') GROUP BY resourceType
```

Export the results as CSV and pass the file to this tool.

### Keeping per-account attribution

The CSV exports above collapse counts per resource type and drop the account dimension. To carry account IDs through to the report (so each recommended control shows which accounts it applies to), select `accountId` alongside `resourceType` and export the aggregator JSON instead of CSV:

```sql
SELECT accountId, resourceType WHERE resourceType LIKE 'AWS::%'
```

The tool reads this aggregator JSON format directly (see [Config aggregator JSON output](#config-aggregator-json-output)) and adds per-account attribution to the report.

## Usage

### Interactive Mode (default)

Run without arguments and you'll be prompted for each option:

```bash
python -m control_tower_controls_generator
```

Example session:

```
Path to resource type input file: input/resources-20260321.csv
Output format (json, markdown) [json]: markdown
Output file path [output/report_20250528_150000.md]:
Severity filter (e.g., HIGH or HIGH,CRITICAL; leave empty for all): HIGH
Behavior filter (PREVENTIVE, PROACTIVE, DETECTIVE; leave empty for all): DETECTIVE
Framework filter (comma-separated, e.g. PCI-DSS-v4.0; leave empty for all): PCI-DSS-v4.0
AWS region (leave empty for default): us-east-1
Organizational Unit ID for comparison (leave empty to skip):
```

### Non-Interactive Mode

Pass all options via command line:

```bash
python -m control_tower_controls_generator \
  --input-file input/resources-20260321.csv \
  --output-format markdown \
  --output-file output/report.md \
  --severity-filter HIGH \
  --behavior-filter PROACTIVE \
  --framework PCI-DSS-v4.0 \
  --region us-east-1 \
  --no-interactive
```

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--input-file` | Path to resource type input file (JSON or CSV) | Prompted |
| `--output-format` | `json` or `markdown` | `json` |
| `--output-file` | File path for the report | Auto-generated in `output/` |
| `--severity-filter` | Minimum level (single value, inclusive upward) or exact list (comma-separated); see note below | All severities |
| `--behavior-filter` | Comma-separated list (`PREVENTIVE`, `PROACTIVE`, `DETECTIVE`) | All behaviors |
| `--framework` | Comma-separated compliance framework names (e.g., `PCI-DSS-v4.0` or `PCI-DSS-v4.0,NIST-SP-800-53-r5`); case-insensitive exact match | All frameworks (no filtering) |
| `--region` | AWS region for API calls | Default from credential chain |
| `--organizational-unit` | OU ID to compare against enabled controls | Skip comparison |
| `--no-interactive` | Disable prompts (requires `--input-file`) | False |

**Severity filter modes.** Severity ranks `LOW` < `MEDIUM` < `HIGH` < `CRITICAL`. A single value is treated as a **minimum** and keeps that level and everything above it, so `--severity-filter HIGH` returns both HIGH and CRITICAL controls. A comma-separated value is treated as an **exact list** and keeps only the levels you name, so `--severity-filter MEDIUM,CRITICAL` returns MEDIUM and CRITICAL but not HIGH.

## Input File Formats

### CSV (AWS Config export)

The standard export format from an AWS Config advanced query:

```csv
"resourceType","COUNT(*)"
"AWS::EC2::Instance",42
"AWS::S3::Bucket",12
"AWS::Lambda::Function",9
```

### Simple JSON array

```json
["AWS::EC2::Instance", "AWS::S3::Bucket", "AWS::Lambda::Function"]
```

### Config aggregator JSON output

```json
{
  "QueryInfo": {"SelectFields": [{"Name": "resourceType"}, {"Name": "accountId"}]},
  "Results": [
    "{\"resourceType\":\"AWS::EC2::Instance\",\"accountId\":\"123456789012\"}",
    "{\"resourceType\":\"AWS::S3::Bucket\",\"accountId\":\"987654321098\"}"
  ]
}
```

When account IDs are present, the report includes per-account attribution.

## Framework Filtering

Framework filtering narrows the recommended controls down to those mapped to one or more compliance frameworks (for example, `PCI-DSS-v4.0`, `NIST-SP-800-53-r5`, or `CIS-v8.0`).

The feature is opt-in. Without `--framework`, behavior is unchanged and no `ListControlMappings` call is made.

- **Multiple frameworks are any-of (OR).** `--framework PCI-DSS-v4.0,NIST-SP-800-53-r5` keeps controls mapped to *either* framework.
- **Matching is case-insensitive exact** on the framework name (not a substring match).
- **Filters compose with AND.** When combined with `--severity-filter` and `--behavior-filter`, a control must satisfy every active filter to appear in the report.
- **Unrecognized framework names produce a warning on stderr and processing continues.** If no controls match the requested frameworks, the report is still produced with zero controls and a `No controls matched the requested frameworks` message.
- **When active, each control in the report is annotated** with the framework name(s) and item(s) it maps to (see [Output](#output)).

The set of supported frameworks is published at [Framework controls supported by AWS Control Tower](https://docs.aws.amazon.com/controltower/latest/controlreference/frameworks-supported.html).

```bash
python -m control_tower_controls_generator --input-file input/resources.csv --framework PCI-DSS-v4.0 --no-interactive
```

## Output

### JSON

```json
{
  "summary": {
    "totalRecommended": 15,
    "alreadyEnabled": 5,
    "gaps": 10
  },
  "controls": [
    {
      "controlName": "ECS containers should run as non-privileged",
      "controlArn": "arn:aws:controlcatalog:::control/...",
      "behavior": "DETECTIVE",
      "severity": "HIGH",
      "matchedResourceTypes": ["AWS::ECS::TaskDefinition"],
      "accounts": ["123456789012"],
      "enablementStatus": "not enabled",
      "frameworks": [{ "name": "PCI-DSS-v4.0", "item": "7.2.2" }]
    }
  ]
}
```

When a framework filter is active, each control gains a `frameworks` array of `{ "name": ..., "item": ... }` objects. The key is omitted entirely when no framework filter is used.

### Markdown

A table with summary counts and per-control details including severity, behavior, matched resources, and enablement status. When a framework filter is active, a `Frameworks` column is added (each association rendered as `Name: Item`); it is omitted otherwise.

## Project Structure

```
sample-control-tower-controls-generator/
├── src/control_tower_controls_generator/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                      # CLI entry point (click)
│   ├── models.py                   # Data models (dataclasses)
│   ├── input_parser.py             # JSON/CSV input parsing
│   ├── control_retriever.py        # ListControls API
│   ├── control_mappings_retriever.py  # ListControlMappings API
│   ├── control_mapper.py           # Resource-to-control mapping
│   ├── severity_filter.py          # Severity filtering
│   ├── framework_filter.py         # Framework-based filtering
│   ├── enabled_controls_retriever.py  # OU enabled controls lookup
│   ├── report_generator.py         # JSON/Markdown report generation
│   └── output_writer.py            # File/stdout output
├── tests/
│   ├── unit/
│   ├── property/
│   └── integration/
├── input/                          # Put your resource-type input files here (contents gitignored)
├── output/                         # Generated reports (contents gitignored; dir kept via .gitkeep)
├── pyproject.toml
├── requirements.txt
└── requirements-dev.txt
```

## Running Tests

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
