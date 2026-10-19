"""JSON output invariant guard for the account-id injection remediation.

The change that added Markdown-cell escaping
(``_escape_markdown_cell`` + escaping in ``_render_markdown``) but deliberately
left the JSON render path (``_render_json`` / ``_control_to_json``) untouched.

Because ``report_generator.py`` as a whole *did* change, a file-content hash
would be the wrong tool here. Instead this is a **behavioral output-identity
guard**: it proves the JSON sink is unaffected by asserting

1. Markdown escaping does not leak into JSON. Fields carrying crafted
   structural/markup characters (``|``, ``<``, ``>``, ``&``, newline) render as
   the raw characters ``json.dumps`` emits -- never as Markdown artifacts
   (``\\|``, ``&lt;``, ``&gt;``) -- and ``json.loads`` round-trips back to the
   exact input strings.
2. Byte-for-byte stability against pinned golden strings, for both the
   no-framework-attribution case and the ``include_framework_attribution=True``
   case (the ``frameworks`` key).
3. The output equals ``json.dumps`` of the expected dict with ``indent=2`` and
   the documented camelCase keys.

These are plain example-based pytest tests (no Hypothesis), consistent with
``tests/unit/test_report_generator_frameworks.py``.

"""

import json

from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    EnabledControl,
    FrameworkAssociation,
    MappedControl,
)
from control_tower_controls_generator.report_generator import generate_report


# --- fixtures / builders -----------------------------------------------------

# A clean, "pre-remediation" representative control: no special characters, so
# escaping is the identity and the JSON must equal today's output exactly.
CLEAN_ARN = "arn:aws:controlcatalog:::control/abc123"
CLEAN_RESOURCE_TYPE = "AWS::EC2::Instance"
CLEAN_ACCOUNT_ID = "123456789012"

# Externally-sourced values carrying every character the Markdown sink escapes:
# pipe (column forgery), '<'/'>'/'&' (markup), and a newline (row forgery).
RAW_CONTROL_NAME = (
    "Ctrl <img src=x onerror=alert(document.domain)> & Co | X\nSECOND LINE"
)
RAW_CONTROL_ARN = "arn:aws:controlcatalog:::control/<a>&b|c"
RAW_RESOURCE_TYPE = "AWS::S3::Bucket<&>|x"
RAW_ACCOUNT_ID = "12345|67890"


def _representative_mapped_control(
    associations: list[FrameworkAssociation] | None = None,
) -> MappedControl:
    """A clean MappedControl whose JSON is pinned byte-for-byte below."""
    return MappedControl(
        control=Control(
            arn=CLEAN_ARN,
            name="Example Control",
            description="An example control.",
            behavior="PREVENTIVE",
            severity="HIGH",
            implementation=ControlImplementation(type="SERVICE_CONTROL_POLICY"),
            governed_resources=[CLEAN_RESOURCE_TYPE],
        ),
        matched_resource_types=[CLEAN_RESOURCE_TYPE],
        framework_associations=list(associations) if associations else [],
    )


def _injected_mapped_control() -> MappedControl:
    """A MappedControl whose fields carry structural/markup characters."""
    return MappedControl(
        control=Control(
            arn=RAW_CONTROL_ARN,
            name=RAW_CONTROL_NAME,
            description="Injected control for the JSON invariant test.",
            behavior="PREVENTIVE",
            severity="HIGH",
            implementation=ControlImplementation(type="SERVICE_CONTROL_POLICY"),
            governed_resources=[],
        ),
        matched_resource_types=[RAW_RESOURCE_TYPE],
        framework_associations=[],
    )


# Golden JSON pins. Built with "\n".join(...) so the expected bytes use LF
# regardless of this file's checkout line endings (json.dumps always emits LF),
# and so every line is pinned explicitly.
EXPECTED_JSON_NO_FRAMEWORKS = "\n".join(
    [
        "{",
        '  "summary": {',
        '    "totalRecommended": 1,',
        '    "alreadyEnabled": 0,',
        '    "gaps": 1',
        "  },",
        '  "controls": [',
        "    {",
        '      "controlName": "Example Control",',
        '      "controlArn": "arn:aws:controlcatalog:::control/abc123",',
        '      "behavior": "PREVENTIVE",',
        '      "severity": "HIGH",',
        '      "matchedResourceTypes": [',
        '        "AWS::EC2::Instance"',
        "      ],",
        '      "accounts": [',
        '        "123456789012"',
        "      ],",
        '      "enablementStatus": "not enabled"',
        "    }",
        "  ],",
        '  "message": null',
        "}",
    ]
)

EXPECTED_JSON_WITH_FRAMEWORKS = "\n".join(
    [
        "{",
        '  "summary": {',
        '    "totalRecommended": 1,',
        '    "alreadyEnabled": 0,',
        '    "gaps": 1',
        "  },",
        '  "controls": [',
        "    {",
        '      "controlName": "Example Control",',
        '      "controlArn": "arn:aws:controlcatalog:::control/abc123",',
        '      "behavior": "PREVENTIVE",',
        '      "severity": "HIGH",',
        '      "matchedResourceTypes": [',
        '        "AWS::EC2::Instance"',
        "      ],",
        '      "accounts": [',
        '        "123456789012"',
        "      ],",
        '      "enablementStatus": "not enabled",',
        '      "frameworks": [',
        "        {",
        '          "name": "PCI-DSS-v4.0",',
        '          "item": "7.2.2"',
        "        }",
        "      ]",
        "    }",
        "  ],",
        '  "message": null',
        "}",
    ]
)


# --- 1. Markdown escaping must not leak into JSON ----------------------------

class TestMarkdownEscapingDoesNotLeakIntoJson:
    """The JSON sink emits raw characters; Markdown escaping stays in Markdown."""

    def test_special_characters_render_raw_in_json(self):
        output = generate_report(
            [_injected_mapped_control()],
            enabled_controls=[],
            account_mapping={RAW_RESOURCE_TYPE: [RAW_ACCOUNT_ID]},
            output_format="json",
        )

        # json.dumps leaves these ASCII characters untouched, so they appear raw.
        assert "|" in output
        assert "<" in output
        assert ">" in output
        assert "&" in output
        # The account id's pipe survives verbatim (no column-forgery escaping).
        assert RAW_ACCOUNT_ID in output

        # None of the Markdown-cell escaping artifacts may appear in the JSON.
        assert "\\|" not in output  # no backslash-escaped pipe
        assert "&lt;" not in output
        assert "&gt;" not in output
        assert "&amp;" not in output

    def test_json_round_trips_to_original_raw_strings(self):
        output = generate_report(
            [_injected_mapped_control()],
            enabled_controls=[],
            account_mapping={RAW_RESOURCE_TYPE: [RAW_ACCOUNT_ID]},
            output_format="json",
        )

        control = json.loads(output)["controls"][0]
        assert control["controlName"] == RAW_CONTROL_NAME
        assert control["controlArn"] == RAW_CONTROL_ARN
        assert control["matchedResourceTypes"] == [RAW_RESOURCE_TYPE]
        assert control["accounts"] == [RAW_ACCOUNT_ID]

    def test_markdown_escapes_the_same_data_that_json_leaves_raw(self):
        """Same inputs, two sinks: Markdown escapes, JSON does not.

        This pins the sink boundary directly -- ``_escape_markdown_cell`` runs
        only on the Markdown path, so its artifacts never reach JSON.
        """
        mapped = _injected_mapped_control()
        account_mapping = {RAW_RESOURCE_TYPE: [RAW_ACCOUNT_ID]}

        markdown = generate_report(
            [mapped],
            enabled_controls=[],
            account_mapping=account_mapping,
            output_format="markdown",
        )
        js = generate_report(
            [mapped],
            enabled_controls=[],
            account_mapping=account_mapping,
            output_format="json",
        )

        # Markdown path escapes markup and pipes.
        assert "&lt;" in markdown
        assert "&gt;" in markdown
        assert "\\|" in markdown
        # JSON path leaves them raw.
        assert "&lt;" not in js
        assert "&gt;" not in js
        assert "\\|" not in js


# --- 2 & 3. Byte-for-byte stability against pinned goldens -------------------

class TestJsonByteForByteStability:
    """The JSON render path is unchanged: output equals pinned golden strings."""

    def test_no_framework_attribution_matches_pinned_golden(self):
        output = generate_report(
            [_representative_mapped_control()],
            enabled_controls=[],
            account_mapping={CLEAN_RESOURCE_TYPE: [CLEAN_ACCOUNT_ID]},
            output_format="json",
        )

        assert output == EXPECTED_JSON_NO_FRAMEWORKS

    def test_with_framework_attribution_matches_pinned_golden(self):
        output = generate_report(
            [
                _representative_mapped_control(
                    associations=[
                        FrameworkAssociation(name="PCI-DSS-v4.0", item="7.2.2")
                    ]
                )
            ],
            enabled_controls=[],
            account_mapping={CLEAN_RESOURCE_TYPE: [CLEAN_ACCOUNT_ID]},
            output_format="json",
            include_framework_attribution=True,
        )

        assert output == EXPECTED_JSON_WITH_FRAMEWORKS

    def test_no_framework_equals_expected_dict_dumps(self):
        """Documents the exact camelCase structure emitted with indent=2."""
        expected_dict = {
            "summary": {"totalRecommended": 1, "alreadyEnabled": 0, "gaps": 1},
            "controls": [
                {
                    "controlName": "Example Control",
                    "controlArn": CLEAN_ARN,
                    "behavior": "PREVENTIVE",
                    "severity": "HIGH",
                    "matchedResourceTypes": [CLEAN_RESOURCE_TYPE],
                    "accounts": [CLEAN_ACCOUNT_ID],
                    "enablementStatus": "not enabled",
                }
            ],
            "message": None,
        }

        output = generate_report(
            [_representative_mapped_control()],
            enabled_controls=[],
            account_mapping={CLEAN_RESOURCE_TYPE: [CLEAN_ACCOUNT_ID]},
            output_format="json",
        )

        assert output == json.dumps(expected_dict, indent=2)

    def test_with_framework_equals_expected_dict_dumps(self):
        """The frameworks key uses camelCase name/item under indent=2."""
        expected_dict = {
            "summary": {"totalRecommended": 1, "alreadyEnabled": 0, "gaps": 1},
            "controls": [
                {
                    "controlName": "Example Control",
                    "controlArn": CLEAN_ARN,
                    "behavior": "PREVENTIVE",
                    "severity": "HIGH",
                    "matchedResourceTypes": [CLEAN_RESOURCE_TYPE],
                    "accounts": [CLEAN_ACCOUNT_ID],
                    "enablementStatus": "not enabled",
                    "frameworks": [{"name": "PCI-DSS-v4.0", "item": "7.2.2"}],
                }
            ],
            "message": None,
        }

        output = generate_report(
            [
                _representative_mapped_control(
                    associations=[
                        FrameworkAssociation(name="PCI-DSS-v4.0", item="7.2.2")
                    ]
                )
            ],
            enabled_controls=[],
            account_mapping={CLEAN_RESOURCE_TYPE: [CLEAN_ACCOUNT_ID]},
            output_format="json",
            include_framework_attribution=True,
        )

        assert output == json.dumps(expected_dict, indent=2)

    def test_enabled_control_status_reflected_in_json(self):
        """Sanity: enablement status flows through the untouched JSON path."""
        output = generate_report(
            [_representative_mapped_control()],
            enabled_controls=[EnabledControl(control_arn=CLEAN_ARN)],
            account_mapping={CLEAN_RESOURCE_TYPE: [CLEAN_ACCOUNT_ID]},
            output_format="json",
        )

        data = json.loads(output)
        assert data["controls"][0]["enablementStatus"] == "already enabled"
        assert data["summary"]["alreadyEnabled"] == 1
        assert data["summary"]["gaps"] == 0
