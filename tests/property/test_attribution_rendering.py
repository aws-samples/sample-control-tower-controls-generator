"""Property-based test for framework attribution rendering.

Validates that framework attribution is rendered faithfully in both the JSON
and Markdown reports: the (name, item) pairs presented for each control equal
exactly the pairs the control carries in its ``framework_associations`` — with
no missing pairs and no extra pairs.
"""

import json
import string

from hypothesis import given, settings, strategies as st

from control_tower_controls_generator.report_generator import generate_report
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    MappedControl,
    FrameworkAssociation,
)


# Restrict generated names/items to alphanumerics. This keeps them free of the
# Markdown table delimiter ("|"), the "<br/>" association separator, and the
# ": " name/item separator used by the renderer, so the rendered output can be
# parsed back into (name, item) pairs unambiguously. The property under test is
# attribution fidelity, not character escaping.
_SAFE_TEXT = st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=10)

_association = st.builds(FrameworkAssociation, name=_SAFE_TEXT, item=_SAFE_TEXT)


@st.composite
def _mapped_controls(draw):
    """Build a non-empty list of MappedControls carrying framework associations.

    Each control is given a unique, index-based name and ARN so its row (in
    Markdown) and entry (in JSON) can be located unambiguously. Association
    lists may be empty to exercise the "no associations" case. At least one
    control is generated so the report is not the empty/no-match report.
    """
    assoc_lists = draw(
        st.lists(st.lists(_association, min_size=0, max_size=5), min_size=1, max_size=6)
    )
    controls: list[MappedControl] = []
    for i, assocs in enumerate(assoc_lists):
        control = Control(
            arn=f"arn:aws:controlcatalog:::control/ctrl-{i}",
            name=f"Control-{i}",
            description="description",
            behavior="Detective",
            severity="HIGH",
            implementation=ControlImplementation(type="AWS::Config::Rule"),
            governed_resources=["AWS::EC2::Instance"],
        )
        controls.append(
            MappedControl(
                control=control,
                matched_resource_types=["AWS::EC2::Instance"],
                framework_associations=list(assocs),
            )
        )
    return controls


# Framework attribution reflects requested associations
@settings(max_examples=100)
@given(mapped_controls=_mapped_controls())
def test_framework_attribution_rendering(mapped_controls):
    # JSON report with framework attribution enabled.
    json_output = generate_report(
        mapped_controls,
        enabled_controls=[],
        account_mapping=None,
        output_format="json",
        include_framework_attribution=True,
    )
    parsed = json.loads(json_output)
    json_by_name = {entry["controlName"]: entry for entry in parsed["controls"]}

    # Markdown report with framework attribution enabled.
    md_output = generate_report(
        mapped_controls,
        enabled_controls=[],
        account_mapping=None,
        output_format="markdown",
        include_framework_attribution=True,
    )
    md_lines = md_output.splitlines()

    for mc in mapped_controls:
        expected_pairs = sorted(
            (assoc.name, assoc.item) for assoc in mc.framework_associations
        )

        # --- JSON: frameworks is a structured list of {name, item} objects ---
        assert mc.control.name in json_by_name
        entry = json_by_name[mc.control.name]
        assert "frameworks" in entry
        json_pairs = sorted(
            (fw["name"], fw["item"]) for fw in entry["frameworks"]
        )
        assert json_pairs == expected_pairs

        # --- Markdown: each name and item present as readable "Name: Item" ---
        prefix = f"| {mc.control.name} |"
        rows = [line for line in md_lines if line.startswith(prefix)]
        assert len(rows) == 1

        # The row ends with a trailing "|", so the frameworks cell is the
        # second-to-last field after splitting on "|".
        frameworks_cell = rows[0].split("|")[-2].strip()
        if frameworks_cell:
            md_pairs = sorted(
                tuple(part.split(": ", 1))
                for part in frameworks_cell.split("<br/>")
            )
        else:
            md_pairs = []
        assert md_pairs == expected_pairs
