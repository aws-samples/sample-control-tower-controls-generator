"""Preservation baseline: what a *successful* enabled-controls retrieval owes
everything downstream of it.

Successful Retrieval Keeps Its Downstream Contract.

This file is recorded against the **UNFIXED** code, before any edit lands in
``enabled_controls_retriever.py``, so the post-fix assertions
compare against *measured* behavior rather than assumed behavior. Every test
here is expected to PASS today; each passing test is a baseline to preserve, not
a defect to close.

Four contracts are recorded:

1. **Labelling and summary**. ``report_generator`` labels a
   control "already enabled" exactly when its ARN is in the enabled set and
   "not enabled" otherwise, and Total Recommended, Already Enabled and Gaps are
   derived from those labels. The enabled set is fed **directly** to
   ``generate_report`` rather than routed through ``retrieve_enabled_controls``:
   the retriever cannot currently return anything, so going through it would
   record nothing.
2. **Multi-page ordering**. Aggregation is page-then-item
   ordered. See the shape-asymmetry note below -- it is the crux of this file.
3. **Region and client config**. ``region_name`` is
   passed only when a region is supplied, and the client carries adaptive
   retries capped at 3 attempts with 30-second connect and read timeouts.
4. **The comparison's own shape**. ``EnabledControl`` keeps a
   single ``control_arn`` field, and ``report_generator`` compares it by set
   membership against ``Control.arn``.

Response-shape asymmetry -- READ BEFORE "FIXING" THE PASCALCASE PAGES BELOW
--------------------------------------------------------------------------
The ordering tests feed the paginator **PascalCase** pages
(``EnabledControls`` / ``ControlIdentifier``). That is deliberate. PascalCase is
the *only* shape the unfixed code can read, so it is the only shape that can
observe an ordering baseline today. It is **not** the shape the real service
returns -- the service model is camelCase, and reading PascalCase is precisely
the latent defect this bugfix addresses.

The two shape constants are therefore isolated in ``RESPONSE_PAGE_KEY`` and
``RESPONSE_ITEM_KEY``, and the ordering contract itself is recorded separately
from them, as data, in ``ORDERING_CONTRACT_PAGES`` /
``ORDERING_CONTRACT_EXPECTED_ORDER``. **The shape changes; the ordering
contract does not.** A companion test re-asserts the same contract by flipping exactly
those two constants to ``"enabledControls"`` and ``"controlIdentifier"`` and
changing nothing else.
``test_ordering_contract_is_independent_of_the_response_key_shape`` states that
invariance executably, and holds under both shapes.

``moto`` does not support the ``controltower`` service and the client is
constructed *inside* ``retrieve_enabled_controls`` (via the module's ``boto3``
reference), so boto3 is mocked with ``unittest.mock.patch`` on that reference,
mirroring ``tests/unit/test_control_catalog_retriever.py``.
"""

import dataclasses
import json
from unittest.mock import MagicMock, patch

import pytest
from botocore.config import Config

from control_tower_controls_generator.enabled_controls_retriever import (
    retrieve_enabled_controls,
)
from control_tower_controls_generator.models import (
    Control,
    ControlImplementation,
    EnabledControl,
    MappedControl,
)
from control_tower_controls_generator.report_generator import generate_report


BOTO3_TARGET = "control_tower_controls_generator.enabled_controls_retriever.boto3"

OU_ID = "ou-tito-abcd1234"

ARN_A = "arn:aws:controlcatalog:::control/2xknmxmas18xrbvvexzq9k06g"
ARN_B = "arn:aws:controlcatalog:::control/e2saoisw5u8xe40acfetio41w"
ARN_C = "arn:aws:controlcatalog:::control/aaaabbbbccccddddeeeeffff00"
ARN_D = "arn:aws:controlcatalog:::control/9zzzz111122223333444455556"
ARN_E = "arn:aws:controlcatalog:::control/mmmm7777888899990000aaaabb"
ARN_F = "arn:aws:controlcatalog:::control/0000cccc1111dddd2222eeee33"


# --- the response shape the code under test reads TODAY -----------------------

# PascalCase, because that is what the UNFIXED retriever reads. See the
# "Response-shape asymmetry" note in the module docstring before changing these:
# they are the single edit point for the post-fix change, which flips them to
# "enabledControls" / "controlIdentifier". The ordering contract recorded below
# is deliberately independent of them.
RESPONSE_PAGE_KEY = "enabledControls"
RESPONSE_ITEM_KEY = "controlIdentifier"

# The camelCase shape the real service returns, kept here only so the
# shape-invariance of the ordering contract can be stated executably.
SERVICE_PAGE_KEY = "enabledControls"
SERVICE_ITEM_KEY = "controlIdentifier"


# --- the ordering contract, recorded as data, not as a shape -------------------

#: Pages of control ARNs, as an abstract spec: one tuple per response page, in
#: response order, each holding that page's items in item order. Includes an
#: empty page (contributes nothing) and a repeated ARN in the final page (the
#: aggregation appends, it does not de-duplicate).
ORDERING_CONTRACT_PAGES: tuple[tuple[str, ...], ...] = (
    (ARN_B, ARN_A),
    (),
    (ARN_F,),
    (ARN_D, ARN_C, ARN_E, ARN_A),
)

#: The order aggregation must produce: every page in response order, and within
#: each page every item in item order. This sequence is the contract. It is
#: written in terms of no response-key casing at all, which is what lets task
#: 8.10 re-assert it against camelCase pages unchanged.
ORDERING_CONTRACT_EXPECTED_ORDER: tuple[str, ...] = tuple(
    arn for page in ORDERING_CONTRACT_PAGES for arn in page
)


# --- helpers ------------------------------------------------------------------

def _pages_in_shape(
    spec: tuple[tuple[str, ...], ...], page_key: str, item_key: str
) -> list[dict]:
    """Render the abstract page spec into paginator pages using the given keys."""
    return [
        {page_key: [{item_key: arn} for arn in page]} for page in spec
    ]


def _read_pages(pages: list[dict], page_key: str, item_key: str) -> tuple[str, ...]:
    """Read pages back in page-then-item order using the given keys.

    A shape-agnostic reader used only to state that the ordering contract does
    not depend on which casing the pages are written in.
    """
    return tuple(item[item_key] for page in pages for item in page[page_key])


def _page(*control_arns: str) -> dict:
    """One paginator page carrying the given control ARNs, in the current shape."""
    return {RESPONSE_PAGE_KEY: [{RESPONSE_ITEM_KEY: arn} for arn in control_arns]}


def _setup_boto3_mock(mock_boto3: MagicMock, pages: list) -> MagicMock:
    """Wire a mocked boto3 so client.get_paginator(...).paginate() -> pages.

    ``boto3.client`` dispatches on the service name so that every constructed
    client stays observable through ``mock_boto3.client.call_args_list``, which
    is what lets the client-config contract be asserted for *all* clients rather
    than only the first.
    """
    paginator = MagicMock(name="paginator")
    paginator.paginate.return_value = pages

    controltower = MagicMock(name="controltower_client")
    controltower.get_paginator.return_value = paginator

    organizations = MagicMock(name="organizations_client")
    organizations.describe_organizational_unit.return_value = {
        "OrganizationalUnit": {
            "Id": OU_ID,
            "Arn": f"arn:aws:organizations::111122223333:ou/o-abc123/{OU_ID}",
            "Name": "Sandbox",
        }
    }

    def _client(*args, **kwargs):
        service = args[0] if args else kwargs.get("service_name")
        return organizations if service == "organizations" else controltower

    mock_boto3.client.side_effect = _client
    return controltower


def _control(arn: str, name: str, *, severity: str = "HIGH") -> Control:
    """Build a minimal Control for report generation."""
    return Control(
        arn=arn,
        name=name,
        description="An example control.",
        behavior="PREVENTIVE",
        severity=severity,
        implementation=ControlImplementation(type="SERVICE_CONTROL_POLICY"),
        governed_resources=["AWS::EC2::Instance"],
    )


def _mapped(arn: str, name: str) -> MappedControl:
    """Build a MappedControl matched to a single resource type."""
    return MappedControl(
        control=_control(arn, name),
        matched_resource_types=["AWS::EC2::Instance"],
    )


def _json_report(mapped: list[MappedControl], enabled: list[EnabledControl]) -> dict:
    """Generate the JSON report and parse it back."""
    return json.loads(
        generate_report(
            mapped_controls=mapped, enabled_controls=enabled, output_format="json"
        )
    )


def _status_by_name(report: dict) -> dict[str, str]:
    """Map control name -> enablement status from a parsed JSON report."""
    return {c["controlName"]: c["enablementStatus"] for c in report["controls"]}


# --- design test case 3: labelling and summary --------------------------------

class TestLabellingAndSummary:
    """"already enabled" iff the ARN is in the enabled set; the summary follows.

    The enabled set is fed straight to ``generate_report``, which is what makes
    this observable while the retriever is still broken.
    """

    def test_membership_decides_the_label(self):
        """A control whose ARN is in the enabled set is labelled "already
        enabled"; one whose ARN is absent is labelled "not enabled"."""
        report = _json_report(
            [_mapped(ARN_A, "Alpha"), _mapped(ARN_B, "Bravo")],
            [EnabledControl(control_arn=ARN_A)],
        )

        assert _status_by_name(report) == {
            "Alpha": "already enabled",
            "Bravo": "not enabled",
        }

    def test_summary_counts_are_derived_from_the_labels(self):
        """Total Recommended, Already Enabled and Gaps follow from the labels.

        Recorded as a derivation from the entries themselves, not as three
        hard-coded integers, so the relationship is what is pinned.
        """
        mapped = [
            _mapped(ARN_A, "Alpha"),
            _mapped(ARN_B, "Bravo"),
            _mapped(ARN_C, "Charlie"),
            _mapped(ARN_D, "Delta"),
        ]
        enabled = [EnabledControl(control_arn=ARN_B), EnabledControl(control_arn=ARN_D)]

        report = _json_report(mapped, enabled)
        entries = report["controls"]
        labelled_enabled = [
            e for e in entries if e["enablementStatus"] == "already enabled"
        ]

        assert report["summary"]["totalRecommended"] == len(entries) == 4
        assert report["summary"]["alreadyEnabled"] == len(labelled_enabled) == 2
        assert report["summary"]["gaps"] == len(entries) - len(labelled_enabled) == 2
        assert report["message"] is None

    def test_empty_enabled_set_labels_everything_not_enabled(self):
        """An empty enabled set gives Already Enabled 0 and Gaps == total.

        This is the *genuine* zero, distinct from the failure-shaped zero;
        nothing here asserts on that distinction.
        """
        mapped = [_mapped(ARN_A, "Alpha"), _mapped(ARN_B, "Bravo")]

        report = _json_report(mapped, [])

        assert set(_status_by_name(report).values()) == {"not enabled"}
        assert report["summary"] == {
            "totalRecommended": 2,
            "alreadyEnabled": 0,
            "gaps": 2,
        }

    def test_markdown_summary_and_status_column_mirror_the_json_report(self):
        """Markdown renders the same labels and the same three counts."""
        mapped = [_mapped(ARN_A, "Alpha"), _mapped(ARN_B, "Bravo")]
        enabled = [EnabledControl(control_arn=ARN_A)]

        markdown = generate_report(
            mapped_controls=mapped, enabled_controls=enabled, output_format="markdown"
        )

        assert "- **Total Recommended**: 2" in markdown
        assert "- **Already Enabled**: 1" in markdown
        assert "- **Gaps**: 1" in markdown

        rows = [line for line in markdown.splitlines() if line.startswith("| Alpha ")]
        assert len(rows) == 1
        assert rows[0].endswith("| already enabled |")
        bravo = [line for line in markdown.splitlines() if line.startswith("| Bravo ")]
        assert bravo[0].endswith("| not enabled |")


# --- the comparison's own shape ------------------------------------------------

class TestEnabledSetComparisonShape:
    """``EnabledControl.control_arn`` vs ``Control.arn``, by set membership.

    Today's labelling semantics are preserved, so they are recorded
    exactly as they behave. The design's "Deliberately Out of Scope" section
    documents that Control Catalog ``arn`` and Control Tower
    ``controlIdentifier`` are different ARN namespaces; that is a separate
    defect with its own follow-up spec and is not judged here.
    """

    def test_enabled_control_carries_exactly_one_field_named_control_arn(self):
        """``EnabledControl`` keeps its single ``control_arn`` field."""
        fields = dataclasses.fields(EnabledControl)

        assert tuple(f.name for f in fields) == ("control_arn",)
        assert EnabledControl(control_arn=ARN_A).control_arn == ARN_A

    def test_comparison_is_exact_string_membership(self):
        """Only an exact ``Control.arn`` == ``EnabledControl.control_arn`` match
        counts. Near misses -- a prefix, a superstring, or a different case --
        do not, and neither does an ARN for the same control in another
        namespace."""
        near_misses = [
            ARN_A[:-1],                                              # prefix
            ARN_A + "x",                                             # superstring
            ARN_A.upper(),                                           # case variant
            "arn:aws:controltower:us-west-2::control/AWS-GR_TEST",   # other namespace
        ]

        report = _json_report(
            [_mapped(ARN_A, "Alpha")],
            [EnabledControl(control_arn=arn) for arn in near_misses],
        )

        assert _status_by_name(report) == {"Alpha": "not enabled"}
        assert report["summary"]["alreadyEnabled"] == 0

    def test_set_semantics_absorb_duplicates_and_unmatched_entries(self):
        """Already Enabled counts *labelled entries*, so a repeated enabled ARN
        cannot inflate it and an enabled ARN absent from the catalog cannot
        appear in the report at all."""
        report = _json_report(
            [_mapped(ARN_A, "Alpha"), _mapped(ARN_B, "Bravo")],
            [
                EnabledControl(control_arn=ARN_A),
                EnabledControl(control_arn=ARN_A),
                EnabledControl(control_arn=ARN_F),  # enabled, not in the catalog
            ],
        )

        assert report["summary"] == {
            "totalRecommended": 2,
            "alreadyEnabled": 1,
            "gaps": 1,
        }
        assert [c["controlArn"] for c in report["controls"]] == [ARN_A, ARN_B]

    def test_label_ignores_the_control_name(self):
        """The comparison reads ``Control.arn``, not any other Control field."""
        report = _json_report(
            [_mapped(ARN_B, ARN_A)],  # name *is* the enabled ARN, arn is not
            [EnabledControl(control_arn=ARN_A)],
        )

        assert report["controls"][0]["enablementStatus"] == "not enabled"


# --- design test case 4: multi-page ordering -----------------------------------

class TestMultiPageOrderingContract:
    """Aggregation is page-then-item ordered.

    Driven with PascalCase pages because that is the only shape the unfixed code
    reads. The contract asserted is ``ORDERING_CONTRACT_EXPECTED_ORDER``, which
    carries no key casing, so a companion test re-asserts it verbatim against camelCase
    pages. See the module docstring.
    """

    def test_ordering_contract_is_independent_of_the_response_key_shape(self):
        """The recorded order is the same whether the pages are written in the
        PascalCase shape the unfixed code reads or the camelCase shape the
        service actually returns.

        This is the statement that keeps the two concerns apart: the response
        *shape* is what the fix changes, the aggregation *order* is what it
        preserves. No code under test is involved -- this pins the contract
        itself, and it passes before and after the fix.
        """
        pascal = _pages_in_shape(
            ORDERING_CONTRACT_PAGES, "EnabledControls", "ControlIdentifier"
        )
        camel = _pages_in_shape(
            ORDERING_CONTRACT_PAGES, SERVICE_PAGE_KEY, SERVICE_ITEM_KEY
        )

        assert _read_pages(pascal, "EnabledControls", "ControlIdentifier") == (
            ORDERING_CONTRACT_EXPECTED_ORDER
        )
        assert _read_pages(camel, SERVICE_PAGE_KEY, SERVICE_ITEM_KEY) == (
            ORDERING_CONTRACT_EXPECTED_ORDER
        )

    def test_expected_order_is_positional_not_incidental(self):
        """The contract sequence is not in sorted or reverse-sorted order, so an
        implementation that sorted or reversed the pages could not satisfy it by
        accident."""
        order = list(ORDERING_CONTRACT_EXPECTED_ORDER)

        assert order != sorted(order)
        assert order != sorted(order, reverse=True)

    def test_multi_page_aggregation_is_page_then_item_ordered(self):
        """Every page contributes, in response order, and within each page every
        item contributes in item order."""
        pages = _pages_in_shape(
            ORDERING_CONTRACT_PAGES, RESPONSE_PAGE_KEY, RESPONSE_ITEM_KEY
        )

        with patch(BOTO3_TARGET) as mock_boto3:
            controltower = _setup_boto3_mock(mock_boto3, pages)
            result = retrieve_enabled_controls(OU_ID)

        controltower.get_paginator.assert_called_once_with("list_enabled_controls")
        assert all(isinstance(ec, EnabledControl) for ec in result)
        assert tuple(ec.control_arn for ec in result) == (
            ORDERING_CONTRACT_EXPECTED_ORDER
        )

    def test_aggregation_appends_rather_than_de_duplicates(self):
        """A control ARN repeated across pages is returned once per occurrence.

        De-duplication happens downstream, in ``report_generator``'s set of
        enabled ARNs, not in the retriever.
        """
        pages = _pages_in_shape(
            ORDERING_CONTRACT_PAGES, RESPONSE_PAGE_KEY, RESPONSE_ITEM_KEY
        )

        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, pages)
            result = retrieve_enabled_controls(OU_ID)

        arns = [ec.control_arn for ec in result]
        assert len(arns) == len(ORDERING_CONTRACT_EXPECTED_ORDER)
        assert arns.count(ARN_A) == 2


# --- design test case 5: region and client config -----------------------------

def _assert_client_config_contract(client_calls) -> None:
    """Every client constructed carries the retry/timeout Config contract.

    Asserted on the ``Config`` object's resolved attributes rather than on
    object identity, so the contract is about the *values* botocore will use.
    Written over all ``boto3.client`` calls so that the post-fix
    Organizations client is covered by the same assertion.
    """
    assert client_calls, "expected at least one boto3.client call"

    for args, kwargs in client_calls:
        config = kwargs["config"]
        assert isinstance(config, Config)
        assert config.retries == {"max_attempts": 3, "mode": "adaptive"}
        assert config.connect_timeout == 30
        assert config.read_timeout == 30


class TestRegionAndClientConfig:
    """Client construction: region pass-through and the retry/timeout Config."""

    def test_control_tower_client_is_built_with_adaptive_retries_and_timeouts(self):
        """Adaptive retries capped at 3 attempts, 30-second connect and read
        timeouts."""
        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [_page(ARN_A)])
            retrieve_enabled_controls(OU_ID, region="us-east-1")

        services = [
            args[0] for args, _ in mock_boto3.client.call_args_list if args
        ]
        assert "controltower" in services

        _assert_client_config_contract(mock_boto3.client.call_args_list)

    def test_region_name_passed_when_region_supplied(self):
        """A supplied region reaches the client."""
        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [_page(ARN_A)])
            retrieve_enabled_controls(OU_ID, region="us-west-2")

        for _, kwargs in mock_boto3.client.call_args_list:
            assert kwargs.get("region_name") == "us-west-2"

    @pytest.mark.parametrize("region", [None, ""], ids=["none", "empty"])
    def test_region_name_omitted_when_no_region_supplied(self, region):
        """With no region, ``region_name`` is not passed at all, so default AWS
        region and credential resolution applies."""
        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [_page(ARN_A)])
            retrieve_enabled_controls(OU_ID, region=region)

        for _, kwargs in mock_boto3.client.call_args_list:
            assert "region_name" not in kwargs

    def test_region_defaults_to_none_when_not_passed_at_all(self):
        """``region`` is optional, and omitting it behaves as passing None."""
        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [_page(ARN_A)])
            retrieve_enabled_controls(OU_ID)

        for _, kwargs in mock_boto3.client.call_args_list:
            assert "region_name" not in kwargs
