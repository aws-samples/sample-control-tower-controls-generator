"""Untouched-modules guard, re-baselined after the caching feature was removed.

This guard has two jobs:

1. **Scope fence (unchanged, still valid).** The ``controlcatalog`` service
   model genuinely defines ``Controls``, ``ControlMappings``, ``MappingType``,
   and ``ControlArn`` in PascalCase, so ``control_retriever.py`` and
   ``control_mappings_retriever.py`` read the *correct* keys. The camelCase
   spelling belongs to ``controltower``'s ``ListEnabledControls`` alone and must
   not bleed across the service boundary. This is grounded against the shipped
   botocore model (no credentials, no network) and then asserted behaviorally:
   PascalCase pages are collected, camelCase pages are not. Removing caching did
   not change which API keys the retrievers read, so these behavioral assertions
   still hold unchanged.

2. **Edit detection (re-baselined here).** Content hashes of the guarded files
   are pinned below so an *unintended* future edit is detected rather than
   assumed absent.

Removing the control-catalog and framework-mappings caching feature deliberately
changed all four pinned files, so every recorded hash was re-recorded against
the post-removal state:

* ``control_retriever.py`` and ``control_mappings_retriever.py`` no longer read
  from or write to an on-disk cache; each fetches straight from its
  ListControls / ListControlMappings paginator; and
* ``tests/unit/test_control_catalog_retriever.py`` and
  ``tests/unit/test_control_mappings_retriever.py`` were updated to drop their
  cache references.

Hashes are the hard assertion, computed over newline-normalized bytes so a CRLF
checkout does not register as an edit. They need no git, so this guard re-runs
identically in any checkout state.
"""

import hashlib
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import botocore.session
import pytest

from control_tower_controls_generator.control_mappings_retriever import (
    _index_mappings,
)
from control_tower_controls_generator.control_retriever import (
    retrieve_control_catalog,
)
from control_tower_controls_generator.models import FrameworkAssociation


REPO_ROOT = Path(__file__).resolve().parents[2]

# Re-baselined after the caching feature was removed from the two retrievers.
# Those removal edits live in the working tree and are not committed, so no
# single commit SHA captures this baseline: the hashes were recorded from the
# working tree on top of HEAD 8bcd32adf402f07ef7d108ea4835d3fba44e61bc, which
# does not itself contain the removal.
BASELINE_COMMIT = (
    "re-baselined from the uncommitted working tree after caching was removed; "
    "recorded on top of HEAD 8bcd32adf402f07ef7d108ea4835d3fba44e61bc, which "
    "does not itself contain the removal edits"
)

# Both modules had their caching removed; the hashes below pin that post-removal
# state. Hashes are over newline-normalized bytes so a CRLF checkout does not
# register as an edit. There is no git cross-check, so the content hashes are the
# sole drift guard and this runs identically in any checkout state.
GUARDED_SOURCE_MODULES: dict[str, str] = {
    "src/control_tower_controls_generator/control_retriever.py":
        "646e5ac622af98e0fb0cc5b6a9b21a6028c4cd3261d75c2b4dfe8b5a58778136",
    "src/control_tower_controls_generator/control_mappings_retriever.py":
        "b5e4cbfc11364ff938cceca760e136de733a0399242cd0b4f74f39c21db975c7",
}

# Retriever baseline suites, tracked separately from the source modules so a
# failure says which kind of file drifted. Running them proves they pass; hashing
# them proves they were not edited to make that so. Both suites were updated to
# drop their cache references when caching was removed, so both hashes are
# re-recorded to the post-removal state.
GUARDED_BASELINE_TESTS: dict[str, str] = {
    "tests/unit/test_control_catalog_retriever.py":
        "8e82281e3453587f02777d765c769d7b354467cfbc8e4e69f4518b6875734c1e",
    "tests/unit/test_control_mappings_retriever.py":
        "9e71da9a931b74c948f571ce4e0c3622158640cc451d9c24bf7b0e18eb9c009c",
}

BOTO3_TARGET = "control_tower_controls_generator.control_retriever.boto3"

CATALOG_ARN = "arn:aws:controlcatalog:::control/2xknmxmas18xrbvvexzq9k06g"


# --- helpers -----------------------------------------------------------------

def _normalized_bytes(path: Path) -> bytes:
    """Read a file as bytes with line endings normalized to LF."""
    return path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _content_hash(path: Path) -> str:
    """sha256 over the newline-normalized contents of ``path``."""
    return hashlib.sha256(_normalized_bytes(path)).hexdigest()


def _catalog_item(arn: str = CATALOG_ARN) -> dict:
    """A ListControls response item with the PascalCase keys the model defines."""
    return {
        "Arn": arn,
        "Name": "Require MFA",
        "Description": "A control.",
        "Behavior": "PREVENTIVE",
        "Severity": "MEDIUM",
        "Implementation": {"Type": "AWS::Config::ConfigRule"},
        "GovernedResources": ["AWS::S3::Bucket"],
    }


def _framework_mapping(
    *,
    arn_key: str = "ControlArn",
    type_key: str = "MappingType",
    arn: str = CATALOG_ARN,
) -> dict:
    """A FRAMEWORK ControlMapping, with the two key names parameterizable.

    Swapping ``arn_key`` or ``type_key`` to their camelCase spelling is how each
    named key is pinned individually.
    """
    return {
        type_key: "FRAMEWORK",
        arn_key: arn,
        "Mapping": {"Framework": {"Name": "PCI-DSS-v4.0", "Item": "7.2.2"}},
    }


def _setup_boto3_mock(mock_boto3: MagicMock, pages: list) -> MagicMock:
    """Wire a mocked boto3 so client.get_paginator(...).paginate() -> pages."""
    mock_client = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = pages
    mock_client.get_paginator.return_value = mock_paginator
    mock_boto3.client.return_value = mock_client
    return mock_client


# --- scope fence: the controlcatalog model really is PascalCase ---------------

class TestControlCatalogServiceModelIsPascalCase:
    """The guarded modules are correct, not merely current.

    Read straight off the shipped botocore service model, so this is evidence
    rather than assertion-by-restatement. Needs no credentials and no network.
    """

    @staticmethod
    def _controlcatalog():
        return botocore.session.get_session().get_service_model("controlcatalog")

    def test_list_controls_output_defines_pascalcase_controls(self):
        output = self._controlcatalog().operation_model(
            "ListControls"
        ).output_shape
        assert "Controls" in output.members
        assert "controls" not in output.members

    def test_list_control_mappings_output_defines_pascalcase_controlmappings(self):
        output = self._controlcatalog().operation_model(
            "ListControlMappings"
        ).output_shape
        assert "ControlMappings" in output.members
        assert "controlMappings" not in output.members

    def test_control_mapping_defines_pascalcase_mappingtype_and_controlarn(self):
        mapping = self._controlcatalog().operation_model(
            "ListControlMappings"
        ).output_shape.members["ControlMappings"].member
        assert "MappingType" in mapping.members
        assert "ControlArn" in mapping.members
        assert "mappingType" not in mapping.members
        assert "controlArn" not in mapping.members


# --- the guarded modules still read those PascalCase keys ---------------------

class TestControlRetrieverReadsPascalCaseControls:
    """Guards ``control_retriever.py``'s ``Controls`` key."""

    def test_pascalcase_controls_page_is_collected(self):
        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [{"Controls": [_catalog_item()]}])
            controls = retrieve_control_catalog()

        assert len(controls) == 1
        # Every field read off the PascalCase item made it through.
        assert controls[0].arn == CATALOG_ARN
        assert controls[0].name == "Require MFA"
        assert controls[0].behavior == "PREVENTIVE"
        assert controls[0].severity == "MEDIUM"
        assert controls[0].implementation.type == "AWS::Config::ConfigRule"
        assert controls[0].governed_resources == ["AWS::S3::Bucket"]

    def test_camelcase_controls_page_is_not_collected(self):
        """The camelCase spelling is NOT what this module reads.

        If the enabled-controls fix ever bled into here, this page would start
        producing controls.
        """
        with patch(BOTO3_TARGET) as mock_boto3:
            _setup_boto3_mock(mock_boto3, [{"controls": [_catalog_item()]}])
            controls = retrieve_control_catalog()

        assert controls == []


class TestControlMappingsRetrieverReadsPascalCaseKeys:
    """Guards ``ControlMappings``, ``MappingType``, ``ControlArn``.

    ``_index_mappings`` is the key-reading site and is pure, so it is driven
    directly with no boto3 client.
    """

    def test_pascalcase_controlmappings_page_is_indexed(self):
        index = _index_mappings([{"ControlMappings": [_framework_mapping()]}])

        assert index == {
            CATALOG_ARN: [FrameworkAssociation(name="PCI-DSS-v4.0", item="7.2.2")]
        }

    def test_camelcase_controlmappings_page_is_not_indexed(self):
        index = _index_mappings([{"controlMappings": [_framework_mapping()]}])

        assert index == {}

    def test_mappingtype_discriminator_is_read_from_pascalcase_key(self):
        """A mapping carrying ``mappingType`` is skipped, not treated as FRAMEWORK."""
        index = _index_mappings(
            [{"ControlMappings": [_framework_mapping(type_key="mappingType")]}]
        )

        assert index == {}

    def test_index_key_is_read_from_pascalcase_controlarn(self):
        """A FRAMEWORK mapping carrying ``controlArn`` is skipped, not indexed."""
        index = _index_mappings(
            [{"ControlMappings": [_framework_mapping(arn_key="controlArn")]}]
        )

        assert index == {}


# --- edit detection ----------------------------------------------------------

class TestUntouchedModulesGuard:
    """Detect an edit to either guarded module rather than assuming none."""

    @pytest.mark.parametrize(
        "rel_path,expected_hash", sorted(GUARDED_SOURCE_MODULES.items())
    )
    def test_guarded_source_module_content_hash_unchanged(
        self, rel_path: str, expected_hash: str
    ):
        path = REPO_ROOT / rel_path
        assert path.is_file(), f"guarded module is missing: {rel_path}"

        actual = _content_hash(path)
        assert actual == expected_hash, (
            f"Guarded module modified: {rel_path}.\n"
            f"  expected sha256 {expected_hash}\n"
            f"  actual   sha256 {actual}\n"
            f"  size now {len(_normalized_bytes(path))} bytes\n"
            f"Baseline: {BASELINE_COMMIT}. If this edit was intentional, "
            f"re-record the pinned hash above; otherwise revert it."
        )

    @pytest.mark.parametrize(
        "rel_path,expected_hash", sorted(GUARDED_BASELINE_TESTS.items())
    )
    def test_baseline_test_file_content_hash_unchanged(
        self, rel_path: str, expected_hash: str
    ):
        """The pre-existing Control Catalog suites must pass *unmodified*."""
        path = REPO_ROOT / rel_path
        assert path.is_file(), f"baseline test file is missing: {rel_path}"

        actual = _content_hash(path)
        assert actual == expected_hash, (
            f"{rel_path} was modified. This suite must pass unchanged; editing "
            f"it would make the retriever baseline vacuous.\n"
            f"  expected sha256 {expected_hash}\n"
            f"  actual   sha256 {actual}"
        )

    def test_guard_detects_a_one_byte_edit(self, tmp_path: Path):
        """The mechanism is not vacuous: a trivial edit changes the hash.

        Operates on a temp copy, so the guarded modules are never written to.
        """
        for rel_path, expected_hash in GUARDED_SOURCE_MODULES.items():
            copy = tmp_path / Path(rel_path).name
            shutil.copyfile(REPO_ROOT / rel_path, copy)
            assert _content_hash(copy) == expected_hash

            copy.write_bytes(_normalized_bytes(copy) + b"\n")
            assert _content_hash(copy) != expected_hash, (
                f"guard failed to detect an edit to {rel_path}"
            )
