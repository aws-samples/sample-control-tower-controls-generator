"""Unit tests for the input file parser module.

Plain example-based pytest tests covering ``parse_input_file`` across its
documented formats and error paths: simple JSON array parsing, Config
aggregator query output with and without ``accountId`` data, deduplication,
and the error conditions for a missing file, invalid JSON, and empty / no
valid resource types.
"""

import csv
import io
import json

import pytest

from control_tower_controls_generator.input_parser import (
    InputParserError,
    parse_input_file,
)


def _write(tmp_path, name: str, content: str) -> str:
    """Write ``content`` to ``name`` under ``tmp_path``; return the path str."""
    file_path = tmp_path / name
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


def _config_row(resource_type: str, account_id: str | None = None) -> str:
    """Build a single JSON-stringified Config aggregator result row."""
    row: dict[str, str] = {"resourceType": resource_type}
    if account_id is not None:
        row["accountId"] = account_id
    return json.dumps(row)


def _config_doc(rows: list[str]) -> str:
    """Wrap JSON-stringified result rows in a Config aggregator query doc."""
    return json.dumps({"QueryInfo": {"SelectFields": []}, "Results": rows})


def _csv_doc(rows, header=("resourceType", "accountId")) -> str:
    """Build CSV text with ``header`` and ``(resource_type, account_id)`` rows.

    Written via :mod:`csv` so quoting matches a real AWS Config CSV export. The
    account payloads exercised here contain no comma, quote, or newline, so they
    round-trip as single unquoted cells.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(list(header))
    for row in rows:
        writer.writerow(list(row))
    return buf.getvalue()


HTML_PAYLOAD = "<img src=x onerror=alert(document.domain)>"

# Non-canonical account ids that Layer 1 validation must reject. Each fails
# ``^\d{12}$`` compiled with ``re.ASCII``.
INVALID_ACCOUNT_IDS = [
    "12345678901|forged",  # pipe: Markdown table row/column forgery vector
    "11111111111",  # 11 digits: too short
    "1111111111111",  # 13 digits: too long
    "１２３４５６７８９０１２",  # 12 full-width digits: match \d but not re.ASCII
]


class TestSimpleArray:
    """Simple JSON array of resource type strings."""

    def test_valid_simple_array_returns_resource_types(self, tmp_path):
        path = _write(
            tmp_path,
            "input.json",
            json.dumps(["AWS::EC2::Instance", "AWS::S3::Bucket"]),
        )

        result = parse_input_file(path)

        assert result.resource_types == ["AWS::EC2::Instance", "AWS::S3::Bucket"]

    def test_simple_array_has_no_account_mapping(self, tmp_path):
        # A simple array carries no account data, so mapping must be None.
        path = _write(tmp_path, "input.json", json.dumps(["AWS::S3::Bucket"]))

        result = parse_input_file(path)

        assert result.account_mapping is None

    def test_simple_array_deduplicates_preserving_order(self, tmp_path):
        # Duplicates are removed and first-seen order is preserved.
        path = _write(
            tmp_path,
            "input.json",
            json.dumps(
                [
                    "AWS::S3::Bucket",
                    "AWS::EC2::Instance",
                    "AWS::S3::Bucket",
                ]
            ),
        )

        result = parse_input_file(path)

        assert result.resource_types == ["AWS::S3::Bucket", "AWS::EC2::Instance"]

    def test_simple_array_skips_blank_and_non_string_entries(self, tmp_path):
        # Empty/whitespace strings and non-string entries are ignored, and the
        # surviving values are trimmed.
        path = _write(
            tmp_path,
            "input.json",
            json.dumps(["  AWS::EC2::Instance  ", "", "   ", 42, None]),
        )

        result = parse_input_file(path)

        assert result.resource_types == ["AWS::EC2::Instance"]


class TestConfigAggregatorWithAccountId:
    """Config aggregator output including accountId."""

    def test_builds_account_mapping_from_rows(self, tmp_path):
        path = _write(
            tmp_path,
            "aggregator.json",
            _config_doc(
                [
                    _config_row("AWS::EC2::Instance", "111111111111"),
                    _config_row("AWS::S3::Bucket", "222222222222"),
                ]
            ),
        )

        result = parse_input_file(path)

        assert result.resource_types == ["AWS::EC2::Instance", "AWS::S3::Bucket"]
        assert result.account_mapping == {
            "AWS::EC2::Instance": ["111111111111"],
            "AWS::S3::Bucket": ["222222222222"],
        }

    def test_aggregates_multiple_accounts_for_same_resource_type(self, tmp_path):
        # The same resource type seen under two accounts collapses to one
        # deduplicated resource type mapped to both account IDs.
        path = _write(
            tmp_path,
            "aggregator.json",
            _config_doc(
                [
                    _config_row("AWS::S3::Bucket", "111111111111"),
                    _config_row("AWS::S3::Bucket", "222222222222"),
                    _config_row("AWS::S3::Bucket", "111111111111"),
                ]
            ),
        )

        result = parse_input_file(path)

        assert result.resource_types == ["AWS::S3::Bucket"]
        # Account IDs are deduplicated per resource type, order preserved.
        assert result.account_mapping == {
            "AWS::S3::Bucket": ["111111111111", "222222222222"],
        }


class TestConfigAggregatorWithoutAccountId:
    """Config aggregator output lacking accountId."""

    def test_resource_types_parsed_without_account_mapping(self, tmp_path):
        path = _write(
            tmp_path,
            "aggregator.json",
            _config_doc(
                [
                    _config_row("AWS::EC2::Instance"),
                    _config_row("AWS::Lambda::Function"),
                ]
            ),
        )

        result = parse_input_file(path)

        assert result.resource_types == [
            "AWS::EC2::Instance",
            "AWS::Lambda::Function",
        ]
        # No accountId data anywhere -> mapping is omitted entirely.
        assert result.account_mapping is None

    def test_config_aggregator_deduplicates_resource_types(self, tmp_path):
        path = _write(
            tmp_path,
            "aggregator.json",
            _config_doc(
                [
                    _config_row("AWS::EC2::Instance"),
                    _config_row("AWS::EC2::Instance"),
                    _config_row("AWS::S3::Bucket"),
                ]
            ),
        )

        result = parse_input_file(path)

        assert result.resource_types == ["AWS::EC2::Instance", "AWS::S3::Bucket"]
        assert result.account_mapping is None


class TestFileNotFound:
    """Missing / unreadable input file."""

    def test_missing_file_raises_input_parser_error(self, tmp_path):
        missing = str(tmp_path / "does_not_exist.json")

        with pytest.raises(InputParserError) as exc_info:
            parse_input_file(missing)

        assert "not found" in str(exc_info.value).lower()


class TestInvalidJson:
    """Malformed JSON content."""

    def test_invalid_json_raises_input_parser_error(self, tmp_path):
        # Starts with '{' so it is treated as JSON (not CSV), then fails to
        # parse and surfaces the invalid-JSON error.
        path = _write(tmp_path, "broken.json", "{ this is not valid json ]")

        with pytest.raises(InputParserError) as exc_info:
            parse_input_file(path)

        assert "invalid json" in str(exc_info.value).lower()


class TestEmptyInput:
    """Empty or resource-type-less input."""

    def test_empty_array_raises_input_parser_error(self, tmp_path):
        path = _write(tmp_path, "empty.json", json.dumps([]))

        with pytest.raises(InputParserError) as exc_info:
            parse_input_file(path)

        assert "no valid resource types" in str(exc_info.value).lower()

    def test_empty_results_raises_input_parser_error(self, tmp_path):
        # Config aggregator shape with an empty Results array yields no types.
        path = _write(tmp_path, "empty_results.json", _config_doc([]))

        with pytest.raises(InputParserError) as exc_info:
            parse_input_file(path)

        assert "no valid resource types" in str(exc_info.value).lower()


class TestAccountIdValidationHappyPath:
    """Layer 1 validation accepts a canonical 12-digit accountId."""

    def test_valid_account_id_accepted_aggregator(self, tmp_path):
        # A canonical id survives parse-time validation on the aggregator path.
        path = _write(
            tmp_path,
            "aggregator.json",
            _config_doc([_config_row("AWS::EC2::Instance", "123456789012")]),
        )

        result = parse_input_file(path)

        assert result.resource_types == ["AWS::EC2::Instance"]
        assert result.account_mapping == {"AWS::EC2::Instance": ["123456789012"]}

    def test_valid_account_id_accepted_csv(self, tmp_path):
        # The same guarantee holds on the CSV path.
        path = _write(
            tmp_path,
            "aggregator.csv",
            _csv_doc([("AWS::EC2::Instance", "123456789012")]),
        )

        result = parse_input_file(path)

        assert result.resource_types == ["AWS::EC2::Instance"]
        assert result.account_mapping == {"AWS::EC2::Instance": ["123456789012"]}


class TestAccountIdValidationDropsHtmlPayload:
    """The HTML-injection payload is rejected at parse time."""

    def test_html_payload_dropped_aggregator(self, tmp_path):
        path = _write(
            tmp_path,
            "aggregator.json",
            _config_doc([_config_row("AWS::EC2::Instance", HTML_PAYLOAD)]),
        )

        result = parse_input_file(path)

        # The resource type is still parsed; the payload never enters the
        # mapping, so with no other account data the mapping collapses to None.
        assert result.resource_types == ["AWS::EC2::Instance"]
        assert result.account_mapping is None

    def test_html_payload_dropped_csv(self, tmp_path):
        path = _write(
            tmp_path,
            "aggregator.csv",
            _csv_doc([("AWS::EC2::Instance", HTML_PAYLOAD)]),
        )

        result = parse_input_file(path)

        assert result.resource_types == ["AWS::EC2::Instance"]
        assert result.account_mapping is None


class TestAccountIdValidationDropsInvalidFormats:
    """Pipe, wrong-length, and non-ASCII-digit ids are dropped."""

    @pytest.mark.parametrize("account_id", INVALID_ACCOUNT_IDS)
    def test_invalid_id_dropped_aggregator(self, tmp_path, account_id):
        path = _write(
            tmp_path,
            "aggregator.json",
            _config_doc([_config_row("AWS::S3::Bucket", account_id)]),
        )

        result = parse_input_file(path)

        assert result.resource_types == ["AWS::S3::Bucket"]
        assert result.account_mapping is None

    @pytest.mark.parametrize("account_id", INVALID_ACCOUNT_IDS)
    def test_invalid_id_dropped_csv(self, tmp_path, account_id):
        path = _write(
            tmp_path,
            "aggregator.csv",
            _csv_doc([("AWS::S3::Bucket", account_id)]),
        )

        result = parse_input_file(path)

        assert result.resource_types == ["AWS::S3::Bucket"]
        assert result.account_mapping is None


class TestAccountIdValidationAllInvalid:
    """All-invalid ids with a valid resource type."""

    def test_all_invalid_ids_yield_none_mapping_aggregator(self, tmp_path):
        # Every accountId is invalid but the resource types are valid: parsing
        # must succeed (no InputParserError) with account_mapping left as None.
        path = _write(
            tmp_path,
            "aggregator.json",
            _config_doc(
                [
                    _config_row("AWS::EC2::Instance", "not-an-id"),
                    _config_row("AWS::S3::Bucket", "99999999999"),  # 11 digits
                    _config_row("AWS::S3::Bucket", HTML_PAYLOAD),
                ]
            ),
        )

        result = parse_input_file(path)

        assert result.resource_types == ["AWS::EC2::Instance", "AWS::S3::Bucket"]
        assert result.account_mapping is None

    def test_all_invalid_ids_yield_none_mapping_csv(self, tmp_path):
        path = _write(
            tmp_path,
            "aggregator.csv",
            _csv_doc(
                [
                    ("AWS::EC2::Instance", "not-an-id"),
                    ("AWS::S3::Bucket", "99999999999"),
                    ("AWS::S3::Bucket", HTML_PAYLOAD),
                ]
            ),
        )

        result = parse_input_file(path)

        assert result.resource_types == ["AWS::EC2::Instance", "AWS::S3::Bucket"]
        assert result.account_mapping is None


class TestAccountIdValidationFailOpenMix:
    """A mix of valid and invalid ids retains exactly the valid ids."""

    def test_mix_retains_exactly_valid_ids_aggregator(self, tmp_path):
        path = _write(
            tmp_path,
            "aggregator.json",
            _config_doc(
                [
                    _config_row("AWS::EC2::Instance", "111111111111"),
                    _config_row("AWS::EC2::Instance", HTML_PAYLOAD),
                    _config_row("AWS::S3::Bucket", "12345678901|forged"),
                    _config_row("AWS::S3::Bucket", "222222222222"),
                ]
            ),
        )

        result = parse_input_file(path)

        assert result.resource_types == ["AWS::EC2::Instance", "AWS::S3::Bucket"]
        # Only the two canonical ids survive, mapped to their resource types.
        assert result.account_mapping == {
            "AWS::EC2::Instance": ["111111111111"],
            "AWS::S3::Bucket": ["222222222222"],
        }

    def test_mix_retains_exactly_valid_ids_csv(self, tmp_path):
        path = _write(
            tmp_path,
            "aggregator.csv",
            _csv_doc(
                [
                    ("AWS::EC2::Instance", "111111111111"),
                    ("AWS::EC2::Instance", HTML_PAYLOAD),
                    ("AWS::S3::Bucket", "12345678901|forged"),
                    ("AWS::S3::Bucket", "222222222222"),
                ]
            ),
        )

        result = parse_input_file(path)

        assert result.resource_types == ["AWS::EC2::Instance", "AWS::S3::Bucket"]
        assert result.account_mapping == {
            "AWS::EC2::Instance": ["111111111111"],
            "AWS::S3::Bucket": ["222222222222"],
        }


class TestAccountIdValidationWarning:
    """A rejected id warns to stderr and never to stdout."""

    def test_invalid_id_warns_to_stderr_not_stdout_aggregator(self, tmp_path, capsys):
        path = _write(
            tmp_path,
            "aggregator.json",
            _config_doc([_config_row("AWS::EC2::Instance", "12345678901|forged")]),
        )

        parse_input_file(path)

        captured = capsys.readouterr()
        assert "invalid account id" in captured.err.lower()
        assert "12345678901|forged" in captured.err
        # Fail-open warnings must go to stderr only, never polluting stdout.
        assert captured.out == ""

    def test_invalid_id_warns_to_stderr_not_stdout_csv(self, tmp_path, capsys):
        path = _write(
            tmp_path,
            "aggregator.csv",
            _csv_doc([("AWS::EC2::Instance", "12345678901|forged")]),
        )

        parse_input_file(path)

        captured = capsys.readouterr()
        assert "invalid account id" in captured.err.lower()
        assert "12345678901|forged" in captured.err
        assert captured.out == ""
