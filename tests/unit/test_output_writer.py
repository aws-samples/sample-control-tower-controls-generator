"""Unit tests for the output writer module."""

import os
import pytest

from control_tower_controls_generator.output_writer import write_output


class TestWriteOutputToFile:
    """Tests for writing output to a file path."""

    def test_writes_content_to_file(self, tmp_path):
        output_file = str(tmp_path / "report.json")
        content = '{"summary": {"totalRecommended": 5}}'

        write_output(content, output_file)

        with open(output_file, "r", encoding="utf-8") as f:
            assert f.read() == content

    def test_writes_empty_content_to_file(self, tmp_path):
        output_file = str(tmp_path / "empty.json")

        write_output("", output_file)

        with open(output_file, "r", encoding="utf-8") as f:
            assert f.read() == ""

    def test_overwrites_existing_file(self, tmp_path):
        output_file = str(tmp_path / "report.json")
        with open(output_file, "w") as f:
            f.write("old content")

        write_output("new content", output_file)

        with open(output_file, "r", encoding="utf-8") as f:
            assert f.read() == "new content"

    def test_exits_with_code_1_on_write_error(self, tmp_path):
        # A parent path that is a regular file makes directory creation fail,
        # so the write genuinely errors (write_output creates missing parents).
        blocker = tmp_path / "blocker"
        blocker.write_text("i am a file, not a directory", encoding="utf-8")
        invalid_path = str(blocker / "subdir" / "report.json")

        with pytest.raises(SystemExit) as exc_info:
            write_output("content", invalid_path)

        assert exc_info.value.code == 1

    def test_prints_error_message_on_write_failure(self, tmp_path, capsys):
        blocker = tmp_path / "blocker"
        blocker.write_text("i am a file, not a directory", encoding="utf-8")
        invalid_path = str(blocker / "report.json")

        with pytest.raises(SystemExit):
            write_output("content", invalid_path)

        captured = capsys.readouterr()
        assert "Error: Could not write to output file" in captured.err
        assert invalid_path in captured.err


class TestWriteOutputToStdout:
    """Tests for writing output to stdout."""

    def test_writes_content_to_stdout(self, capsys):
        content = '{"summary": {"totalRecommended": 5}}'

        write_output(content)

        captured = capsys.readouterr()
        assert captured.out == content

    def test_writes_to_stdout_when_output_file_is_none(self, capsys):
        write_output("hello", None)

        captured = capsys.readouterr()
        assert captured.out == "hello"

    def test_writes_empty_string_to_stdout(self, capsys):
        write_output("")

        captured = capsys.readouterr()
        assert captured.out == ""
