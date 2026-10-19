"""Output writer module for writing report content to file or stdout."""

import os
import sys
from typing import Optional


def write_output(content: str, output_file: Optional[str] = None) -> None:
    """Write report content to a file or stdout.

    Args:
        content: The report content string to write.
        output_file: Optional file path to write to. If None, writes to stdout.

    Raises:
        SystemExit: If the output file cannot be written, exits with code 1.
    """
    if output_file:
        try:
            # Create parent directories if they don't exist
            output_dir = os.path.dirname(output_file)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            # Write with LF line endings on every platform so report output is
            # byte-for-byte identical regardless of the operating system.
            with open(output_file, "w", encoding="utf-8", newline="\n") as f:
                f.write(content)
            print(f"Report saved to {os.path.abspath(output_file)}", file=sys.stderr)
        except (OSError, IOError) as e:
            print(
                f"Error: Could not write to output file '{output_file}': {e}",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        sys.stdout.write(content)
