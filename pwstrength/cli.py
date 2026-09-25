"""Command-line front end for pwstrength.

Reads passwords one per line from a file (or stdin) and prints diagnostics
in the style of a compiler: file:line:column, the offending source line,
and a caret span under exactly the characters at fault.
"""

import argparse
import sys

from .analyzer import analyze
from .diagnostics import render_finding

_SCORE_LABELS = ["very weak", "weak", "fair", "strong", "very strong"]


def _check_stream(lines, filename: str) -> bool:
    all_clean = True
    for line_no, raw_line in enumerate(lines, start=1):
        password = raw_line.rstrip("\n")
        if not password:
            continue
        report = analyze(password)
        if report.findings:
            all_clean = False
            for finding in report.findings:
                print(render_finding(finding, password, line_no=line_no, filename=filename))
        label = _SCORE_LABELS[report.score]
        print(f"{filename}:{line_no}: score {report.score}/4 ({label})")
    return all_clean


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="pwstrength",
        description="Check password strength and report exactly what is weak, and where.",
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="file with one password per line; reads stdin if omitted",
    )
    args = parser.parse_args(argv)

    if args.file:
        with open(args.file, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
        filename = args.file
    else:
        lines = sys.stdin.readlines()
        filename = "<stdin>"

    clean = _check_stream(lines, filename)
    return 0 if clean else 1


if __name__ == "__main__":
    sys.exit(main())
