"""Update the coverage badge in README.md from a coverage.xml report.

Usage::

    python scripts/update_coverage_badge.py coverage.xml README.md

The badge URL is rewritten in-place; the rest of the README is untouched.
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

BADGE_RE = re.compile(r"https://img\.shields\.io/badge/coverage-[0-9.]+%25-[a-zA-Z0-9]+")


def _color(pct: float) -> str:
    if pct >= 90.0:
        return "brightgreen"
    if pct >= 80.0:
        return "green"
    if pct >= 70.0:
        return "yellowgreen"
    if pct >= 60.0:
        return "yellow"
    if pct >= 50.0:
        return "orange"
    return "red"


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    coverage_xml = Path(sys.argv[1])
    readme = Path(sys.argv[2])

    root = ET.parse(coverage_xml).getroot()
    line_rate = float(root.get("line-rate", "0"))
    pct = round(line_rate * 100.0, 1)
    color = _color(pct)
    new_url = f"https://img.shields.io/badge/coverage-{pct}%25-{color}"

    text = readme.read_text(encoding="utf-8")
    if not BADGE_RE.search(text):
        print(
            "No coverage badge URL found in README; insert "
            "`![coverage](https://img.shields.io/badge/coverage-0.0%25-lightgrey)` "
            "first.",
            file=sys.stderr,
        )
        return 1
    new_text = BADGE_RE.sub(new_url, text)
    if new_text == text:
        print(f"Coverage badge already at {pct}% — no change.")
        return 0
    readme.write_text(new_text, encoding="utf-8")
    print(f"Updated coverage badge to {pct}% ({color}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
