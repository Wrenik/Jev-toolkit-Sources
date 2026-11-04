"""Regenerate src/jev_sources/data/public_suffix_icann.dat from the Public Suffix List (ICANN section only).

    python tools/update_suffixes.py                  # download https://publicsuffix.org/list/public_suffix_list.dat
    python tools/update_suffixes.py --from list.dat  # use a local copy (offline, reproducible)

The PSL changes a few times a week; its maintainers ask consumers to fetch at most once a day. A policy-writing aid
does not need that freshness, so refresh this snapshot before a release (or when `validate` warns it is old).
Only the ICANN section is kept: the PRIVATE section lists hosting platforms and is huge; those are covered by the
short hand-made MULTI_TENANT list in suffixes.py. Comments are dropped and IDN labels are stored as punycode.

Licence: the list is (c) Mozilla Foundation under the Mozilla Public License 2.0. The generated file keeps the
attribution and licence notice in its header. Only this script contacts the network, and only when run by hand.
"""

from __future__ import annotations

import argparse
import datetime
import re
import sys
import urllib.request
from pathlib import Path

URL = "https://publicsuffix.org/list/public_suffix_list.dat"
OUT = Path(__file__).resolve().parent.parent / "src" / "jev_sources" / "data" / "public_suffix_icann.dat"


def _ascii(rule: str) -> str:
    labels = []
    for lab in rule.split("."):
        labels.append(lab if lab.isascii() else lab.encode("idna").decode("ascii"))
    return ".".join(labels)


def convert(text: str, today: str) -> str:
    version = re.search(r"// VERSION: (\S+)", text)
    commit = re.search(r"// COMMIT: (\S+)", text)
    b, e = text.find("// ===BEGIN ICANN DOMAINS==="), text.find("// ===END ICANN DOMAINS===")
    if b < 0 or e < 0 or e < b:
        raise SystemExit("ICANN section markers not found; the list format changed")
    rules = []
    for line in text[b:e].splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        rule = line.split()[0]
        neg = rule.startswith("!")
        rules.append(("!" if neg else "") + _ascii(rule.lstrip("!").lower()))
    header = [
        "# Public Suffix List snapshot, ICANN section only. Used offline by jev_sources to warn about over-broad policy rules.",
        "# Source:     https://publicsuffix.org/list/public_suffix_list.dat",
        f"# PSL version: {version.group(1) if version else 'unknown'}   commit: {commit.group(1) if commit else 'unknown'}",
        f"# Generated:  {today} by tools/update_suffixes.py (comments removed, IDN labels as punycode, ICANN rules only)",
        "# Licence:    the Public Suffix List is (c) Mozilla Foundation and distributed under the Mozilla Public License 2.0",
        "#             (https://mozilla.org/MPL/2.0/). This file is a derivative of that data and stays under MPL-2.0;",
        "#             the rest of this repository is MIT. Rules: 'x.y' = suffix, '*.x' = wildcard, '!a.x' = exception.",
        f"# Rules:      {len(rules)}",
    ]
    return "\n".join(header + sorted(set(rules))) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--from", dest="src", help="read this local copy instead of downloading")
    ap.add_argument("--out", default=str(OUT))
    a = ap.parse_args(argv)
    if a.src:
        text = Path(a.src).read_text(encoding="utf-8")
    else:
        with urllib.request.urlopen(URL, timeout=60) as r:  # noqa: S310 - fixed https URL, run by hand
            text = r.read().decode("utf-8")
    out = convert(text, datetime.date.today().isoformat())
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(out, encoding="utf-8", newline="\n")
    print(f"wrote {a.out}: {len(out) / 1024:.0f} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
