"""CLI for phishing_detector. Analysis of supplied text only — no fetching."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .detector import analyse


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishing_detector",
        description=(
            "Score supplied email text or a URL for phishing signals. "
            "Defensive analysis only: nothing is sent, fetched, or opened."
        ),
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", "-f", type=Path, help="Path to a raw email text file")
    group.add_argument("--url", "-u", help="A single URL string to analyse")
    group.add_argument("--text", "-t", help="A raw text string to analyse")
    p.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.file is not None:
        try:
            text = args.file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"Error reading file: {exc}", file=sys.stderr)
            return 2
    elif args.url is not None:
        text = args.url
    else:
        text = args.text

    result = analyse(text)
    if args.json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        print(f"Score: {result.score}/100")
        print(f"Risk:  {result.level}")
        if result.urls:
            print("URLs found:")
            for url in result.urls:
                print(f"  - {url}")
        print("Reasons:")
        for reason in result.reasons:
            print(f"  - {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
