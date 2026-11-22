"""Command-line entry point.

    exposure-audit --email me@example.com --phone "+1 555 123 4567" --username myhandle

Every email and phone is verified by a one-time code before anything is
checked. Usernames can't be verified the same way, so they are only accepted
alongside at least one verified email or phone, and you must confirm they
are yours.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .audit import run_audit
from .checks.phone import normalize
from .report import to_html, to_markdown
from .verify import VerificationError, verify_email, verify_phone

BANNER = """\
exposure-audit: see what's publicly linkable to YOU.
This tool only audits identifiers you can prove are yours. Running it
against someone else's details is not supported and may be illegal where
you live (stalking, harassment and data-protection laws).
"""


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="exposure-audit", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--email", action="append", default=[], help="an email you own (repeatable)")
    p.add_argument("--phone", action="append", default=[], help="a phone number you own (repeatable)")
    p.add_argument("--username", action="append", default=[], help="a handle you use (repeatable)")
    p.add_argument("--region", default="US", help="default region for phone parsing (default US)")
    p.add_argument("--out", default="exposure-report", help="output path without extension")
    p.add_argument("--format", choices=["html", "md", "both"], default="both")
    p.add_argument("--version", action="version", version=__version__)
    return p.parse_args(argv)


def main(argv=None) -> int:
    a = parse_args(argv)
    print(BANNER)

    if not (a.email or a.phone):
        print("You need at least one email or phone number to verify ownership.", file=sys.stderr)
        return 2

    emails = sorted({x.strip().lower() for x in a.email if x.strip()})
    phones = []
    for raw in a.phone:
        try:
            phones.append(normalize(raw, a.region))
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

    verified_emails, verified_phones = [], []
    try:
        for em in emails:
            if verify_email(em):
                verified_emails.append(em)
                print(f"  ✓ {em} verified")
            else:
                print(f"  ✗ {em} not verified, it will be skipped")
        for ph in sorted(set(phones)):
            if verify_phone(ph):
                verified_phones.append(ph)
                print(f"  ✓ {ph} verified")
            else:
                print(f"  ✗ {ph} not verified, it will be skipped")
    except VerificationError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if not (verified_emails or verified_phones):
        print("Nothing verified, so nothing to audit.", file=sys.stderr)
        return 1

    handles = []
    if a.username:
        print("\nUsernames can't be verified with a code. Confirm each one is yours:")
        for u in dict.fromkeys(x.strip() for x in a.username if x.strip()):
            if input(f"  Is '{u}' your own username? [y/N] ").strip().lower() == "y":
                handles.append(u)

    print("\nRunning checks…")
    result = run_audit(verified_emails, verified_phones, handles)

    out = Path(a.out)
    written = []
    if a.format in ("md", "both"):
        p = out.with_suffix(".md")
        p.write_text(to_markdown(result), encoding="utf-8")
        written.append(p)
    if a.format in ("html", "both"):
        p = out.with_suffix(".html")
        p.write_text(to_html(result), encoding="utf-8")
        written.append(p)
    for p in written:
        try:
            os.chmod(p, 0o600)   # the report is your personal data
        except OSError:
            pass

    hi = sum(1 for f in result.findings if f.severity.value == "high")
    print(f"\nDone: {len(result.findings)} findings ({hi} high). Report: "
          + ", ".join(str(p) for p in written))
    return 0


if __name__ == "__main__":
    sys.exit(main())
