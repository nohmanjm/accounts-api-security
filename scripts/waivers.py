#!/usr/bin/env python3
"""Waiver gatekeeper: `check` fails the build on expired or malformed waivers;
`generate` emits per-tool ignore files from active waivers only."""
import re
import sys
from datetime import date, timedelta
from pathlib import Path

import yaml

WAIVER_FILE = Path(__file__).resolve().parent.parent / "waivers" / "waivers.yaml"
MAX_LIFETIME_DAYS = 90
WARN_DAYS = 7
REQUIRED = {"id", "tool", "reason", "ticket", "approved_by", "created", "expires"}
TOOLS = {"trivy", "gitleaks", "semgrep", "conftest"}


def load():
    data = yaml.safe_load(WAIVER_FILE.read_text()) or {}
    return data.get("waivers") or []


def check(waivers):
    today = date.today()
    errors, warnings = [], []
    for i, w in enumerate(waivers):
        label = f"waiver[{i}] ({w.get('id', '?')})"
        missing = REQUIRED - set(w)
        if missing:
            errors.append(f"{label}: missing fields {sorted(missing)}")
            continue
        if w["tool"] not in TOOLS:
            errors.append(f"{label}: unknown tool '{w['tool']}'")
        if w["tool"] == "gitleaks" and not w.get("fingerprint"):
            errors.append(f"{label}: gitleaks waivers need a fingerprint (file:rule:line)")
        if not re.match(r"SEC-\d+", str(w["ticket"])):
            errors.append(f"{label}: ticket must reference the tracking issue (SEC-n)")
        created, expires = w["created"], w["expires"]
        if (expires - created).days > MAX_LIFETIME_DAYS:
            errors.append(f"{label}: lifetime exceeds {MAX_LIFETIME_DAYS} days")
        if expires < today:
            errors.append(
                f"{label}: EXPIRED {expires} — renew via a fresh platform-team-reviewed "
                f"PR or let the finding block (ticket {w['ticket']})"
            )
        elif expires - timedelta(days=WARN_DAYS) <= today:
            warnings.append(f"{label}: expires {expires} — renewal PR needed this week")
    for msg in warnings:
        print(f"::warning::{msg}")
    if errors:
        for msg in errors:
            print(f"::error::{msg}")
        return 1
    print(f"OK: {len(waivers)} waiver(s) valid and unexpired")
    return 0


def generate(waivers):
    today = date.today()
    active = [w for w in waivers if w["expires"] >= today]
    trivy = [f"{w['id']} # {w['ticket']} exp {w['expires']}" for w in active if w["tool"] == "trivy"]
    gitleaks = [w["fingerprint"] for w in active if w["tool"] == "gitleaks" and w.get("fingerprint")]
    semgrep = [w["id"] for w in active if w["tool"] == "semgrep"]
    Path(".trivyignore").write_text("\n".join(trivy) + "\n")
    Path(".gitleaksignore").write_text("\n".join(gitleaks) + "\n")
    Path("semgrep-excludes.txt").write_text("\n".join(semgrep) + "\n")
    print(f"generated ignore files from {len(active)} active waiver(s)")
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    waivers = load()
    sys.exit(check(waivers) if cmd == "check" else generate(waivers))
