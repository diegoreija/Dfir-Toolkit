"""
Baseline save/compare.

The actual value of a persistence hunter in a DFIR context isn't "here are
500 autostart entries, good luck" -- it's "here is exactly what changed
since last Tuesday". That's what this module is for: snapshot a known-good
state, and on every later run flag only what's NEW (or what disappeared,
which matters too -- malware cleaning up after itself is a signal).
"""

from __future__ import annotations

import json
import os
from typing import List, Tuple

from .core import Finding, Report, Severity


def save_baseline(report: Report, path: str) -> None:
    with open(path, "w") as fh:
        fh.write(report.to_json())


def _load_hashes(path: str) -> dict:
    if not os.path.isfile(path):
        return {}
    with open(path) as fh:
        data = json.load(fh)
    return {f["evidence_hash"]: f for f in data.get("findings", [])}


def compare_to_baseline(report: Report, baseline_path: str) -> Tuple[List[Finding], List[dict]]:
    """Returns (new_findings, findings_that_disappeared_since_baseline)."""
    old = _load_hashes(baseline_path)
    current_hashes = {f.evidence_hash: f for f in report.findings}

    new = [f for h, f in current_hashes.items() if h not in old and f.severity > Severity.CLEAN]
    gone = [f for h, f in old.items() if h not in current_hashes and f.get("severity") not in ("CLEAN",)]
    return new, gone
