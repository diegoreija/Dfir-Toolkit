"""
Shared plumbing every OS hunter uses: the @technique decorator that turns a
plain function into a self-registering persistence check, and a couple of
heuristics (suspicious path, suspicious extension...) reused across OSes.
"""

from __future__ import annotations

import os
import re
from typing import Callable, List, NamedTuple

from ..core import Finding, Report, Severity


class Technique(NamedTuple):
    id: str
    name: str
    func: Callable[[Report], None]


REGISTRY: dict = {}  # os_name -> list[Technique]


def technique(os_name: str, technique_id: str, name: str):
    """Decorator: registers `func(report)` as a persistence check for os_name.

    The function is responsible for calling report.add(Finding(...)) for
    whatever it discovers (zero or more). Exceptions are caught by the
    runner and logged as report.errors so one broken technique never kills
    the whole scan.
    """

    def deco(func):
        REGISTRY.setdefault(os_name, []).append(Technique(technique_id, name, func))
        return func

    return deco


def run_all(os_name: str, report: Report, only: list | None = None) -> None:
    techniques = REGISTRY.get(os_name, [])
    for t in techniques:
        if only and t.id not in only:
            continue
        try:
            t.func(report)
        except Exception as exc:  # noqa: BLE001 - we want to isolate failures
            report.add_error(t.id, f"{type(exc).__name__}: {exc}")


# --------------------------------------------------------------------------- #
# Shared heuristics
# --------------------------------------------------------------------------- #

SUSPICIOUS_DIR_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"[\\/]tmp[\\/]",
        r"[\\/]var[\\/]tmp[\\/]",
        r"[\\/]dev[\\/]shm[\\/]",
        r"[\\/]Users[\\/]Public[\\/]",
        r"[\\/]AppData[\\/]Local[\\/]Temp[\\/]",
        r"[\\/]\.cache[\\/]",
        r"[\\/]Downloads[\\/]",
        r"[\\/]Recycle",
        r"[\\/]\$Recycle\.Bin",
    ]
]

SUSPICIOUS_TOKENS = [
    "base64", "-enc ", "frombase64string", "iex(", "invoke-expression",
    "downloadstring", "downloadfile", "curl -s", "wget -q", "nc -e",
    "/dev/tcp/", "bash -i", "powershell -nop", "-windowstyle hidden",
    "certutil -urlcache", "mshta http", "rundll32.exe javascript:",
]


def path_is_suspicious(path: str) -> bool:
    return any(p.search(path) for p in SUSPICIOUS_DIR_PATTERNS)


def command_is_suspicious(cmd: str) -> bool:
    low = cmd.lower()
    return any(tok in low for tok in SUSPICIOUS_TOKENS)


def classify(location: str, detail: str, default: Severity = Severity.LOW) -> Severity:
    """Cheap heuristic bump: suspicious path/command -> at least SUSPICIOUS."""
    if command_is_suspicious(detail) or path_is_suspicious(location) or path_is_suspicious(detail):
        return Severity.CRITICAL if command_is_suspicious(detail) else Severity.SUSPICIOUS
    return default


def safe_read(path: str, max_bytes: int = 20000) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(max_bytes)
    except OSError:
        return ""


def list_dir(path: str) -> List[str]:
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []
