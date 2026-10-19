"""
Core data model + terminal UX for MultiOS Persistence Hunter.

No third-party dependencies on purpose: this has to run on a bare Windows
box, a minimal Linux server, and macOS with nothing but the stdlib
interpreter already installed.
"""

from __future__ import annotations

import dataclasses
import datetime
import enum
import json
import os
import sys
from typing import Any, Iterable, Optional


# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #

class Severity(enum.IntEnum):
    INFO = 0        # [*] baseline fact, not a finding by itself
    CLEAN = 1       # [+] checked, nothing persisting here
    LOW = 2         # [+] legitimate-looking persistence (known software)
    SUSPICIOUS = 3  # [!] unusual but not conclusively malicious
    CRITICAL = 4    # [X] strong persistence red flags

    @property
    def symbol(self) -> str:
        return {
            Severity.INFO: "*",
            Severity.CLEAN: "+",
            Severity.LOW: "+",
            Severity.SUSPICIOUS: "!",
            Severity.CRITICAL: "X",
        }[self]

    @property
    def color(self) -> str:
        return {
            Severity.INFO: Color.CYAN,
            Severity.CLEAN: Color.GREEN,
            Severity.LOW: Color.GREEN,
            Severity.SUSPICIOUS: Color.YELLOW,
            Severity.CRITICAL: Color.RED,
        }[self]


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    GREY = "\033[90m"


def supports_color() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR") is not None:
        return True
    return sys.stdout.isatty()


# --------------------------------------------------------------------------- #
# Finding
# --------------------------------------------------------------------------- #

@dataclasses.dataclass
class Finding:
    technique_id: str        # short machine id, e.g. "linux.cron.user"
    technique_name: str      # human label, e.g. "User crontab entry"
    severity: Severity
    location: str            # file path / registry key / plist path
    detail: str              # the actual payload: command, binary, ScriptText
    os_name: str             # "windows" | "linux" | "macos"
    evidence_hash: str = ""  # stable hash used for baseline diffing
    extra: dict = dataclasses.field(default_factory=dict)

    def __post_init__(self):
        if not self.evidence_hash:
            import hashlib
            raw = f"{self.technique_id}|{self.location}|{self.detail}".encode(
                "utf-8", errors="replace"
            )
            self.evidence_hash = hashlib.sha256(raw).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.name
        return d


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

@dataclasses.dataclass
class Report:
    os_name: str
    hostname: str
    generated_at: str
    findings: list = dataclasses.field(default_factory=list)
    errors: list = dataclasses.field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, technique_id: str, message: str) -> None:
        self.errors.append({"technique_id": technique_id, "message": message})

    def by_severity(self, minimum: Severity) -> list:
        return [f for f in self.findings if f.severity >= minimum]

    def to_dict(self) -> dict:
        return {
            "os_name": self.os_name,
            "hostname": self.hostname,
            "generated_at": self.generated_at,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @staticmethod
    def now_iso() -> str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Terminal printer
# --------------------------------------------------------------------------- #

class Printer:
    def __init__(self, use_color: Optional[bool] = None, quiet_clean: bool = False):
        self.use_color = supports_color() if use_color is None else use_color
        self.quiet_clean = quiet_clean

    def _c(self, text: str, color: str) -> str:
        if not self.use_color:
            return text
        return f"{color}{text}{Color.RESET}"

    def line(self, severity: Severity, msg: str) -> None:
        if self.quiet_clean and severity in (Severity.CLEAN, Severity.INFO):
            return
        tag = self._c(f"[{severity.symbol}]", severity.color + Color.BOLD if self.use_color else "")
        print(f"{tag} {msg}")

    def info(self, msg: str) -> None:
        self.line(Severity.INFO, msg)

    def clean(self, msg: str) -> None:
        self.line(Severity.CLEAN, msg)

    def suspicious(self, msg: str) -> None:
        self.line(Severity.SUSPICIOUS, msg)

    def critical(self, msg: str) -> None:
        self.line(Severity.CRITICAL, msg)

    def section(self, title: str) -> None:
        bar = "=" * max(8, len(title) + 4)
        header = f"{bar}\n  {title}\n{bar}"
        print(self._c(header, Color.MAGENTA + Color.BOLD if self.use_color else ""))

    def finding(self, f: Finding) -> None:
        self.line(f.severity, f"{self._c(f.technique_name, Color.BOLD)} :: {f.location}")
        detail = f.detail.strip()
        if detail:
            # indent multi-line detail under the finding
            for ln in detail.splitlines()[:6]:
                print(self._c(f"      {ln}", Color.GREY))
            if len(detail.splitlines()) > 6:
                print(self._c(f"      ... ({len(detail.splitlines()) - 6} more lines)", Color.GREY))

    def summary(self, report: Report) -> None:
        counts = {s: 0 for s in Severity}
        for f in report.findings:
            counts[f.severity] += 1
        self.section("SUMMARY")
        print(
            f"  {self._c('[X] critical', Color.RED)}: {counts[Severity.CRITICAL]}   "
            f"{self._c('[!] suspicious', Color.YELLOW)}: {counts[Severity.SUSPICIOUS]}   "
            f"{self._c('[+] low/clean', Color.GREEN)}: {counts[Severity.LOW] + counts[Severity.CLEAN]}   "
            f"{self._c('[*] info', Color.CYAN)}: {counts[Severity.INFO]}"
        )
        if report.errors:
            print(self._c(f"  {len(report.errors)} technique(s) failed to run (see --json for detail)", Color.GREY))
