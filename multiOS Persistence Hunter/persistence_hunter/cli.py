from __future__ import annotations

import argparse
import platform
import socket
import sys

from .core import Printer, Report, Severity
from .baseline import compare_to_baseline, save_baseline

BANNER = r"""
  __  __       _ _   _  ____   _____   ____               _     _
 |  \/  |_   _| | |_(_)/ __ \ / ____| |  _ \             (_)   | |
 | \  / | | | | | __| | |  | | (___   | |_) | ___  _ __   _ ___| |_
 | |\/| | |_| | | |_| | |  | |\___ \  |  _ < / _ \| '_ \ | / __| __|
 | |  | | |_| | | |_| | |__| |____) | | |_) | (_) | | | || \__ \ |_
 |_|  |_|\__,_|_|\__|_|\____/|_____/  |____/ \___/|_| |_||_|___/\__|

      MultiOS Persistence Hunter -- Windows / Linux / macOS
"""


def detect_os() -> str:
    sysname = platform.system().lower()
    if sysname.startswith("win"):
        return "windows"
    if sysname == "darwin":
        return "macos"
    return "linux"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="persistence-hunter",
        description="Enumerates OS persistence mechanisms (Windows/Linux/macOS) for DFIR/threat hunting.",
    )
    p.add_argument("--os", choices=["windows", "linux", "macos"], default=None,
                    help="Force a target OS hunter set instead of auto-detecting.")
    p.add_argument("--json", metavar="FILE", help="Write the full report as JSON to FILE.")
    p.add_argument("--min-severity", choices=["info", "clean", "low", "suspicious", "critical"],
                    default="info", help="Only print findings at or above this severity (default: info).")
    p.add_argument("--quiet-clean", action="store_true",
                    help="Hide CLEAN/INFO lines, show only findings worth a human's attention.")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    p.add_argument("--only", nargs="*", default=None, metavar="TECHNIQUE_ID",
                    help="Run only these technique IDs (space separated).")
    p.add_argument("--baseline-save", metavar="FILE", help="Save this scan's findings as a baseline for future diffing.")
    p.add_argument("--baseline-compare", metavar="FILE", help="Compare this scan against a previously saved baseline.")
    return p


def import_hunters(os_name: str) -> None:
    # importing the module registers its @technique functions
    if os_name == "linux":
        from .hunters import linux  # noqa: F401
    elif os_name == "windows":
        from .hunters import windows  # noqa: F401
    elif os_name == "macos":
        from .hunters import macos  # noqa: F401
    else:
        raise ValueError(f"unknown os: {os_name}")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    os_name = args.os or detect_os()

    printer = Printer(use_color=not args.no_color, quiet_clean=args.quiet_clean)
    print(BANNER)
    printer.info(f"Target OS hunter set : {os_name}")
    printer.info(f"Host                 : {socket.gethostname()}")

    import_hunters(os_name)
    from .hunters.base import run_all

    report = Report(os_name=os_name, hostname=socket.gethostname(), generated_at=Report.now_iso())

    if os_name != detect_os():
        printer.suspicious(
            f"Running {os_name} techniques on a {detect_os()} host -- "
            f"filesystem-dependent checks will mostly come back empty, this is for dev/testing."
        )

    printer.section(f"SCANNING ({os_name})")
    run_all(os_name, report, only=args.only)

    min_sev = Severity[args.min_severity.upper()]
    for f in sorted(report.findings, key=lambda x: -x.severity):
        if f.severity >= min_sev:
            printer.finding(f)

    printer.summary(report)

    if args.baseline_compare:
        printer.section("BASELINE DIFF")
        new, gone = compare_to_baseline(report, args.baseline_compare)
        if not new and not gone:
            printer.clean("No changes since baseline -- no new persistence mechanisms detected.")
        for f in new:
            printer.critical(f"NEW SINCE BASELINE: {f.technique_name} :: {f.location}")
        for f in gone:
            printer.info(f"Removed since baseline: {f.technique_name} :: {f.location}")

    if args.baseline_save:
        save_baseline(report, args.baseline_save)
        printer.info(f"Baseline saved -> {args.baseline_save}")

    if args.json:
        with open(args.json, "w") as fh:
            fh.write(report.to_json())
        printer.info(f"Full JSON report -> {args.json}")

    has_critical = any(f.severity == Severity.CRITICAL for f in report.findings)
    return 2 if has_critical else 0


if __name__ == "__main__":
    sys.exit(main())
