"""
macOS persistence techniques.

Coverage: LaunchAgents/LaunchDaemons (user + global + system scope),
Login Items (via System Events / plist), cron, periodic scripts, legacy
StartupItems, Login/Logout Hooks, Folder Actions, emond rules, and
kernel/system extensions.
"""

from __future__ import annotations

import glob
import os
import plistlib
import subprocess

from ..core import Finding, Report, Severity
from .base import classify, list_dir, safe_read, technique

OS = "macos"


def _home_dirs():
    base = "/Users"
    homes = []
    for name in list_dir(base):
        p = os.path.join(base, name)
        if os.path.isdir(p) and name not in ("Shared", "Guest"):
            homes.append((name, p))
    return homes


def _read_plist(path: str) -> dict:
    try:
        with open(path, "rb") as fh:
            return plistlib.load(fh)
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# 1. LaunchAgents / LaunchDaemons
# --------------------------------------------------------------------------- #

LAUNCH_DIRS = [
    ("system LaunchDaemons", "/Library/LaunchDaemons"),
    ("system LaunchAgents", "/Library/LaunchAgents"),
    ("Apple LaunchDaemons", "/System/Library/LaunchDaemons"),
    ("Apple LaunchAgents", "/System/Library/LaunchAgents"),
]

KNOWN_SAFE_PREFIXES = ("com.apple.",)


@technique(OS, "macos.launchd", "LaunchAgents/LaunchDaemons (system + Apple scope)")
def launchd_system(report: Report) -> None:
    any_found = False
    for label, d in LAUNCH_DIRS:
        for fname in glob.glob(os.path.join(d, "*.plist")):
            plist = _read_plist(fname)
            if not plist:
                continue
            identifier = plist.get("Label", os.path.basename(fname))
            program = plist.get("Program") or " ".join(plist.get("ProgramArguments", []) or [])
            any_found = True
            is_apple = identifier.startswith(KNOWN_SAFE_PREFIXES)
            default_sev = Severity.CLEAN if (is_apple and "/System/" in d) else Severity.LOW
            sev = classify(fname, program, default=default_sev)
            keep_alive = bool(plist.get("KeepAlive"))
            run_at_load = bool(plist.get("RunAtLoad"))
            detail = f"Program: {program}\nRunAtLoad={run_at_load} KeepAlive={keep_alive}"
            report.add(Finding("macos.launchd", f"{label}: {identifier}", sev, fname, detail, OS))
    if not any_found:
        report.add(Finding("macos.launchd", "System/Apple LaunchAgents+Daemons", Severity.CLEAN,
                            "/Library/Launch*", "no entries (or not on macOS)", OS))


@technique(OS, "macos.launchd_user", "Per-user LaunchAgents (~/Library/LaunchAgents)")
def launchd_user(report: Report) -> None:
    any_found = False
    for user, home in _home_dirs():
        d = os.path.join(home, "Library", "LaunchAgents")
        for fname in glob.glob(os.path.join(d, "*.plist")):
            plist = _read_plist(fname)
            if not plist:
                continue
            identifier = plist.get("Label", os.path.basename(fname))
            program = plist.get("Program") or " ".join(plist.get("ProgramArguments", []) or [])
            any_found = True
            sev = classify(fname, program, default=Severity.LOW)
            report.add(Finding("macos.launchd_user", f"User LaunchAgent ({user}): {identifier}",
                                sev, fname, program, OS))
    if not any_found:
        report.add(Finding("macos.launchd_user", "Per-user LaunchAgents", Severity.CLEAN,
                            "~/Library/LaunchAgents", "no entries", OS))


# --------------------------------------------------------------------------- #
# 2. Login Items
# --------------------------------------------------------------------------- #

@technique(OS, "macos.login_items", "Login Items (System Settings > Users > Login Items)")
def login_items(report: Report) -> None:
    script = 'tell application "System Events" to get the name of every login item'
    try:
        out = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        report.add_error("macos.login_items", str(exc))
        return
    items = [i.strip() for i in (out.stdout or "").split(",") if i.strip()]
    if not items:
        report.add(Finding("macos.login_items", "Login Items", Severity.CLEAN,
                            "System Events login items", "no items / not on macOS", OS))
        return
    for item in items:
        report.add(Finding("macos.login_items", "Login Item", Severity.LOW,
                            "System Events login items", item, OS))


# --------------------------------------------------------------------------- #
# 3. Legacy StartupItems
# --------------------------------------------------------------------------- #

@technique(OS, "macos.startup_items", "Legacy StartupItems (/Library/StartupItems)")
def startup_items(report: Report) -> None:
    d = "/Library/StartupItems"
    items = list_dir(d)
    if not items:
        report.add(Finding("macos.startup_items", "Legacy StartupItems", Severity.CLEAN, d,
                            "empty/absent -- deprecated since 10.10, presence alone is notable", OS))
        return
    for item in items:
        # any presence here is unusual on a modern macOS install
        report.add(Finding("macos.startup_items", f"Legacy StartupItem: {item}", Severity.SUSPICIOUS,
                            os.path.join(d, item), "legacy mechanism, deprecated for 10+ years", OS))


# --------------------------------------------------------------------------- #
# 4. cron + periodic
# --------------------------------------------------------------------------- #

@technique(OS, "macos.cron", "crontab (user + /usr/lib/cron/tabs)")
def cron(report: Report) -> None:
    any_found = False
    for user, home in _home_dirs() + [("root", "/var/root")]:
        fpath = f"/usr/lib/cron/tabs/{user}"
        content = safe_read(fpath)
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            any_found = True
            sev = classify(fpath, line, default=Severity.SUSPICIOUS)
            report.add(Finding("macos.cron", f"crontab entry ({user})", sev, fpath, line, OS))
    if not any_found:
        report.add(Finding("macos.cron", "crontab", Severity.CLEAN, "/usr/lib/cron/tabs", "no entries", OS))


@technique(OS, "macos.periodic", "periodic scripts (/etc/periodic/{daily,weekly,monthly})")
def periodic(report: Report) -> None:
    any_found = False
    for period in ("daily", "weekly", "monthly"):
        d = f"/etc/periodic/{period}"
        for fname in list_dir(d):
            fpath = os.path.join(d, fname)
            # stock Apple scripts are named like 100.clean-logs, custom additions stand out
            if fname.split(".")[0].isdigit() and "clean" in fname or "whatis" in fname or "accounting" in fname:
                continue
            any_found = True
            content = safe_read(fpath, 1500)
            report.add(Finding("macos.periodic", f"periodic/{period} script", Severity.SUSPICIOUS,
                                fpath, content[:300], OS))
    if not any_found:
        report.add(Finding("macos.periodic", "periodic scripts", Severity.CLEAN,
                            "/etc/periodic", "only stock Apple scripts (or none found)", OS))


# --------------------------------------------------------------------------- #
# 5. Login/Logout Hooks
# --------------------------------------------------------------------------- #

@technique(OS, "macos.login_hooks", "Login/Logout Hooks (com.apple.loginwindow)")
def login_hooks(report: Report) -> None:
    try:
        out = subprocess.run(["defaults", "read", "com.apple.loginwindow"],
                              capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        report.add_error("macos.login_hooks", str(exc))
        return
    text = out.stdout or ""
    hooks = [l for l in text.splitlines() if "LoginHook" in l or "LogoutHook" in l]
    if not hooks:
        report.add(Finding("macos.login_hooks", "Login/Logout Hooks", Severity.CLEAN,
                            "com.apple.loginwindow", "none configured", OS))
        return
    for h in hooks:
        report.add(Finding("macos.login_hooks", "Login/Logout Hook configured", Severity.CRITICAL,
                            "com.apple.loginwindow", h.strip(), OS))


# --------------------------------------------------------------------------- #
# 6. Folder Actions
# --------------------------------------------------------------------------- #

@technique(OS, "macos.folder_actions", "Folder Actions (scripts attached to folders via Finder)")
def folder_actions(report: Report) -> None:
    any_found = False
    for user, home in _home_dirs():
        d = os.path.join(home, "Library", "Workflows", "Applications", "Folder Actions")
        for item in list_dir(d):
            any_found = True
            report.add(Finding("macos.folder_actions", f"Folder Action ({user})", Severity.SUSPICIOUS,
                                os.path.join(d, item), item, OS))
    if not any_found:
        report.add(Finding("macos.folder_actions", "Folder Actions", Severity.CLEAN,
                            "~/Library/Workflows/Applications/Folder Actions", "none found", OS))


# --------------------------------------------------------------------------- #
# 7. emond rules (old but occasionally still abused)
# --------------------------------------------------------------------------- #

@technique(OS, "macos.emond", "emond rules (/etc/emond.d/rules)")
def emond(report: Report) -> None:
    d = "/etc/emond.d/rules"
    rules = list_dir(d)
    if not rules:
        report.add(Finding("macos.emond", "emond rules", Severity.CLEAN, d, "none found", OS))
        return
    for r in rules:
        report.add(Finding("macos.emond", f"emond rule: {r}", Severity.SUSPICIOUS, os.path.join(d, r),
                            "emond is deprecated but still executed if present", OS))


# --------------------------------------------------------------------------- #
# 8. Kernel / System extensions
# --------------------------------------------------------------------------- #

@technique(OS, "macos.kext_sysext", "Kernel extensions (kext) and System Extensions")
def kext_sysext(report: Report) -> None:
    any_found = False
    for d in ("/Library/Extensions", "/Library/SystemExtensions"):
        for item in list_dir(d):
            any_found = True
            report.add(Finding("macos.kext_sysext", f"Extension: {item}", Severity.LOW,
                                os.path.join(d, item), "third-party kernel/system extension present", OS))
    if not any_found:
        report.add(Finding("macos.kext_sysext", "Kernel/System extensions", Severity.CLEAN,
                            "/Library/Extensions, /Library/SystemExtensions", "no third-party extensions", OS))
