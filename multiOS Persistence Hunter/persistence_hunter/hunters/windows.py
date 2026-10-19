"""
Windows persistence techniques.

Coverage: Run/RunOnce (HKLM+HKCU, 32/64-bit views), Startup folders,
Services (non-standard ImagePath), Scheduled Tasks (Tasks XML dir walk),
WMI permanent event subscriptions, AppInit_DLLs, Image File Execution
Options debugger hijack, Winlogon Shell/Userinit, LSA Security/Auth
packages, BITS jobs, Active Setup, Print Monitors, and a simplified COM
hijack check (HKCU CLSID shadowing HKLM).

Written to degrade gracefully when `winreg` isn't available (i.e. when
developing/testing this on Linux or macOS) -- every technique checks
`_WINREG_OK` first and reports itself unavailable rather than crashing,
and `run_all()` in base.py already isolates per-technique exceptions too.
"""

from __future__ import annotations

import glob
import os
import subprocess
import xml.etree.ElementTree as ET

from ..core import Finding, Report, Severity
from .base import classify, command_is_suspicious, technique

OS = "windows"

try:
    import winreg  # type: ignore

    _WINREG_OK = True
except ImportError:
    _WINREG_OK = False


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

_HIVE_NAMES = {
    "HKLM": winreg.HKEY_LOCAL_MACHINE if _WINREG_OK else None,
    "HKCU": winreg.HKEY_CURRENT_USER if _WINREG_OK else None,
    "HKU": winreg.HKEY_USERS if _WINREG_OK else None,
}

_VIEWS = (
    [("64-bit", 0), ("32-bit", winreg.KEY_WOW64_32KEY)]
    if _WINREG_OK
    else []
)


def _iter_values(hive_name: str, subkey: str, view_flag: int = 0):
    """Yield (value_name, value_data) for every value under hive/subkey."""
    if not _WINREG_OK:
        return
    hive = _HIVE_NAMES[hive_name]
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view_flag) as key:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    yield name, data
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        return
    except OSError:
        return


def _key_exists(hive_name: str, subkey: str) -> bool:
    if not _WINREG_OK:
        return False
    hive = _HIVE_NAMES[hive_name]
    try:
        with winreg.OpenKey(hive, subkey):
            return True
    except OSError:
        return False


def _iter_subkeys(hive_name: str, subkey: str):
    if not _WINREG_OK:
        return
    hive = _HIVE_NAMES[hive_name]
    try:
        with winreg.OpenKey(hive, subkey) as key:
            i = 0
            while True:
                try:
                    yield winreg.EnumKey(key, i)
                    i += 1
                except OSError:
                    break
    except OSError:
        return


def _report_unavailable(report: Report, technique_id: str, name: str) -> None:
    report.add(Finding(technique_id, name, Severity.INFO, "winreg", "unavailable on this platform (dev run)", OS))


# --------------------------------------------------------------------------- #
# 1. Run / RunOnce keys
# --------------------------------------------------------------------------- #

RUN_KEYS = [
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
]


@technique(OS, "windows.run_keys", "Run/RunOnce autostart registry keys")
def run_keys(report: Report) -> None:
    if not _WINREG_OK:
        return _report_unavailable(report, "windows.run_keys", "Run/RunOnce keys")
    any_found = False
    for hive, subkey in RUN_KEYS:
        for view_label, view_flag in _VIEWS:
            for name, data in _iter_values(hive, subkey, view_flag):
                any_found = True
                sev = classify(f"{hive}\\{subkey}", str(data), default=Severity.LOW)
                report.add(Finding("windows.run_keys", f"Run entry ({hive}, {view_label})",
                                    sev, f"{hive}\\{subkey}\\{name}", str(data), OS))
    if not any_found:
        report.add(Finding("windows.run_keys", "Run/RunOnce keys", Severity.CLEAN,
                            "HKLM/HKCU Run keys", "no entries", OS))


# --------------------------------------------------------------------------- #
# 2. Startup folders
# --------------------------------------------------------------------------- #

@technique(OS, "windows.startup_folders", "Startup folder shortcuts (user + common)")
def startup_folders(report: Report) -> None:
    candidates = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    any_found = False
    for d in candidates:
        if not os.path.isdir(d):
            continue
        for fname in os.listdir(d):
            any_found = True
            fpath = os.path.join(d, fname)
            sev = classify(fpath, fname, default=Severity.LOW)
            report.add(Finding("windows.startup_folders", "Startup folder item", sev, fpath, fname, OS))
    if not any_found:
        report.add(Finding("windows.startup_folders", "Startup folders", Severity.CLEAN,
                            "Startup folders", "no items / not on Windows", OS))


# --------------------------------------------------------------------------- #
# 3. Services with non-standard ImagePath
# --------------------------------------------------------------------------- #

STANDARD_SERVICE_DIRS = (r"c:\windows\system32", r"c:\windows\syswow64")


@technique(OS, "windows.services", "Services with ImagePath outside System32")
def services(report: Report) -> None:
    if not _WINREG_OK:
        return _report_unavailable(report, "windows.services", "Services")
    base = r"SYSTEM\CurrentControlSet\Services"
    any_flagged = False
    for svc_name in _iter_subkeys("HKLM", base):
        subkey = f"{base}\\{svc_name}"
        image_path = None
        for name, data in _iter_values("HKLM", subkey):
            if name.lower() == "imagepath":
                image_path = str(data)
        if not image_path:
            continue
        low = image_path.lower().strip('"')
        if not low.startswith(STANDARD_SERVICE_DIRS) and ":\\" in low:
            any_flagged = True
            sev = classify(subkey, image_path, default=Severity.SUSPICIOUS)
            report.add(Finding("windows.services", f"Service: {svc_name}", sev, subkey, image_path, OS))
    if not any_flagged:
        report.add(Finding("windows.services", "Services (non-standard ImagePath)", Severity.CLEAN,
                            base, "all services load from System32/SysWOW64 (or none found)", OS))


# --------------------------------------------------------------------------- #
# 4. Scheduled Tasks (filesystem walk of Tasks XML, no COM dependency)
# --------------------------------------------------------------------------- #

@technique(OS, "windows.scheduled_tasks", "Scheduled Tasks (Windows\\System32\\Tasks)")
def scheduled_tasks(report: Report) -> None:
    root = r"C:\Windows\System32\Tasks"
    if not os.path.isdir(root):
        report.add(Finding("windows.scheduled_tasks", "Scheduled Tasks", Severity.CLEAN,
                            root, "directory not present (not on Windows, or none)", OS))
        return
    any_found = False
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            fpath = os.path.join(dirpath, fname)
            try:
                tree = ET.parse(fpath)
            except ET.ParseError:
                continue
            ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
            cmd_el = tree.find(".//t:Actions/t:Exec/t:Command", ns)
            args_el = tree.find(".//t:Actions/t:Exec/t:Arguments", ns)
            cmd = (cmd_el.text or "") if cmd_el is not None else ""
            args = (args_el.text or "") if args_el is not None else ""
            detail = f"{cmd} {args}".strip()
            if not detail:
                continue
            any_found = True
            sev = classify(fpath, detail, default=Severity.LOW)
            report.add(Finding("windows.scheduled_tasks", f"Scheduled Task: {fname}", sev, fpath, detail, OS))
    if not any_found:
        report.add(Finding("windows.scheduled_tasks", "Scheduled Tasks", Severity.CLEAN,
                            root, "no tasks with executable actions found", OS))


# --------------------------------------------------------------------------- #
# 5. WMI permanent event subscriptions
# --------------------------------------------------------------------------- #

@technique(OS, "windows.wmi_subscriptions", "WMI permanent event subscriptions (__EventFilter/__EventConsumer)")
def wmi_subscriptions(report: Report) -> None:
    if os.name != "nt":
        report.add(Finding("windows.wmi_subscriptions", "WMI event subscriptions", Severity.INFO,
                            "root\\subscription", "skipped (not on Windows)", OS))
        return
    ps_cmd = (
        "Get-WmiObject -Namespace root\\subscription -Class __EventConsumer | "
        "Select-Object -Property __CLASS,Name,CommandLineTemplate,ScriptFileName,ScriptText | "
        "ConvertTo-Json -Compress"
    )
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd],
                              capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        report.add_error("windows.wmi_subscriptions", str(exc))
        return
    text = (out.stdout or "").strip()
    if not text or text == "null":
        report.add(Finding("windows.wmi_subscriptions", "WMI event consumers", Severity.CLEAN,
                            "root\\subscription", "no permanent consumers", OS))
        return
    # one or many consumers -- treat every CommandLineTemplate/ScriptText hit as CRITICAL,
    # this mechanism is almost never used legitimately outside SCCM/enterprise tooling
    report.add(Finding("windows.wmi_subscriptions", "WMI permanent event consumer", Severity.CRITICAL,
                        "root\\subscription:__EventConsumer", text[:1500], OS))


# --------------------------------------------------------------------------- #
# 6. AppInit_DLLs
# --------------------------------------------------------------------------- #

@technique(OS, "windows.appinit_dlls", "AppInit_DLLs (loaded into every GUI process)")
def appinit_dlls(report: Report) -> None:
    if not _WINREG_OK:
        return _report_unavailable(report, "windows.appinit_dlls", "AppInit_DLLs")
    subkey = r"Software\Microsoft\Windows NT\CurrentVersion\Windows"
    value = ""
    for name, data in _iter_values("HKLM", subkey):
        if name == "AppInit_DLLs":
            value = str(data)
    if value.strip():
        report.add(Finding("windows.appinit_dlls", "AppInit_DLLs set", Severity.CRITICAL,
                            f"HKLM\\{subkey}\\AppInit_DLLs", value, OS))
    else:
        report.add(Finding("windows.appinit_dlls", "AppInit_DLLs", Severity.CLEAN,
                            f"HKLM\\{subkey}", "empty", OS))


# --------------------------------------------------------------------------- #
# 7. Image File Execution Options (debugger hijack)
# --------------------------------------------------------------------------- #

@technique(OS, "windows.ifeo_debugger", "Image File Execution Options Debugger hijack")
def ifeo_debugger(report: Report) -> None:
    if not _WINREG_OK:
        return _report_unavailable(report, "windows.ifeo_debugger", "IFEO Debugger hijack")
    base = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    any_found = False
    for exe_name in _iter_subkeys("HKLM", base):
        subkey = f"{base}\\{exe_name}"
        for name, data in _iter_values("HKLM", subkey):
            if name.lower() == "debugger":
                any_found = True
                report.add(Finding("windows.ifeo_debugger", f"IFEO Debugger on {exe_name}",
                                    Severity.CRITICAL, subkey, str(data), OS))
    if not any_found:
        report.add(Finding("windows.ifeo_debugger", "IFEO Debugger hijack", Severity.CLEAN,
                            base, "no Debugger values set", OS))


# --------------------------------------------------------------------------- #
# 8. Winlogon Shell / Userinit
# --------------------------------------------------------------------------- #

@technique(OS, "windows.winlogon", "Winlogon Shell/Userinit hijack")
def winlogon(report: Report) -> None:
    if not _WINREG_OK:
        return _report_unavailable(report, "windows.winlogon", "Winlogon Shell/Userinit")
    subkey = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    expected_shell = "explorer.exe"
    expected_userinit = r"c:\windows\system32\userinit.exe,"
    any_flagged = False
    for name, data in _iter_values("HKLM", subkey):
        sdata = str(data)
        if name.lower() == "shell" and sdata.strip().lower() != expected_shell:
            any_flagged = True
            report.add(Finding("windows.winlogon", "Winlogon Shell modified", Severity.CRITICAL,
                                f"HKLM\\{subkey}\\Shell", sdata, OS))
        elif name.lower() == "userinit" and not sdata.lower().startswith(expected_userinit):
            any_flagged = True
            report.add(Finding("windows.winlogon", "Winlogon Userinit modified", Severity.CRITICAL,
                                f"HKLM\\{subkey}\\Userinit", sdata, OS))
    if not any_flagged:
        report.add(Finding("windows.winlogon", "Winlogon Shell/Userinit", Severity.CLEAN,
                            subkey, "standard values (or key absent)", OS))


# --------------------------------------------------------------------------- #
# 9. LSA Security/Authentication Packages
# --------------------------------------------------------------------------- #

@technique(OS, "windows.lsa_packages", "LSA Security/Authentication Packages (credential theft persistence)")
def lsa_packages(report: Report) -> None:
    if not _WINREG_OK:
        return _report_unavailable(report, "windows.lsa_packages", "LSA Packages")
    subkey = r"SYSTEM\CurrentControlSet\Control\Lsa"
    interesting = {"Security Packages", "Authentication Packages", "Notification Packages"}
    any_found = False
    for name, data in _iter_values("HKLM", subkey):
        if name in interesting:
            entries = [e for e in str(data).split("\x00") if e and e.lower() not in ("", "msv1_0", "kerberos",
                                                                                       "negoexts", "pku2u", "wdigest",
                                                                                       "rassfm")]
            if entries:
                any_found = True
                report.add(Finding("windows.lsa_packages", f"Custom {name}", Severity.CRITICAL,
                                    f"HKLM\\{subkey}\\{name}", ", ".join(entries), OS))
    if not any_found:
        report.add(Finding("windows.lsa_packages", "LSA Packages", Severity.CLEAN,
                            subkey, "only default packages loaded", OS))


# --------------------------------------------------------------------------- #
# 10. BITS jobs
# --------------------------------------------------------------------------- #

@technique(OS, "windows.bits_jobs", "BITS jobs (Background Intelligent Transfer Service)")
def bits_jobs(report: Report) -> None:
    if os.name != "nt":
        report.add(Finding("windows.bits_jobs", "BITS jobs", Severity.INFO, "bitsadmin", "skipped (not on Windows)", OS))
        return
    try:
        out = subprocess.run(["bitsadmin", "/list", "/allusers", "/verbose"],
                              capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        report.add_error("windows.bits_jobs", str(exc))
        return
    text = out.stdout or ""
    if "DISPLAY:" not in text:
        report.add(Finding("windows.bits_jobs", "BITS jobs", Severity.CLEAN, "bitsadmin /list", "no active jobs", OS))
        return
    report.add(Finding("windows.bits_jobs", "Active BITS job(s) found", Severity.SUSPICIOUS,
                        "bitsadmin /list /allusers /verbose", text[:1500], OS))


# --------------------------------------------------------------------------- #
# 11. Active Setup
# --------------------------------------------------------------------------- #

@technique(OS, "windows.active_setup", "Active Setup StubPath (runs once per user at logon)")
def active_setup(report: Report) -> None:
    if not _WINREG_OK:
        return _report_unavailable(report, "windows.active_setup", "Active Setup")
    base = r"Software\Microsoft\Active Setup\Installed Components"
    any_found = False
    for comp_id in _iter_subkeys("HKLM", base):
        subkey = f"{base}\\{comp_id}"
        for name, data in _iter_values("HKLM", subkey):
            if name.lower() == "stubpath":
                any_found = True
                sev = classify(subkey, str(data), default=Severity.LOW)
                report.add(Finding("windows.active_setup", f"Active Setup component {comp_id}",
                                    sev, subkey, str(data), OS))
    if not any_found:
        report.add(Finding("windows.active_setup", "Active Setup", Severity.CLEAN, base, "no StubPath entries", OS))


# --------------------------------------------------------------------------- #
# 12. Print Monitors
# --------------------------------------------------------------------------- #

@technique(OS, "windows.print_monitors", "Print Monitors (loaded into SYSTEM spooler process)")
def print_monitors(report: Report) -> None:
    if not _WINREG_OK:
        return _report_unavailable(report, "windows.print_monitors", "Print Monitors")
    base = r"SYSTEM\CurrentControlSet\Control\Print\Monitors"
    any_flagged = False
    for monitor in _iter_subkeys("HKLM", base):
        subkey = f"{base}\\{monitor}"
        for name, data in _iter_values("HKLM", subkey):
            if name.lower() == "driver":
                low = str(data).lower()
                if not low.startswith(("c:\\windows\\system32", "localspl.dll", "tcpmon.dll", "usbmon.dll",
                                        "pdfmon.dll", "wsdmon.dll")):
                    any_flagged = True
                    report.add(Finding("windows.print_monitors", f"Non-standard print monitor: {monitor}",
                                        Severity.CRITICAL, subkey, str(data), OS))
    if not any_flagged:
        report.add(Finding("windows.print_monitors", "Print Monitors", Severity.CLEAN, base,
                            "all monitors are stock Windows DLLs", OS))


# --------------------------------------------------------------------------- #
# 13. Simplified COM hijack (HKCU CLSID shadowing HKLM)
# --------------------------------------------------------------------------- #

@technique(OS, "windows.com_hijack", "COM hijack via HKCU CLSID shadowing a system-wide CLSID")
def com_hijack(report: Report) -> None:
    if not _WINREG_OK:
        return _report_unavailable(report, "windows.com_hijack", "COM hijack")
    base_hkcu = r"Software\Classes\CLSID"
    any_found = False
    for clsid in _iter_subkeys("HKCU", base_hkcu):
        hkcu_subkey = f"{base_hkcu}\\{clsid}\\InprocServer32"
        if not _key_exists("HKCU", hkcu_subkey):
            continue
        hklm_subkey = rf"SOFTWARE\Classes\CLSID\{clsid}"
        if _key_exists("HKLM", hklm_subkey):
            # legit CLSID that also exists system-wide, but user has overridden it -- classic hijack pattern
            dll_path = ""
            for name, data in _iter_values("HKCU", hkcu_subkey):
                if name == "":
                    dll_path = str(data)
            any_found = True
            report.add(Finding("windows.com_hijack", f"HKCU override of system CLSID {clsid}",
                                Severity.CRITICAL, f"HKCU\\{hkcu_subkey}", dll_path, OS))
    if not any_found:
        report.add(Finding("windows.com_hijack", "COM hijack (HKCU CLSID shadowing)", Severity.CLEAN,
                            base_hkcu, "no HKCU CLSIDs shadowing HKLM-registered classes", OS))
