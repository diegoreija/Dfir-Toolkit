"""
Linux persistence techniques.

Coverage: cron (user/system/cron.d/anacron), systemd (services + timers,
system + user scope), legacy init (init.d, rc.local), shell profile
hijacking, LD_PRELOAD, udev rules, PAM module tampering, SSH-based
persistence (authorized_keys, AuthorizedKeysCommand, sshd_config overrides),
kernel module autoload, D-Bus services, APT/DPKG hooks, polkit rules,
systemd generators, and cron via at/batch.
"""

from __future__ import annotations

import glob
import os
import pwd
import re
import stat

from ..core import Finding, Report, Severity
from .base import classify, command_is_suspicious, list_dir, path_is_suspicious, safe_read, technique

OS = "linux"


def _all_home_dirs():
    homes = []
    try:
        for entry in pwd.getpwall():
            if entry.pw_dir and os.path.isdir(entry.pw_dir):
                homes.append((entry.pw_name, entry.pw_dir))
    except Exception:
        pass
    return homes


# --------------------------------------------------------------------------- #
# 1. Cron
# --------------------------------------------------------------------------- #

@technique(OS, "linux.cron.system", "System-wide crontab (/etc/crontab, /etc/cron.d/*)")
def cron_system(report: Report) -> None:
    paths = ["/etc/crontab"] + glob.glob("/etc/cron.d/*")
    found = False
    for p in paths:
        content = safe_read(p)
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            found = True
            sev = classify(p, line, default=Severity.LOW)
            report.add(Finding("linux.cron.system", "System crontab entry", sev, p, line, OS))
    if not found:
        report.add(Finding("linux.cron.system", "System crontab entry", Severity.CLEAN,
                            "/etc/crontab, /etc/cron.d/*", "no entries", OS))


@technique(OS, "linux.cron.periodic_dirs", "cron.{hourly,daily,weekly,monthly} scripts")
def cron_periodic(report: Report) -> None:
    any_found = False
    for period in ("hourly", "daily", "weekly", "monthly"):
        d = f"/etc/cron.{period}"
        for fname in list_dir(d):
            fpath = os.path.join(d, fname)
            if not os.path.isfile(fpath):
                continue
            any_found = True
            content = safe_read(fpath, 2000)
            sev = classify(fpath, content, default=Severity.LOW)
            report.add(Finding("linux.cron.periodic_dirs", f"cron.{period} script", sev,
                                fpath, content[:300], OS))
    if not any_found:
        report.add(Finding("linux.cron.periodic_dirs", "cron.{hourly,daily,weekly,monthly}",
                            Severity.CLEAN, "/etc/cron.*", "no entries", OS))


@technique(OS, "linux.cron.user", "Per-user crontabs")
def cron_user(report: Report) -> None:
    found = False
    for var_dir in ("/var/spool/cron/crontabs", "/var/spool/cron"):
        for user in list_dir(var_dir):
            fpath = os.path.join(var_dir, user)
            if not os.path.isfile(fpath):
                continue
            content = safe_read(fpath)
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                found = True
                sev = classify(fpath, line, default=Severity.LOW)
                report.add(Finding("linux.cron.user", f"User crontab ({user})", sev, fpath, line, OS))
    if not found:
        report.add(Finding("linux.cron.user", "Per-user crontabs", Severity.CLEAN,
                            "/var/spool/cron", "no entries", OS))


@technique(OS, "linux.cron.at", "Pending at/batch jobs")
def at_jobs(report: Report) -> None:
    spool = "/var/spool/cron/atjobs"
    jobs = [f for f in list_dir(spool) if not f.startswith(".")]
    if not jobs:
        report.add(Finding("linux.cron.at", "at/batch jobs", Severity.CLEAN, spool, "no jobs queued", OS))
        return
    for j in jobs:
        fpath = os.path.join(spool, j)
        content = safe_read(fpath, 2000)
        sev = classify(fpath, content, default=Severity.SUSPICIOUS)
        report.add(Finding("linux.cron.at", "Queued at job", sev, fpath, content[:300], OS))


# --------------------------------------------------------------------------- #
# 2. systemd
# --------------------------------------------------------------------------- #

SYSTEMD_SYSTEM_DIRS = [
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
]


@technique(OS, "linux.systemd.units", "Enabled systemd services/timers (system scope)")
def systemd_units(report: Report) -> None:
    seen = set()
    any_found = False
    for base in SYSTEMD_SYSTEM_DIRS:
        for unit_file in glob.glob(os.path.join(base, "*.service")) + glob.glob(os.path.join(base, "*.timer")):
            name = os.path.basename(unit_file)
            real = os.path.realpath(unit_file)
            key = (name, real)
            if key in seen:
                continue
            seen.add(key)
            content = safe_read(unit_file, 4000)
            exec_lines = [l for l in content.splitlines() if l.strip().lower().startswith(("execstart", "execstartpre"))]
            detail = "\n".join(exec_lines) if exec_lines else content[:300]
            is_link = os.path.islink(unit_file) or "/etc/systemd/system" in unit_file
            # units enabled via symlinks under multi-user.target.wants etc are the
            # strongest persistence signal
            default_sev = Severity.LOW
            sev = classify(unit_file, detail, default=default_sev)
            any_found = True
            report.add(Finding("linux.systemd.units", f"systemd unit: {name}", sev, unit_file, detail, OS))
    # .wants/.requires symlink forests are the actual "this runs at boot" proof
    for wants_dir in glob.glob("/etc/systemd/system/*.wants") + glob.glob("/etc/systemd/system/*.requires"):
        for link in list_dir(wants_dir):
            lp = os.path.join(wants_dir, link)
            if os.path.islink(lp):
                target = os.path.realpath(lp)
                sev = classify(lp, target, default=Severity.LOW)
                report.add(Finding("linux.systemd.units", f"Enabled via {os.path.basename(wants_dir)}",
                                    sev, lp, f"-> {target}", OS))
    if not any_found:
        report.add(Finding("linux.systemd.units", "systemd units", Severity.CLEAN,
                            "/etc/systemd/system", "no custom units found", OS))


@technique(OS, "linux.systemd.user_units", "User-scope systemd units (per-user persistence)")
def systemd_user_units(report: Report) -> None:
    any_found = False
    for user, home in _all_home_dirs():
        d = os.path.join(home, ".config", "systemd", "user")
        for unit_file in glob.glob(os.path.join(d, "*.service")) + glob.glob(os.path.join(d, "*.timer")):
            any_found = True
            content = safe_read(unit_file, 2000)
            sev = classify(unit_file, content, default=Severity.LOW)
            report.add(Finding("linux.systemd.user_units", f"User systemd unit ({user})",
                                sev, unit_file, content[:300], OS))
    if not any_found:
        report.add(Finding("linux.systemd.user_units", "User systemd units", Severity.CLEAN,
                            "~/.config/systemd/user", "no entries", OS))


@technique(OS, "linux.systemd.generators", "systemd generators (run at every boot/reload)")
def systemd_generators(report: Report) -> None:
    dirs = ["/etc/systemd/system-generators", "/usr/local/lib/systemd/system-generators"]
    any_found = False
    for d in dirs:
        for f in list_dir(d):
            fpath = os.path.join(d, f)
            any_found = True
            # generators outside the stock /lib path are unusual by definition
            report.add(Finding("linux.systemd.generators", "Custom systemd generator",
                                Severity.SUSPICIOUS, fpath, "non-standard generator path", OS))
    if not any_found:
        report.add(Finding("linux.systemd.generators", "systemd generators", Severity.CLEAN,
                            "/etc/systemd/system-generators", "no custom generators", OS))


# --------------------------------------------------------------------------- #
# 3. Legacy init / rc.local
# --------------------------------------------------------------------------- #

@technique(OS, "linux.initd", "/etc/init.d scripts + rc*.d symlinks")
def init_d(report: Report) -> None:
    any_found = False
    for f in list_dir("/etc/init.d"):
        fpath = os.path.join("/etc/init.d", f)
        if not os.path.isfile(fpath) or not os.access(fpath, os.X_OK):
            continue
        any_found = True
        content = safe_read(fpath, 1500)
        sev = classify(fpath, content, default=Severity.LOW)
        report.add(Finding("linux.initd", "init.d script", sev, fpath, content[:200], OS))
    if not any_found:
        report.add(Finding("linux.initd", "/etc/init.d", Severity.CLEAN, "/etc/init.d", "no scripts", OS))


@technique(OS, "linux.rclocal", "/etc/rc.local")
def rc_local(report: Report) -> None:
    content = safe_read("/etc/rc.local")
    meaningful = [l for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
    if not meaningful:
        report.add(Finding("linux.rclocal", "/etc/rc.local", Severity.CLEAN, "/etc/rc.local", "empty/default", OS))
        return
    for line in meaningful:
        sev = classify("/etc/rc.local", line, default=Severity.SUSPICIOUS)
        report.add(Finding("linux.rclocal", "/etc/rc.local command", sev, "/etc/rc.local", line, OS))


# --------------------------------------------------------------------------- #
# 4. Shell profile hijacking
# --------------------------------------------------------------------------- #

PROFILE_FILES = [
    ".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv",
]

SUSPICIOUS_PROFILE_PATTERN = re.compile(
    r"(curl|wget|nc\s|/dev/tcp/|base64|chmod\s+\+x|LD_PRELOAD=|eval\s*\(|python -c)",
    re.IGNORECASE,
)


@technique(OS, "linux.shell_profiles", "~/.bashrc, ~/.profile, /etc/profile.d/* hijacking")
def shell_profiles(report: Report) -> None:
    any_flagged = False
    for user, home in _all_home_dirs():
        for fname in PROFILE_FILES:
            fpath = os.path.join(home, fname)
            if not os.path.isfile(fpath):
                continue
            content = safe_read(fpath)
            hits = [l for l in content.splitlines() if SUSPICIOUS_PROFILE_PATTERN.search(l)]
            for h in hits:
                any_flagged = True
                sev = classify(fpath, h, default=Severity.SUSPICIOUS)
                report.add(Finding("linux.shell_profiles", f"Suspicious line in {fname} ({user})",
                                    sev, fpath, h.strip(), OS))
    for fpath in glob.glob("/etc/profile.d/*.sh"):
        content = safe_read(fpath, 2000)
        sev = classify(fpath, content, default=Severity.LOW)
        report.add(Finding("linux.shell_profiles", "System profile.d script", sev, fpath, content[:200], OS))
        any_flagged = True
    if not any_flagged:
        report.add(Finding("linux.shell_profiles", "Shell profiles", Severity.CLEAN,
                            "~/.bashrc, /etc/profile.d", "nothing suspicious found", OS))


# --------------------------------------------------------------------------- #
# 5. LD_PRELOAD / shared library hijack
# --------------------------------------------------------------------------- #

@technique(OS, "linux.ld_preload", "/etc/ld.so.preload + LD_PRELOAD in environment files")
def ld_preload(report: Report) -> None:
    content = safe_read("/etc/ld.so.preload")
    if content.strip():
        report.add(Finding("linux.ld_preload", "Global LD_PRELOAD (ld.so.preload)",
                            Severity.CRITICAL, "/etc/ld.so.preload", content.strip(), OS))
    else:
        report.add(Finding("linux.ld_preload", "Global LD_PRELOAD", Severity.CLEAN,
                            "/etc/ld.so.preload", "empty/absent", OS))

    for envf in ["/etc/environment"] + glob.glob("/etc/profile.d/*.sh"):
        content = safe_read(envf, 2000)
        for line in content.splitlines():
            if "LD_PRELOAD" in line:
                report.add(Finding("linux.ld_preload", "LD_PRELOAD set in env file",
                                    Severity.CRITICAL, envf, line.strip(), OS))


# --------------------------------------------------------------------------- #
# 6. udev rules
# --------------------------------------------------------------------------- #

@technique(OS, "linux.udev", "Custom udev rules (RUN+= triggers on device events)")
def udev_rules(report: Report) -> None:
    any_found = False
    for fpath in glob.glob("/etc/udev/rules.d/*.rules") + glob.glob("/lib/udev/rules.d/*.rules"):
        content = safe_read(fpath, 4000)
        run_lines = [l for l in content.splitlines() if "RUN+=" in l or "RUN=" in l]
        for line in run_lines:
            any_found = True
            sev = classify(fpath, line, default=Severity.SUSPICIOUS)
            report.add(Finding("linux.udev", "udev RUN+= rule", sev, fpath, line.strip(), OS))
    if not any_found:
        report.add(Finding("linux.udev", "udev rules", Severity.CLEAN,
                            "/etc/udev/rules.d", "no RUN+= triggers", OS))


# --------------------------------------------------------------------------- #
# 7. PAM
# --------------------------------------------------------------------------- #

@technique(OS, "linux.pam", "PAM module tampering (/etc/pam.d/*)")
def pam_modules(report: Report) -> None:
    any_flagged = False
    known_dirs = {"/lib/security", "/lib64/security", "/usr/lib/security", "/usr/lib64/security",
                  "/usr/lib/x86_64-linux-gnu/security"}
    for fpath in glob.glob("/etc/pam.d/*"):
        content = safe_read(fpath, 3000)
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.search(r"\s(/\S*\.so\S*)", line)
            if m:
                so_path = m.group(1)
                so_dir = os.path.dirname(so_path)
                if so_dir and so_dir not in known_dirs:
                    any_flagged = True
                    report.add(Finding("linux.pam", f"Non-standard PAM module in {os.path.basename(fpath)}",
                                        Severity.CRITICAL, fpath, line, OS))
    if not any_flagged:
        report.add(Finding("linux.pam", "PAM modules", Severity.CLEAN,
                            "/etc/pam.d", "all modules load from standard paths", OS))


# --------------------------------------------------------------------------- #
# 8. SSH-based persistence
# --------------------------------------------------------------------------- #

@technique(OS, "linux.ssh.authorized_keys", "authorized_keys across all user homes")
def ssh_authorized_keys(report: Report) -> None:
    any_found = False
    for user, home in _all_home_dirs():
        for fname in ("authorized_keys", "authorized_keys2"):
            fpath = os.path.join(home, ".ssh", fname)
            content = safe_read(fpath)
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                any_found = True
                comment = line.split()[-1] if len(line.split()) >= 3 else "(no comment)"
                report.add(Finding("linux.ssh.authorized_keys", f"SSH authorized key ({user})",
                                    Severity.LOW, fpath, f"comment/tag: {comment}", OS))
    if not any_found:
        report.add(Finding("linux.ssh.authorized_keys", "SSH authorized_keys", Severity.CLEAN,
                            "~/.ssh/authorized_keys", "no keys found", OS))


@technique(OS, "linux.ssh.sshd_config", "sshd_config persistence hooks (AuthorizedKeysCommand, ForceCommand)")
def sshd_config(report: Report) -> None:
    content = safe_read("/etc/ssh/sshd_config")
    hits = [l for l in content.splitlines()
            if re.match(r"\s*(AuthorizedKeysCommand|ForceCommand|Match)\b", l, re.IGNORECASE)]
    if not hits:
        report.add(Finding("linux.ssh.sshd_config", "sshd_config hooks", Severity.CLEAN,
                            "/etc/ssh/sshd_config", "no AuthorizedKeysCommand/ForceCommand/Match blocks", OS))
        return
    for h in hits:
        report.add(Finding("linux.ssh.sshd_config", "sshd_config directive", Severity.SUSPICIOUS,
                            "/etc/ssh/sshd_config", h.strip(), OS))


# --------------------------------------------------------------------------- #
# 9. Kernel modules
# --------------------------------------------------------------------------- #

@technique(OS, "linux.kernel_modules", "Autoloaded kernel modules (/etc/modules-load.d, /etc/modules)")
def kernel_modules(report: Report) -> None:
    any_found = False
    sources = ["/etc/modules"] + glob.glob("/etc/modules-load.d/*.conf")
    for src in sources:
        content = safe_read(src)
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            any_found = True
            report.add(Finding("linux.kernel_modules", "Autoloaded kernel module", Severity.LOW, src, line, OS))
    if not any_found:
        report.add(Finding("linux.kernel_modules", "Kernel module autoload", Severity.CLEAN,
                            "/etc/modules-load.d", "no custom entries", OS))


# --------------------------------------------------------------------------- #
# 10. D-Bus services
# --------------------------------------------------------------------------- #

@technique(OS, "linux.dbus", "D-Bus auto-activated services")
def dbus_services(report: Report) -> None:
    any_found = False
    for d in ("/usr/share/dbus-1/system-services", "/etc/dbus-1/system-services"):
        for fname in list_dir(d):
            fpath = os.path.join(d, fname)
            content = safe_read(fpath, 1000)
            exec_line = next((l for l in content.splitlines() if l.strip().lower().startswith("exec=")), "")
            standard_prefixes = ("exec=/usr", "exec=/lib", "exec=/bin", "exec=/sbin")
            if exec_line and not exec_line.lower().startswith(standard_prefixes):
                any_found = True
                report.add(Finding("linux.dbus", "D-Bus service with non-standard Exec path",
                                    Severity.SUSPICIOUS, fpath, exec_line, OS))
    if not any_found:
        report.add(Finding("linux.dbus", "D-Bus services", Severity.CLEAN,
                            "/usr/share/dbus-1/system-services", "nothing unusual", OS))


# --------------------------------------------------------------------------- #
# 11. APT/DPKG hooks
# --------------------------------------------------------------------------- #

@technique(OS, "linux.apt_hooks", "APT/DPKG hooks (run on every package operation)")
def apt_hooks(report: Report) -> None:
    any_found = False
    for d in ("/etc/apt/apt.conf.d", "/etc/dpkg/dpkg.cfg.d"):
        for fname in list_dir(d):
            fpath = os.path.join(d, fname)
            content = safe_read(fpath, 2000)
            if re.search(r"DPkg::(Pre|Post)-Invoke", content):
                any_found = True
                sev = classify(fpath, content, default=Severity.SUSPICIOUS)
                report.add(Finding("linux.apt_hooks", "APT Pre/Post-Invoke hook", sev, fpath, content[:300], OS))
    if not any_found:
        report.add(Finding("linux.apt_hooks", "APT/DPKG hooks", Severity.CLEAN,
                            "/etc/apt/apt.conf.d", "no Pre/Post-Invoke hooks", OS))


# --------------------------------------------------------------------------- #
# 12. polkit rules
# --------------------------------------------------------------------------- #

@technique(OS, "linux.polkit", "polkit rules granting passwordless privilege")
def polkit_rules(report: Report) -> None:
    any_found = False
    for fpath in glob.glob("/etc/polkit-1/rules.d/*.rules") + glob.glob("/usr/share/polkit-1/rules.d/*.rules"):
        content = safe_read(fpath, 4000)
        if re.search(r"YES|AUTH_ADMIN_KEEP", content):
            any_found = True
            report.add(Finding("linux.polkit", "polkit rule granting elevated access",
                                Severity.SUSPICIOUS, fpath, content[:300], OS))
    if not any_found:
        report.add(Finding("linux.polkit", "polkit rules", Severity.CLEAN,
                            "/etc/polkit-1/rules.d", "nothing unusual", OS))


# --------------------------------------------------------------------------- #
# 13. World-writable persistence paths (enabler, not persistence itself)
# --------------------------------------------------------------------------- #

@technique(OS, "linux.writable_persistence_paths", "World-writable files inside persistence-relevant dirs")
def writable_persistence_paths(report: Report) -> None:
    check_dirs = ["/etc/cron.d", "/etc/systemd/system", "/etc/init.d", "/etc/profile.d"]
    any_found = False
    for d in check_dirs:
        for fname in list_dir(d):
            fpath = os.path.join(d, fname)
            try:
                st = os.stat(fpath)
            except OSError:
                continue
            if st.st_mode & stat.S_IWOTH:
                any_found = True
                report.add(Finding("linux.writable_persistence_paths",
                                    "World-writable persistence file", Severity.CRITICAL,
                                    fpath, f"mode={oct(stat.S_IMODE(st.st_mode))}", OS))
    if not any_found:
        report.add(Finding("linux.writable_persistence_paths", "World-writable persistence paths",
                            Severity.CLEAN, ", ".join(check_dirs), "none found", OS))
