# multios-persistence-hunter

A single persistence hunter that runs across **Windows, Linux, and macOS**,
enumerates the autostart/persistence mechanisms relevant to threat hunting
and DFIR on each platform, and classifies them by severity — instead of
dumping 400 lines of "this could theoretically be something" the way
linPEAS/WinPEAS do.

```
  __  __       _ _   _  ____   _____   ____               _     _
 |  \/  |_   _| | |_(_)/ __ \ / ____| |  _ \             (_)   | |
 | \  / | | | | | __| | |  | | (___   | |_) | ___  _ __   _ ___| |_
 | |\/| | |_| | | |_| | |  | |\___ \  |  _ < / _ \| '_ \ | / __| __|
 | |  | | |_| | | |_| | |__| |____) | | |_) | (_) | | | || \__ \ |_
 |_|  |_|\__,_|_|\__|_|\____/|_____/  |____/ \___/|_| |_||_|___/\__|

      MultiOS Persistence Hunter -- Windows / Linux / macOS

====================
  SCANNING (linux)
====================
[!] Custom systemd generator :: /etc/systemd/system-generators/systemd-gpt-auto-generator
      non-standard generator path
[!] udev RUN+= rule :: /lib/udev/rules.d/71-seat.rules
      RUN+="/usr/bin/udevadm trigger --parent-match=%p/.."
[X] Global LD_PRELOAD (ld.so.preload) :: /etc/ld.so.preload
      /tmp/.hidden/libshim.so
```

[SCREENSHOT: Full terminal output of `persistence-hunter` running against a live Linux host, showing the banner, the color-coded `[*] [+] [!] [X]` findings, and the final severity summary block]

## Why this exists

Anyone can run `autoruns` on Windows or `linpeas.sh` on Linux. What doesn't
exist — done properly — is **one tool that understands all three operating
systems under the same classification logic**, and that actually answers
the question a DFIR analyst cares about: *"what changed since the last time
I looked?"* — not "here are 300 autostart entries, good luck."

This project solves that with two building blocks:

1. **Real per-OS coverage**, not a wrapper around third-party tools — every
   technique is implemented by reading the registry, filesystem, or plist
   directly.
2. **Baseline/diff mode**: capture a snapshot of a known-good state, and
   every subsequent run flags only what's **new** (or what disappeared,
   which is a signal too — malware cleaning up after itself).

## Coverage

| OS | Techniques |
|---|---|
| **Linux** | cron (system/user/periodic/at), systemd (units + generators + user scope), init.d/rc.local, shell profile hijacking, `LD_PRELOAD`, udev rules, non-standard PAM modules, SSH-based persistence (authorized_keys, sshd_config), kernel module autoload, D-Bus services, APT/DPKG hooks, polkit rules, world-writable persistence paths |
| **Windows** | Run/RunOnce (HKLM+HKCU, 32/64-bit views), Startup folders, services with `ImagePath` outside System32, Scheduled Tasks, permanent WMI event subscriptions, `AppInit_DLLs`, IFEO Debugger hijacking, Winlogon Shell/Userinit, LSA packages, BITS jobs, Active Setup, Print Monitors, COM hijacking via HKCU CLSID shadowing |
| **macOS** | LaunchAgents/LaunchDaemons (system + user scope), Login Items, legacy StartupItems, cron, periodic scripts, Login/Logout Hooks, Folder Actions, emond rules, kernel/system extensions |

Every technique self-registers via a `@technique` decorator, so adding a new
one is a matter of writing a function — not touching the core engine.

[SCREENSHOT: Side-by-side or carousel of the three hunters — Windows Registry Editor open next to a flagged `AppInit_DLLs` finding, a macOS `~/Library/LaunchAgents` Finder view next to its matching terminal finding, and the Linux `/etc/cron.d` listing next to its finding]

## Usage

```bash
pip install -e .

# scan the current OS, print to terminal
persistence-hunter

# only what deserves attention (hides CLEAN/INFO)
persistence-hunter --quiet-clean

# export the full report
persistence-hunter --json report.json

# capture a known-good state
persistence-hunter --baseline-save baseline.json

# on the next run, compare against that state
persistence-hunter --baseline-compare baseline.json
```

Exit code `2` whenever at least one `CRITICAL` finding is present — built to
plug into a cron/scheduled task for continuous monitoring.

[SCREENSHOT: Terminal split showing `--baseline-save` on day 1, a persistence mechanism being planted (e.g. a new cron entry or registry Run key), then `--baseline-compare` on day 2 flagging it in red as "NEW SINCE BASELINE"]

## Severity levels

| Symbol | Level | Meaning |
|---|---|---|
| `[*]` | INFO | Context data, not a finding |
| `[+]` | CLEAN / LOW | Known-legitimate persistence, or a check that found nothing unusual |
| `[!]` | SUSPICIOUS | Unusual but not conclusive — needs human review |
| `[X]` | CRITICAL | Strong indicator of malicious persistence |

## Architecture

```
persistence_hunter/
├── core.py              # Finding/Severity model + the colored terminal printer
├── baseline.py           # snapshot save/compare for the diff mode
├── cli.py                 # argument parsing, OS auto-detection, orchestration
└── hunters/
    ├── base.py            # @technique registry + shared heuristics
    ├── linux.py            # 13 techniques
    ├── windows.py          # 13 techniques
    └── macos.py            # 11 techniques
```

[SCREENSHOT: VS Code / terminal view of the `hunters/` directory tree alongside one `@technique`-decorated function, to show the self-registration pattern at a glance]

## Honest limitations

- Severity heuristics are conservative by design: the tool is tuned to
  avoid false negatives over achieving zero false positives. This is a
  **triage** tool, not an automated verdict.
- The Windows and macOS hunters are written and unit-tested for their
  parsing logic, but have not yet been run against a live system of that
  OS — validating them on real Windows/macOS hosts is the next step before
  calling them production-ready.
- `--baseline-compare` is only as trustworthy as the state the first
  baseline was captured in.

## Roadmap

- [ ] Validate the Windows hunter against a live HTB/lab Windows host
- [ ] Validate the macOS hunter against a live macOS host
- [ ] Signature/hash allowlisting to reduce LOW-severity noise from known-good software
- [ ] Optional YARA-style custom rule input for org-specific baselines
