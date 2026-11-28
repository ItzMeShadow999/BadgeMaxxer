"""Installs the system programs the BadgeMaxxer streamer needs (Node.js, npm, ffmpeg).

Used by BadgeMaxxer.py right before the streamer starts. Only installs what is missing, asks for
admin/root through the normal OS prompt (UAC on Windows, sudo/pkexec on Linux), and refreshes PATH
afterwards so the streamer can be launched in the same run without restarting the terminal.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Callable

Log = Callable[[str, str], None]
Runner = Callable[..., subprocess.CompletedProcess]

NODESOURCE_MAJOR = "24"
WIN_NODE_ID = "OpenJS.NodeJS.LTS"
WIN_FFMPEG_ID = "Gyan.FFmpeg"
MANUAL_HELP = {
    "node": "Node.js: https://nodejs.org (LTS)",
    "npm": "npm comes with Node.js: https://nodejs.org (LTS)",
    "ffmpeg": "ffmpeg: https://ffmpeg.org/download.html",
}


def _runs(cmd: list[str]) -> bool:
    try:
        return subprocess.run(cmd, capture_output=True, timeout=30).returncode == 0
    except Exception:
        return False


def _node_version() -> tuple[int, ...] | None:
    node = shutil.which("node")
    if not node:
        return None
    try:
        done = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=15)
    except Exception:
        return None
    if done.returncode != 0:
        return None
    try:
        return tuple(int(p) for p in done.stdout.strip().lstrip("v").split(".")[:3])
    except ValueError:
        return ()


def missing(node_min: tuple[int, int]) -> list[str]:
    need: list[str] = []
    version = _node_version()
    if version is None or (version and version[:2] < tuple(node_min)):
        need.append("node")
    elif not shutil.which("npm"):
        need.append("npm")
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg or not _runs([ffmpeg, "-version"]):
        need.append("ffmpeg")
    return need


def refresh_path() -> None:
    parts = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    extra: list[str] = []
    if os.name == "nt":
        try:
            import winreg
            for root, sub in ((winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
                              (winreg.HKEY_CURRENT_USER, "Environment")):
                try:
                    with winreg.OpenKey(root, sub) as key:
                        value, _ = winreg.QueryValueEx(key, "Path")
                    extra += [os.path.expandvars(p) for p in str(value).split(";") if p]
                except OSError:
                    pass
        except ImportError:
            pass
        local = os.environ.get("LOCALAPPDATA", "")
        extra += [r"C:\Program Files\nodejs", r"C:\ProgramData\chocolatey\bin"]
        if local:
            extra.append(os.path.join(local, "Microsoft", "WinGet", "Links"))
    else:
        extra += ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"]
    seen = {p.lower() if os.name == "nt" else p for p in parts}
    for p in extra:
        key = p.lower() if os.name == "nt" else p
        if p and key not in seen and os.path.isdir(p):
            parts.append(p)
            seen.add(key)
    os.environ["PATH"] = os.pathsep.join(parts)


def _run(runner: Runner | None, label: str, cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    if runner is not None:
        return runner(label, cmd, **kwargs)
    kwargs.pop("parser", None)
    kwargs.pop("watch_file", None)
    return subprocess.run(cmd, **kwargs)


def _set(loader, frac: float, sub: str = "") -> None:
    loader.indeterminate = False
    loader.pct = max(loader.pct, min(frac, 0.99))
    if sub:
        loader.sub = sub


_APT_STATUS = re.compile(r"^(dlstatus|pmstatus):[^:]*:([\d.]+):(.*)$")


def parse_apt(line: str, loader) -> None:
    m = _APT_STATUS.match(line)
    if m:
        frac = float(m.group(2)) / 100
        _set(loader, frac * 0.5 if m.group(1) == "dlstatus" else 0.5 + frac * 0.5, m.group(3).strip())


_COUNTER = re.compile(r"^\(\s*(\d+)/(\d+)\)\s+((?:installing|upgrading)\b.*)$", re.I)


def parse_counter(line: str, loader) -> None:
    m = _COUNTER.match(line)
    if m:
        _set(loader, (int(m.group(1)) - 1) / int(m.group(2)), m.group(3))


_DNF_DOWNLOAD = re.compile(r"^(?:\((\d+)/(\d+)\):|\[(\d+)/(\d+)\](?!\s+(?:installing|upgrading)\b))\s*(\S+)", re.I)
_DNF_INSTALL = re.compile(r"^(?:\[(\d+)/(\d+)\]\s+(?:installing|upgrading)\b\s*(\S*)|(?:installing|upgrading)\s*:\s*(\S+).*?\s(\d+)/(\d+)\s*$)", re.I)


def parse_dnf(line: str, loader) -> None:
    m = _DNF_INSTALL.match(line)
    if m:
        n, total = (m.group(1), m.group(2)) if m.group(1) else (m.group(5), m.group(6))
        _set(loader, 0.5 + (int(n) - 1) / int(total) * 0.5, f"installing {m.group(3) or m.group(4) or ''}".strip())
        return
    m = _DNF_DOWNLOAD.match(line)
    if m:
        n, total = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        _set(loader, (int(n) - 1) / int(total) * 0.5, f"downloading {m.group(5)}")


def brew_parser(total: int):
    state = {"started": 0, "done": 0}

    def feed(line: str, loader) -> None:
        if line.startswith("==> Installing ") and not line.startswith("==> Installing dependencies for"):
            state["started"] += 1
            sub = line.lstrip("=> ")
        elif line.startswith("🍺") or ("/Cellar/" in line and " files, " in line):
            state["done"] += 1
            sub = ""
        else:
            return
        if total:
            _set(loader, (state["done"] + 0.5 * (state["started"] > state["done"])) / total, sub)

    return feed


def _brew_total(brew: str, pkgs: list[str]) -> int:
    try:
        deps = subprocess.run([brew, "deps", "--formula", "--union", *pkgs], capture_output=True, text=True, timeout=60).stdout.split()
        have = set(subprocess.run([brew, "list", "--formula", "-1"], capture_output=True, text=True, timeout=60).stdout.split())
    except Exception:
        return 0
    return len((set(deps) | set(pkgs)) - have)


_STEP = re.compile(r"^##(STEP|DONE) (\d+)/(\d+)(?: (.+))?$")
_SIZES = re.compile(r"([\d.]+)\s*(KB|MB|GB)\s*/\s*([\d.]+)\s*(KB|MB|GB)", re.I)
_PERCENT = re.compile(r"(\d{1,3})\s*%")
_MB = {"kb": 1 / 1024, "mb": 1.0, "gb": 1024.0}


def windows_parser():
    state = {"i": 0, "n": 1, "inner": 0.0}

    def feed(line: str, loader) -> None:
        m = _STEP.match(line)
        if m:
            state["i"], state["n"] = int(m.group(2)), int(m.group(3))
            if m.group(1) == "STEP":
                state["inner"] = 0.0
                loader.sub = f"{m.group(4)} ({state['i']}/{state['n']})"
            else:
                state["inner"] = 1.0
        elif state["i"]:
            size = _SIZES.search(line)
            pct = _PERCENT.search(line)
            if size and float(size.group(3)) > 0:
                inner = (float(size.group(1)) * _MB[size.group(2).lower()]) / (float(size.group(3)) * _MB[size.group(4).lower()])
            elif pct:
                inner = int(pct.group(1)) / 100
            else:
                return
            state["inner"] = max(state["inner"], min(inner, 0.95))
        else:
            return
        _set(loader, (state["i"] - 1 + state["inner"]) / state["n"])

    return feed


def _is_admin_windows() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _windows_script(need: list[str], log: str) -> str | None:
    want_node = "node" in need
    want_ff = "ffmpeg" in need
    jobs: list[tuple[str, str]] = []
    if shutil.which("winget"):
        flags = "--exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity"
        if want_node:
            jobs.append(("Node.js", f"winget install --id {WIN_NODE_ID} {flags}"))
        if want_ff:
            jobs.append(("ffmpeg", f"winget install --id {WIN_FFMPEG_ID} {flags}"))
    elif shutil.which("choco"):
        if want_node:
            jobs.append(("Node.js", "choco install nodejs-lts -y"))
        if want_ff:
            jobs.append(("ffmpeg", "choco install ffmpeg -y"))
    if not jobs:
        return None
    body: list[str] = []
    for i, (name, cmd) in enumerate(jobs, 1):
        body += [f"Write-Output '##STEP {i}/{len(jobs)} {name}'", cmd, f"Write-Output '##DONE {i}/{len(jobs)}'"]
    lines = [
        "$ErrorActionPreference = 'Continue'",
        "$log = '" + log.replace("'", "''") + "'",
        "& {",
        *body,
        '} *>&1 | ForEach-Object { "$_"; Add-Content -LiteralPath $log -Value "$_" -Encoding UTF8 }',
        "Start-Sleep -Seconds 2",
    ]
    return "\r\n".join(lines) + "\r\n"


def _install_windows(need: list[str], log: Log, runner: Runner | None = None) -> None:
    if "npm" in need and "node" not in need:
        need = need + ["node"]
    path = Path(tempfile.gettempdir()) / f"bm_deps_{uuid.uuid4().hex}.ps1"
    log_path = path.with_suffix(".log")
    script = _windows_script(need, str(log_path))
    if script is None:
        log("err", "Neither winget nor Chocolatey was found. Install App Installer (winget) from the Microsoft Store, "
                   "or install manually.")
        return
    label = ", ".join(need)
    path.write_text(script, encoding="utf-8")
    log_path.write_text("", encoding="utf-8")
    progress = {"parser": windows_parser(), "watch_file": str(log_path)}
    try:
        if _is_admin_windows():
            log("info", "Installing (already running as administrator)...")
            _run(runner, label, ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(path)], **progress)
        else:
            log("info", "Windows will ask for administrator permission (UAC). Approve it, an installer window opens.")
            quoted = str(path).replace("'", "''")
            launcher = (f"Start-Process powershell -Verb RunAs -Wait -ArgumentList "
                        f"'-NoProfile','-ExecutionPolicy','Bypass','-File','\"{quoted}\"'")
            _run(runner, label, ["powershell", "-NoProfile", "-Command", launcher], **progress)
    finally:
        for leftover in (path, log_path):
            try:
                leftover.unlink()
            except OSError:
                pass


def _install_macos(need: list[str], log: Log, runner: Runner | None = None) -> None:
    brew = shutil.which("brew") or next((p for p in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew") if os.path.isfile(p)), "")
    if not brew:
        log("err", 'Homebrew was not found. Install it from https://brew.sh (or run: /bin/bash -c "$(curl -fsSL '
                   'https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"), then run BadgeMaxxer again.')
        return
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        log("err", "Homebrew refuses to run as root. Start BadgeMaxxer as your normal user.")
        return
    pkgs = (["node"] if ("node" in need or "npm" in need) else []) + (["ffmpeg"] if "ffmpeg" in need else [])
    if runner is None:
        log("info", f"brew install {' '.join(pkgs)}")
    parser = brew_parser(_brew_total(brew, pkgs)) if runner is not None else None
    _run(runner, ", ".join(pkgs), [brew, "install", *pkgs], parser=parser)


def _privilege_prefix() -> list[str] | None:
    if os.geteuid() == 0:
        return []
    for tool in ("sudo", "pkexec", "doas"):
        if shutil.which(tool):
            return [tool]
    return None


def _linux_plan(need: list[str]) -> list[list[list[str]]]:
    want_node = "node" in need or "npm" in need
    want_ff = "ffmpeg" in need
    nodesource_deb = ["sh", "-c", f"curl -fsSL https://deb.nodesource.com/setup_{NODESOURCE_MAJOR}.x | bash -"]
    nodesource_rpm = ["sh", "-c", f"curl -fsSL https://rpm.nodesource.com/setup_{NODESOURCE_MAJOR}.x | bash -"]
    steps: list[list[list[str]]] = []
    if shutil.which("apt-get"):
        env = ["env", "DEBIAN_FRONTEND=noninteractive"]
        steps.append([[*env, "apt-get", "update"]])
        if want_node:
            steps.append([[*env, "apt-get", "install", "-y", "curl", "ca-certificates"]])
            steps.append([nodesource_deb])
            steps.append([[*env, "apt-get", "install", "-y", "nodejs"]])
        if want_ff:
            steps.append([[*env, "apt-get", "install", "-y", "ffmpeg"]])
    elif shutil.which("dnf") or shutil.which("yum"):
        pm = "dnf" if shutil.which("dnf") else "yum"
        if want_node:
            steps.append([[pm, "install", "-y", "curl", "ca-certificates"]])
            steps.append([nodesource_rpm])
            steps.append([[pm, "install", "-y", "nodejs"]])
        if want_ff:
            steps.append([[pm, "install", "-y", "ffmpeg"], [pm, "install", "-y", "ffmpeg-free"]])
    elif shutil.which("pacman"):
        pk = (["nodejs", "npm"] if want_node else []) + (["ffmpeg"] if want_ff else [])
        steps.append([["pacman", "-Syu", "--noconfirm", "--needed", *pk]])
    elif shutil.which("zypper"):
        pk = (["nodejs24", "npm24"] if want_node else []) + (["ffmpeg"] if want_ff else [])
        steps.append([["zypper", "--non-interactive", "install", *pk],
                      ["zypper", "--non-interactive", "install", *[p for p in pk if "node" not in p and "npm" not in p], "nodejs", "npm"]])
    elif shutil.which("apk"):
        pk = (["nodejs", "npm"] if want_node else []) + (["ffmpeg"] if want_ff else [])
        steps.append([["apk", "add", *pk]])
    return steps


_LINUX_PARSERS = {"apt-get": parse_apt, "pacman": parse_counter, "apk": parse_counter, "zypper": parse_counter,
                  "dnf": parse_dnf, "yum": parse_dnf}


def _with_progress(cmd: list[str]):
    for i, arg in enumerate(cmd):
        parser = _LINUX_PARSERS.get(arg)
        if parser:
            if arg == "apt-get":
                cmd = [*cmd[:i + 1], "-o", "APT::Status-Fd=1", *cmd[i + 1:]]
            return cmd, parser
    return cmd, None


def _install_linux(need: list[str], log: Log, runner: Runner | None = None) -> None:
    steps = _linux_plan(need)
    if not steps:
        log("err", "No supported package manager found (apt, dnf/yum, pacman, zypper, apk).")
        return
    prefix = _privilege_prefix()
    if prefix is None:
        log("err", "Root is needed but neither sudo, pkexec nor doas exists. Run BadgeMaxxer as root or install manually.")
        return
    if prefix:
        log("info", f"Using {prefix[0]}, it may ask for your password in this terminal.")
    if prefix == ["sudo"] and subprocess.run(["sudo", "-v"]).returncode != 0:
        log("err", "sudo did not accept the password, nothing was installed.")
        return
    if shutil.which("pacman") and not shutil.which("apt-get") and not shutil.which("dnf") and not shutil.which("yum"):
        log("info", "Arch: pacman -Syu also updates the rest of the system, Arch does not support installing without it.")
    label = ", ".join(need)
    for n, alternatives in enumerate(steps, 1):
        ok = False
        for cmd in alternatives:
            if runner is None:
                log("info", " ".join(cmd) if cmd[0] != "sh" else cmd[-1])
            run_cmd, parser = _with_progress(cmd) if runner is not None else (cmd, None)
            if _run(runner, f"{label} ({n}/{len(steps)})", prefix + run_cmd, parser=parser).returncode == 0:
                ok = True
                break
        if not ok:
            log("warn", "A step failed, continuing to see whether the programs are available anyway.")


def install(need: list[str], log: Log, runner: Runner | None = None) -> None:
    if sys.platform == "win32":
        _install_windows(need, log, runner)
    elif sys.platform == "darwin":
        _install_macos(need, log, runner)
    else:
        _install_linux(need, log, runner)
    refresh_path()


def manual_help(names: list[str]) -> list[str]:
    return [MANUAL_HELP[n] for n in names if n in MANUAL_HELP]
