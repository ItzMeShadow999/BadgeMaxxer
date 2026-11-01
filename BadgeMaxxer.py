#!/usr/bin/env python3
from __future__ import annotations

import atexit
import base64
import codecs
import importlib
import importlib.util
import json
import os
import random
import re
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator, Sequence

def _install_package(name: str) -> bool:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", name],
            capture_output=True, text=True, timeout=300,
        )
    except Exception:
        return False
    return result.returncode == 0


def _load_crypto() -> bool:
    global AESGCM
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return True
    except ImportError:
        return False


HAS_CRYPTO = _load_crypto()
if not HAS_CRYPTO:
    print("Installing missing dependency: cryptography ...")
    if _install_package("cryptography"):
        importlib.invalidate_caches()
        HAS_CRYPTO = _load_crypto()
    print("cryptography installed." if HAS_CRYPTO else "cryptography could not be installed, continuing without encrypted audio frames.")

WORKSPACE_DIR = Path(__file__).resolve().parent
STATE_STORAGE_PATH = WORKSPACE_DIR / "session.json"
WATCHER_DIR = WORKSPACE_DIR / "Watcher"
WATCHER_SCRIPT = WATCHER_DIR / "stream_watcher.py"
WATCHER_PACKAGES = ("websockets", "davey")
DATABASE_STORAGE_PATH = WORKSPACE_DIR.parent / "data" / "games.json"

REST_IDENTITY_URL = "https://discord.com/api/v9/users/@me?with_analytics_token=true"
DISCORD_USERS_API = "https://discord.com/api/v9/users"
TELEMETRY_INGEST_URL = "https://discord.com/api/v9/science"
UPSTREAM_METRICS_URL = "https://cordapi.dolfi.es/api/v2/properties/windows"
DISCORD_CATALOG_URL = "https://cdn.discordapp.com/detectables/games.json"
GATEWAY_URL = "gateway.discord.gg"

DISPATCH_BATCH_LIMIT = 50
TIME_DEFAULT_GAMES = 3
TIME_DEFAULT_HOURS = 10.0
VARIETY_DEFAULT_HOURS = 1.0
STREAM_DEFAULT_HOURS = 1.0
NETWORK_COOLDOWN_SEC = 0.3
TOKEN_EXPIRY_THRESHOLD_SEC = 12 * 3600
TOKEN_SNIPPET = (
    "copy(((w=webpackChunkdiscord_app).push([[Symbol()],{},o=>{try{Object.values(o.c)"
    ".some(e=>e.exports?.setToken&&(w.t=e.exports.getToken()))}catch{}}]),w.t))"
)
COOKIE_HELP = (
    "How to get cf_clearance (the console cannot read it, it is an HttpOnly cookie):",
    "1. Open https://discord.com/app in your browser and log in.",
    "2. Press F12 (Ctrl+Shift+I) to open DevTools.",
    "3. Chrome/Edge: Application tab > Cookies > https://discord.com.",
    "   Firefox: Storage tab > Cookies > https://discord.com.",
    "4. Find cf_clearance and copy its Value.",
    "   Or: Network tab > reload > click any discord.com request > Request Headers > cookie.",
    "5. Paste it below as cf_clearance=VALUE, or paste the whole cookie line or a Copy as cURL (bash) of the @me request.",
    "Not in the list? Cloudflare only sets it after a challenge. Try a private window or a fresh network.",
    "It is tied to your IP and this script's User-Agent, and it expires. Use 'Refresh Credentials & Cookie' in the menu to update it.",
)
TOKEN_HELP = (
    "Or get your token from the Network tab:",
    "1. Open https://discord.com/app in your browser and log in.",
    "2. Press F12 (Ctrl+Shift+I) and open the Network tab.",
    "3. Type /api in the filter box, then click around Discord (switch a channel) to trigger requests.",
    "4. Click any request to discord.com/api (for example library, science or messages).",
    "5. Headers > Request Headers > find authorization and copy its value.",
    "Never share your token. Anyone with it has full access to the account.",
)
BACK_TO_MENU = -1.0
TERMINAL_ZOOM_OUT_STEPS = 2
TERMINAL_MIN_COLS = 150
TERMINAL_MIN_ROWS = 45

DESKTOP_CLIENT_VERSION = "1.0.9253"
DESKTOP_BUILD_IDENTIFIER = 594031
PLATFORM_BUILD_IDENTIFIER = 88414
PLATFORM_OS_REVISION = "10.0.26200"
USER_AGENT_IDENTIFIER = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) discord/1.0.9253 Chrome/148.0.7778.280 "
    "Electron/42.7.1 Safari/537.36"
)

_POWERSHELL_PE_ANALYZER = r'''
param(
  [int]$ProcessId = 0,
  [string]$Path,
  [Parameter(Mandatory = $true)][string]$UserId
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CertPubKeyHash {
  const uint X509_ASN_ENCODING = 0x00000001;
  const uint PKCS_7_ASN_ENCODING = 0x00010000;
  const uint CALG_SHA_256 = 0x0000800C;

  [StructLayout(LayoutKind.Sequential)] struct Blob { public uint cbData; public IntPtr pbData; }
  [StructLayout(LayoutKind.Sequential)] struct AlgId { public IntPtr pszObjId; public Blob Parameters; }
  [StructLayout(LayoutKind.Sequential)] struct BitBlob { public uint cbData; public IntPtr pbData; public uint cUnusedBits; }
  [StructLayout(LayoutKind.Sequential)] struct PubKeyInfo { public AlgId Algorithm; public BitBlob PublicKey; }
  [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low; public uint High; }
  [StructLayout(LayoutKind.Sequential)]
  struct CertInfo {
    public uint Version; public Blob SerialNumber; public AlgId SignatureAlgorithm; public Blob Issuer;
    public FileTime NotBefore; public FileTime NotAfter; public Blob Subject;
    public PubKeyInfo SubjectPublicKeyInfo; public BitBlob IssuerUniqueId; public BitBlob SubjectUniqueId;
    public uint ExtensionCount; public IntPtr Extensions;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct CertContext {
    public uint EncodingType; public IntPtr Encoded; public uint EncodedSize;
    public IntPtr CertInfo; public IntPtr Store;
  }

  [DllImport("crypt32.dll", SetLastError = true)]
  static extern bool CryptHashPublicKeyInfo(
    IntPtr provider, uint algid, uint flags, uint encoding, ref PubKeyInfo info, byte[] hash, ref uint hashSize);

  public static byte[] Hash(IntPtr certContext) {
    var ctx = Marshal.PtrToStructure<CertContext>(certContext);
    var info = Marshal.PtrToStructure<CertInfo>(ctx.CertInfo);
    var hash = new byte[32];
    uint hashSize = 32;
    if (!CryptHashPublicKeyInfo(IntPtr.Zero, CALG_SHA_256, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, ref info.SubjectPublicKeyInfo, hash, ref hashSize) || hashSize != 32)
      throw new InvalidOperationException("CryptHashPublicKeyInfo failed");
    return hash;
  }
}
"@

if (!$Path) {
  if (!$ProcessId) { throw "Pass -Path <exe> or -ProcessId <pid>." }
  $Path = (Get-Process -Id $ProcessId).Path
}
if (!$Path) { throw "Could not resolve executable path." }

$fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
try {
  $fileSize = [UInt64]$fs.Length
  $readSize = [int][Math]::Min($fs.Length, 0x10000)
  $buf = [byte[]]::new($readSize)
  $read = $fs.Read($buf, 0, $readSize)
  if ($read -lt 0x40) { throw "File prefix is too small." }
  if ($read -ne $readSize) { [Array]::Resize([ref]$buf, $read) }
} finally {
  $fs.Dispose()
}

if ([BitConverter]::ToUInt16($buf, 0) -ne 0x5A4D) { throw "Not an MZ executable." }
$pe = [BitConverter]::ToInt32($buf, 0x3C)
if ($pe -lt 0 -or [BitConverter]::ToUInt32($buf, $pe) -ne 0x4550) { throw "Not a PE executable." }

$fh = $pe + 4
$sections = [BitConverter]::ToUInt16($buf, $fh + 2)
$timestamp = [BitConverter]::ToUInt32($buf, $fh + 4)
$optSize = [BitConverter]::ToUInt16($buf, $fh + 16)
$opt = $fh + 20
$isPe32Plus = [BitConverter]::ToUInt16($buf, $opt) -eq 0x20B
if (!$isPe32Plus) { throw "Discord only fingerprints PE32+." }
$sizeOfImage = [BitConverter]::ToUInt32($buf, $opt + 56)

$sectionTable = $opt + $optSize
$sha256 = [Security.Cryptography.SHA256]::Create()
$headerHash = $sha256.ComputeHash([byte[]]$buf[0..($sectionTable - 1)])
$sectionHash = $sha256.ComputeHash([byte[]]$buf[$sectionTable..($sectionTable + $sections * 40 - 1)])

$machineGuid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
$machineUserHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($machineGuid + $UserId))

$sig = Get-AuthenticodeSignature -LiteralPath $Path
$signed = $sig.Status -eq "Valid" -and $sig.SignerCertificate
if ($signed) {
  $name = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
  $certHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($name) + [CertPubKeyHash]::Hash($sig.SignerCertificate.Handle))
} else {
  $certHash = [byte[]]::new(32)
}

$flags = 0
if ($signed) { $flags += 1 }
if ($isPe32Plus) { $flags += 2 }

$out = [byte[]](@(1, [byte]$flags) +
  [BitConverter]::GetBytes($fileSize) +
  [BitConverter]::GetBytes($timestamp) +
  [BitConverter]::GetBytes($sizeOfImage) +
  $headerHash + $machineUserHash + $sectionHash + $certHash)

$key = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($UserId + "https://discord.com/careers"))
for ($i = 1; $i -lt $out.Length; $i++) {
  $out[$i] = $out[$i] -bxor $key[($i - 1) -band 31]
}

[Convert]::ToBase64String($out)
'''


def extract_account_snowflake(auth_token: str) -> str:
    try:
        prefix = auth_token.split(".", 1)[0]
        padding = "=" * (-len(prefix) % 4)
        return base64.b64decode(prefix + padding).decode("utf-8")
    except Exception:
        return ""


def build_binary_signature(account_id: str, file_path: str = "", active_pid: int = 0) -> str:
    if os.name != "nt":
        raise RuntimeError("Fingerprint generation requires a Windows runtime.")
    temp_script = Path(tempfile.gettempdir()) / f"sig_gen_{uuid.uuid4().hex}.ps1"
    temp_script.write_text(_POWERSHELL_PE_ANALYZER, encoding="utf-8")
    try:
        cmd = [
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(temp_script), "-UserId", account_id
        ]
        cmd += (["-ProcessId", str(active_pid)] if active_pid else ["-Path", file_path])
        execution = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    finally:
        try:
            temp_script.unlink()
        except OSError:
            pass
    if execution.returncode != 0:
        err_msg = (execution.stderr or execution.stdout or "").strip().splitlines()
        raise RuntimeError(err_msg[-1] if err_msg else "PowerShell fingerprint generation failed.")
    lines = [line.strip() for line in execution.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("Fingerprint generator yielded empty output.")
    return lines[-1]


BANNER_ART = r"""
 ███████████                █████                   ██████   ██████
▒▒███▒▒▒▒▒███              ▒▒███                   ▒▒██████ ██████
 ▒███    ▒███  ██████    ███████   ███████  ██████  ▒███▒█████▒███   ██████   █████ █████ █████ █████  ██████  ████████
 ▒██████████  ▒▒▒▒▒███  ███▒▒███  ███▒▒███ ███▒▒███ ▒███▒▒███ ▒███  ▒▒▒▒▒███ ▒▒███ ▒▒███ ▒▒███ ▒▒███  ███▒▒███▒▒███▒▒███
 ▒███▒▒▒▒▒███  ███████ ▒███ ▒███ ▒███ ▒███▒███████  ▒███ ▒▒▒  ▒███   ███████  ▒▒▒█████▒   ▒▒▒█████▒  ▒███████  ▒███ ▒▒▒
 ▒███    ▒███ ███▒▒███ ▒███ ▒███ ▒███ ▒███▒███▒▒▒   ▒███      ▒███  ███▒▒███   ███▒▒▒███   ███▒▒▒███ ▒███▒▒▒   ▒███
 ███████████ ▒▒████████▒▒████████▒▒███████▒▒██████  █████     █████▒▒████████ █████ █████ █████ █████▒▒██████  █████
▒▒▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒▒███ ▒▒▒▒▒▒  ▒▒▒▒▒     ▒▒▒▒▒  ▒▒▒▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒  ▒▒▒▒▒▒  ▒▒▒▒▒
                                  ███ ▒███
                                 ▒▒██████
                                  ▒▒▒▒▒▒
"""

ANSI_RESET = "\x1b[0m"
GOLD = "\x1b[38;2;237;203;64m"
GOLD_BOLD = "\x1b[1;38;2;237;203;64m"
GOLD_DIM = "\x1b[38;2;201;164;14m"
GOLD_STOPS = ((237, 203, 64), (201, 164, 14))
SPIN_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")


def gold_at(t: float) -> tuple[int, int, int]:
    t = max(0.0, min(1.0, t))
    s = t * (len(GOLD_STOPS) - 1)
    i = min(int(s), len(GOLD_STOPS) - 2)
    f = s - i
    a, b = GOLD_STOPS[i], GOLD_STOPS[i + 1]
    return (int(a[0] + (b[0] - a[0]) * f), int(a[1] + (b[1] - a[1]) * f), int(a[2] + (b[2] - a[2]) * f))


def gold_fg(rgb: tuple[int, int, int]) -> str:
    return f"\x1b[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m"


def gold_text(text: str) -> str:
    span = max(1, len(text) - 1)
    out: list[str] = []
    last = -1
    for c, ch in enumerate(text):
        if ch == " ":
            out.append(ch)
            continue
        q = round(c / span * 24)
        if q != last:
            out.append(gold_fg(gold_at(q / 24)))
            last = q
        out.append(ch)
    out.append(ANSI_RESET)
    return "".join(out)


class Banner:

    SUBTITLE = "Discord badge leveling  ·  Game Time  ·  Game Variety  ·  Streaming"
    MIN_ROWS_FULL = 28
    MIN_ROWS_BODY = 10

    def __init__(self) -> None:
        self.art = [ln.rstrip() for ln in BANNER_ART.strip("\n").split("\n")]
        self.art_width = max(len(ln) for ln in self.art)
        self.pinned = False

    def build(self, cols: int, rows: int) -> list[str]:
        if cols > self.art_width and rows >= self.MIN_ROWS_FULL:
            height = len(self.art)
            lines: list[str] = []
            credit_row = height - 2
            for r, raw in enumerate(self.art):
                credit_col = self.art_width - len(self.CREDIT) - 5
                with_credit = r == credit_row and len(raw) < credit_col - 2
                line = raw.ljust(credit_col if with_credit else self.art_width)
                out: list[str] = []
                last = -1
                for c, ch in enumerate(line):
                    if ch == " ":
                        out.append(" ")
                        continue
                    q = round(((c / self.art_width) * 0.85 + (r / height) * 0.15) * 24)
                    if q != last:
                        out.append(gold_fg(gold_at(q / 24)))
                        last = q
                    out.append(ch)
                out.append(ANSI_RESET)
                if with_credit:
                    out.append(self.credit_link())
                lines.append("".join(out))
            lines.append(GOLD_DIM + "  " + self.SUBTITLE[: max(0, cols - 3)] + ANSI_RESET)
            return lines
        width = max(20, min(cols - 2, 64))
        sub_room = max(0, cols - 2 - 13)
        sub = ("  ·  " + self.SUBTITLE)[:sub_room]
        tail = ("  " + self.credit_link()) if sub_room >= len("  ·  " + self.SUBTITLE) + 2 + len(self.CREDIT) else ""
        return [
            gold_text("━" * width),
            "  " + gold_text("BadgeMaxxer") + GOLD_DIM + sub + ANSI_RESET + tail,
            gold_text("━" * width),
        ]

    CREDIT = "- By ItzMeShadow999"
    CREDIT_URL = "https://github.com/ItzMeShadow999"

    def credit_link(self) -> str:
        return f"\x1b]8;;{self.CREDIT_URL}\x1b\\{GOLD}{self.CREDIT}{ANSI_RESET}\x1b]8;;\x1b\\"

    def draw(self) -> None:
        if not sys.stdout.isatty():
            print("BadgeMaxxer")
            return
        cols, rows = shutil.get_terminal_size((120, 30))
        lines = self.build(cols, rows)
        top = len(lines) + 1
        out = "\x1b]0;BadgeMaxxer\x07\x1b[r\x1b[2J\x1b[3J\x1b[H" + "\n".join(lines) + "\n"
        if rows - top >= self.MIN_ROWS_BODY:
            out += f"\x1b[{top};{rows}r\x1b[{top};1H"
            self.pinned = True
        sys.stdout.write(out)
        sys.stdout.flush()

    def release(self) -> None:
        if sys.stdout.isatty():
            try:
                sys.stdout.write("\x1b[r\x1b[?25h")
                sys.stdout.flush()
            except Exception:
                pass


BANNER = Banner()
atexit.register(BANNER.release)


def zoom_out_terminal() -> None:
    if os.name != "nt" or not sys.stdout.isatty():
        return
    try:
        if os.environ.get("WT_SESSION"):
            if TERMINAL_ZOOM_OUT_STEPS <= 0:
                return
            import ctypes
            keybd = ctypes.windll.user32.keybd_event
            for _ in range(TERMINAL_ZOOM_OUT_STEPS):
                keybd(0x11, 0, 0, 0)
                keybd(0xBD, 0, 0, 0)
                keybd(0xBD, 0, 2, 0)
                keybd(0x11, 0, 2, 0)
                time.sleep(0.05)
            time.sleep(0.3)
        else:
            os.system(f"mode con: cols={TERMINAL_MIN_COLS} lines={TERMINAL_MIN_ROWS}")
    except Exception:
        pass


def read_key() -> str:
    if os.name == "nt":
        import msvcrt
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            return {"H": "up", "P": "down", "K": "left", "M": "right"}.get(msvcrt.getwch(), "")
        if ch in ("\r", "\n"):
            return "enter"
        if ch == "\x03":
            raise KeyboardInterrupt
        if ch == "\x1b":
            return "esc"
        return ch.lower()
    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = os.read(fd, 1).decode("utf-8", "ignore")
        if ch == "\x1b":
            if select.select([fd], [], [], 0.05)[0]:
                seq = os.read(fd, 2).decode("utf-8", "ignore")
                return {"[A": "up", "[B": "down", "[C": "right", "[D": "left", "OA": "up", "OB": "down"}.get(seq, "")
            return "esc"
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    if not ch:
        return "esc"
    if ch in ("\r", "\n"):
        return "enter"
    if ch == "\x03":
        raise KeyboardInterrupt
    return ch.lower()


def arrow_menu(title: str, options: Sequence[str], hint: str = "↑/↓ move · enter select", start: int = 0) -> int | None:
    n = len(options)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print(f"  {title}")
        for i, opt in enumerate(options, 1):
            print(f"    {i}. {opt}")
        raw = input("  › ").strip()
        return int(raw) - 1 if raw.isdigit() and 1 <= int(raw) <= n else None

    sel = start if 0 <= start < n else 0

    def paint(first: bool) -> None:
        buf: list[str] = []
        if not first:
            buf.append(f"\x1b[{n}A")
        room = max(20, shutil.get_terminal_size((120, 30)).columns - 8)
        for i, raw in enumerate(options):
            opt = raw if len(raw) <= room else raw[: room - 1] + "…"
            base = GOLD_BOLD if i == sel else "\x1b[37m"
            if opt.startswith("Recommended"):
                opt = "\x1b[92mRecommended" + base + opt[len("Recommended"):]
            if i == sel:
                buf.append(f"\r\x1b[2K   {GOLD_BOLD}› {opt}{ANSI_RESET}\n")
            else:
                buf.append(f"\r\x1b[2K     {base}{opt}{ANSI_RESET}\n")
        sys.stdout.write("".join(buf))
        sys.stdout.flush()

    sys.stdout.write("\x1b[?25l")
    sys.stdout.write(f"  {GOLD_BOLD}{title}{ANSI_RESET}  \x1b[90m{hint}{ANSI_RESET}\n")
    paint(True)
    try:
        while True:
            key = read_key()
            if key in ("up", "k"):
                sel = (sel - 1) % n
            elif key in ("down", "j"):
                sel = (sel + 1) % n
            elif key == "enter":
                return sel
            elif key in ("esc", "q"):
                return None
            else:
                continue
            paint(False)
    finally:
        sys.stdout.write(f"\x1b[{n + 1}A\r\x1b[J\x1b[?25h")
        sys.stdout.flush()


class LineLoader:

    def __init__(self) -> None:
        self.enabled = sys.stdout.isatty()
        self.frame = 0
        self.last_draw = 0.0
        self.active = False

    @staticmethod
    def _width() -> int:
        return max(40, shutil.get_terminal_size((80, 24)).columns)

    def update(self, name: str, tail: str, force: bool = False) -> None:
        if not self.enabled:
            return
        now = time.time()
        if not force and now - self.last_draw < 0.04:
            return
        self.last_draw = now
        w = self._width()
        line_w = min(w, 100) - 5
        prefix = "Fetching "
        end = (tail[:-5] if tail.endswith(" done") else tail).rjust(10)
        name_w = max(8, line_w - len(prefix) - 5 - len(end))
        nm = name if len(name) <= name_w else name[: name_w - 1] + "…"
        label = f"{prefix}{nm.ljust(name_w)}.... {end}"
        spin = SPIN_FRAMES[self.frame % len(SPIN_FRAMES)]
        self.frame += 1
        if not self.active:
            sys.stdout.write("\x1b[?25l")
            self.active = True
        sys.stdout.write(f"\r  {GOLD}{spin}{ANSI_RESET} \x1b[37m{label.ljust(w - 5)}{ANSI_RESET}")
        sys.stdout.flush()

    def clear(self) -> None:
        if not self.enabled or not self.active:
            return
        sys.stdout.write("\r" + " " * (self._width() - 1) + "\r\x1b[?25h")
        sys.stdout.flush()
        self.active = False


class TerminalInterface:
    COLOR_ALERT = "\x1b[91m"
    COLOR_PRIMARY = "\x1b[38;2;237;203;64m"
    COLOR_SUCCESS = "\x1b[92m"
    COLOR_NOTICE = "\x1b[93m"
    COLOR_TEXT = "\x1b[97m"
    COLOR_MUTED = "\x1b[90m"
    COLOR_RESET = "\x1b[0m"
    DIVIDER = "─" * 46

    def __init__(self) -> None:
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
        if sys.platform == "win32":
            self._activate_vt_processing()

    @staticmethod
    def _activate_vt_processing() -> None:
        import ctypes
        kernel = ctypes.windll.kernel32
        stdout_handle = kernel.GetStdHandle(-11)
        flags = ctypes.c_uint32()
        if kernel.GetConsoleMode(stdout_handle, ctypes.byref(flags)):
            kernel.SetConsoleMode(stdout_handle, flags.value | 0x0004)

    def _render_timestamp(self) -> str:
        return f"{self.COLOR_MUTED}{time.strftime('%H:%M:%S')}{self.COLOR_RESET}"

    def write_status(self, symbol: str, target: str, message: str, color: str) -> None:
        print(f"  {self._render_timestamp()} {symbol} {self.COLOR_TEXT}{target}{self.COLOR_RESET} "
              f"{self.COLOR_MUTED}·{self.COLOR_RESET} {color}{message}{self.COLOR_RESET}")

    def success(self, target: str, message: str) -> None:
        self.write_status(f"{self.COLOR_SUCCESS}✓{self.COLOR_RESET}", target, message, self.COLOR_SUCCESS)

    def dispatched(self, target: str, message: str) -> None:
        self.write_status(f"{self.COLOR_MUTED}·{self.COLOR_RESET} {self.COLOR_SUCCESS}posted{self.COLOR_RESET}", target, message, self.COLOR_SUCCESS)

    def warning(self, target: str, message: str) -> None:
        self.write_status(f"{self.COLOR_NOTICE}!{self.COLOR_RESET}", target, message, self.COLOR_NOTICE)

    def failure(self, target: str, message: str) -> None:
        self.write_status(f"{self.COLOR_ALERT}✗{self.COLOR_RESET}", target, message, self.COLOR_ALERT)

    def log(self, message: str) -> None:
        print(f"  {self._render_timestamp()} {self.COLOR_MUTED}·{self.COLOR_RESET} {self.COLOR_TEXT}{message}{self.COLOR_RESET}")

    def separator(self) -> None:
        print(f"  {self.COLOR_MUTED}{self.DIVIDER}{self.COLOR_RESET}")

    def display_header(self) -> None:
        BANNER.draw()


_HELP_TOKENS = re.compile(
    r"(?P<url>https://[^\s,]+?(?=[.,]?(?:\s|$)))"
    r"|(?P<key>cf_clearance=VALUE|cf_clearance|Ctrl\+Shift\+I|F12|Application tab|Storage tab|"
    r"Cookies|Value|cookie header|cookie|Network tab|Request Headers|authorization)"
)


def print_cookie_help(T: "TerminalInterface", lines: "tuple[str, ...] | None" = None) -> None:
    R, TXT, GOLD_C = T.COLOR_RESET, T.COLOR_TEXT, T.COLOR_PRIMARY
    CYAN, GREEN, YEL = "\x1b[96m", T.COLOR_SUCCESS, T.COLOR_NOTICE

    def paint(m: "re.Match[str]") -> str:
        return f"{CYAN if m.lastgroup == 'url' else GREEN}{m.group(0)}{TXT}"

    for i, line in enumerate(lines or COOKIE_HELP):
        ts = T._render_timestamp()
        if i == 0:
            print(f"  {ts} {GOLD_C}\x1b[1m{line}{R}")
        elif line.startswith(("Not in the list", "It is tied", "Never share")):
            print(f"  {ts} {YEL}{line}{R}")
        else:
            body = _HELP_TOKENS.sub(paint, line)
            if line[:2] in ("1.", "2.", "3.", "4.", "5."):
                body = f"{GOLD_C}{line[:2]}{TXT}{body[2:]}"
            print(f"  {ts} {TXT}{body}{R}")


_COOKIE_IN_PASTE = re.compile(
    r"""(?:cookie:\s*|(?:-b|--cookie)\s+\^?["'])([^'"^\r\n]+)""", re.I
)


def extract_cookie_header(raw: str) -> str:
    raw = raw.strip()
    m = _COOKIE_IN_PASTE.search(raw)
    return (m.group(1) if m else raw).strip()


def fetch_base_cookies(url: str = "https://discord.com/app") -> str:
    req = urllib.request.Request(url, headers={"user-agent": USER_AGENT_IDENTIFIER})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as exc:
        raw = exc.headers.get_all("Set-Cookie") or []
    except Exception:
        return ""
    pairs = [c.split(";", 1)[0].strip() for c in raw]
    return "; ".join(p for p in pairs if "=" in p)


@dataclass
class AccountSessionState:
    token: str = ""
    cookie: str = ""
    fingerprint: str = ""
    analytics_token: str = ""
    fetched_at: int = 0
    used_games: list[str] = field(default_factory=list)
    total_games_claimed: int = 0
    total_hours_claimed: float = 0.0
    total_stream_hours_claimed: float = 0.0
    total_stream_sessions: int = 0
    last_guild_id: str = ""
    last_channel_id: str = ""
    github_user: str = ""
    github_token: str = ""

    @classmethod
    def restore(cls) -> "AccountSessionState":
        if STATE_STORAGE_PATH.exists():
            try:
                raw_data = json.loads(STATE_STORAGE_PATH.read_text(encoding="utf-8"))
                known_keys = set(cls().__dict__.keys())
                instance = cls(**{k: v for k, v in raw_data.items() if k in known_keys and k != "used_games"})
                instance.used_games = raw_data.get("used_games", [])
                return instance
            except Exception:
                pass
        return cls()

    def persist(self) -> None:
        existing = {}
        if STATE_STORAGE_PATH.exists():
            try:
                existing = json.loads(STATE_STORAGE_PATH.read_text(encoding="utf-8"))
            except Exception:
                pass
        existing.update(asdict(self))
        STATE_STORAGE_PATH.write_text(json.dumps(existing, indent=2), encoding="utf-8")

    def save(self) -> None:
        self.persist()

    @property
    def requires_refresh(self) -> bool:
        return not self.analytics_token or (time.time() - self.fetched_at) > TOKEN_EXPIRY_THRESHOLD_SEC


def generate_fallback_properties() -> dict:
    return {
        "os": "Windows",
        "browser": "Discord Client",
        "release_channel": "stable",
        "client_version": DESKTOP_CLIENT_VERSION,
        "os_version": PLATFORM_OS_REVISION,
        "os_arch": "x64",
        "app_arch": "x64",
        "system_locale": "en-US",
        "has_client_mods": False,
        "browser_user_agent": USER_AGENT_IDENTIFIER,
        "browser_version": "42.7.1",
        "os_sdk_version": "26200",
        "client_build_number": DESKTOP_BUILD_IDENTIFIER,
        "native_build_number": PLATFORM_BUILD_IDENTIFIER,
        "client_event_source": None,
        "client_app_state": "focused",
    }


def assemble_super_properties(signature_id: str, session_id: str) -> tuple[str, dict]:
    try:
        network_req = urllib.request.Request(
            UPSTREAM_METRICS_URL,
            method="POST",
            data=b"{}",
            headers={"content-type": "application/json", "user-agent": USER_AGENT_IDENTIFIER}
        )
        with urllib.request.urlopen(network_req, timeout=10) as net_resp:
            properties_payload = json.loads(net_resp.read().decode("utf-8"))["properties"]
    except Exception:
        properties_payload = generate_fallback_properties()

    properties_payload["client_launch_id"] = str(uuid.uuid4())
    properties_payload["launch_signature"] = signature_id
    properties_payload["client_heartbeat_session_id"] = session_id
    serialized = json.dumps(properties_payload, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(serialized).decode("ascii"), properties_payload


def request_analytics_credential(auth_token: str, super_properties_b64: str) -> str:
    network_req = urllib.request.Request(
        REST_IDENTITY_URL,
        headers={
            "authorization": auth_token,
            "user-agent": USER_AGENT_IDENTIFIER,
            "x-super-properties": super_properties_b64,
        }
    )
    try:
        with urllib.request.urlopen(network_req, timeout=15) as net_resp:
            parsed = json.loads(net_resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Authentication rejected by endpoint (HTTP {exc.code})") from exc

    credential = parsed.get("analytics_token")
    if not credential:
        raise RuntimeError("Upstream response omitted analytics_token field.")
    return credential


def synchronize_credentials(state: AccountSessionState, super_props_b64: str) -> None:
    if not state.requires_refresh:
        return
    state.analytics_token = request_analytics_credential(state.token, super_props_b64)
    state.fetched_at = int(time.time())
    state.persist()


@dataclass(frozen=True)
class RuntimeClientContext:
    heartbeat_session_id: str
    launch_signature_id: str
    encoded_properties: str
    props_dict: dict = field(default_factory=dict)

    @property
    def super_props(self) -> str:
        return self.encoded_properties

    @classmethod
    def initialize(cls) -> "RuntimeClientContext":
        hb_session = str(uuid.uuid4())
        launch_sig = str(uuid.uuid4())
        encoded, raw = assemble_super_properties(launch_sig, hb_session)
        return cls(hb_session, launch_sig, encoded, raw)


@dataclass(frozen=True)
class DetectableTitle:
    title_id: str
    display_name: str
    binary_name: str


def identify_windows_binary(game_record: dict) -> str:
    for target in game_record.get("executables", []):
        if target.get("os") == "win32" and target.get("name"):
            return target["name"]
    return "game.exe"


def fetch_remote_catalog() -> str:
    loader = LineLoader()
    decoder = codecs.getincrementaldecoder("utf-8")()
    json_dec = json.JSONDecoder()
    raw = bytearray()
    text = ""
    pos = 0
    started = False
    count = 0
    name = "games data"
    req = urllib.request.Request(DISCORD_CATALOG_URL, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            total = int(resp.headers.get("Content-Length") or 0)
            loader.update(name, "0% done" if total else "...", force=True)
            while True:
                chunk = resp.read(16384)
                if not chunk:
                    break
                raw.extend(chunk)
                text += decoder.decode(chunk)
                pct = min(99, int(len(raw) * 100 / total)) if total else None
                if not started:
                    k = text.find("[")
                    if k != -1:
                        started = True
                        pos = k + 1
                while started:
                    while pos < len(text) and text[pos] in " \t\r\n,":
                        pos += 1
                    if pos >= len(text) or text[pos] == "]":
                        break
                    try:
                        obj, pos = json_dec.raw_decode(text, pos)
                    except json.JSONDecodeError:
                        break
                    if isinstance(obj, dict) and obj.get("name"):
                        name = str(obj["name"])
                        count += 1
                        loader.update(name, f"{pct}% done" if pct is not None else f"{count} games")
                text = text[pos:]
                pos = 0
                loader.update(name, f"{pct}% done" if pct is not None else f"{count} games")
            loader.update(name, "100% done", force=True)
            if loader.enabled:
                time.sleep(0.25)
        content = bytes(raw).decode("utf-8")
    finally:
        loader.clear()
    try:
        DATABASE_STORAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
        DATABASE_STORAGE_PATH.write_text(content, encoding="utf-8")
    except OSError:
        pass
    return content


def parse_catalog_entries(raw_json: str) -> list[DetectableTitle]:
    payload = json.loads(raw_json)
    catalog: list[DetectableTitle] = []
    registered_ids: set[str] = set()

    for item in payload:
        record_id = str(item.get("id", ""))
        if not record_id.isdigit() or record_id in registered_ids:
            continue
        if not any(entry.get("os") == "win32" and entry.get("name") for entry in item.get("executables", [])):
            continue
        registered_ids.add(record_id)
        catalog.append(DetectableTitle(record_id, item.get("name", "Unknown Game"), identify_windows_binary(item)))

    return catalog


def load_game_catalog() -> list[DetectableTitle]:
    cached_content = ""
    if DATABASE_STORAGE_PATH.exists():
        cached_content = DATABASE_STORAGE_PATH.read_text(encoding="utf-8").strip()
    if cached_content:
        try:
            titles = parse_catalog_entries(cached_content)
            if titles:
                return titles
        except (json.JSONDecodeError, ValueError):
            pass
    try:
        return parse_catalog_entries(fetch_remote_catalog())
    except Exception:
        return []


class TelemetryEventFabricator:
    def __init__(self, state: AccountSessionState, context: RuntimeClientContext) -> None:
        self.state = state
        self.context = context
        self._sequence_index = 0

    def _increment_sequence(self) -> int:
        self._sequence_index += 1
        return self._sequence_index

    def construct_launch_payload(self, title: DetectableTitle) -> dict:
        timestamp_now = int(time.time() * 1000)
        attributes = {
            "client_track_timestamp": timestamp_now,
            "client_heartbeat_session_id": self.context.heartbeat_session_id,
            "event_sequence_number": self._increment_sequence(),
            "game": title.display_name,
            "game_id": title.title_id,
            "verified": True,
            "elevated": False,
            "is_launcher": False,
            "game_platform": "desktop",
            "detection_method": "verified_game",
            "is_overlay_enabled": False,
            "is_overlay_game_enabled": True,
            "is_overlay_game_source": "OOP_DEFAULT_DATABASE",
            "fullscreen_type": "UNKNOWN",
            "hardware_display_count": 1,
            "overlay_method": "Disabled",
            "activity_status_enabled": True,
            "activity_status_shared_guilds": [],
            "current_user_status": "online",
            "game_detection_enabled": True,
            "executable_path": title.binary_name,
            "voice_channel_id": None,
            "voice_channel_type": None,
            "voice_channel_bitrate": None,
            "voice_channel_guild_id": None,
            "hidden_by_distributor": False,
            "game_metadata": None,
            "executable_fingerprint": self.state.fingerprint,
            "client_performance_cpu": None,
            "client_performance_memory": None,
            "cpu_core_count": None,
            "accessibility_features": 0,
            "rendered_locale": "en-US",
            "launch_signature": self.context.launch_signature_id,
            "client_rtc_state": None,
            "client_app_state": "focused",
            "client_send_timestamp": timestamp_now,
        }
        if not self.state.fingerprint:
            attributes.pop("executable_fingerprint", None)
        return {"type": "launch_game", "properties": attributes}

    def construct_heartbeat_payload(
        self,
        title: DetectableTitle,
        duration_ms: int,
        session_token: str,
        is_initial: bool,
        is_final: bool,
        event_time_ms: int | None = None
    ) -> dict:
        tracked_time = int(time.time() * 1000) if event_time_ms is None else event_time_ms
        return {
            "type": "running_game_heartbeat",
            "properties": {
                "client_track_timestamp": tracked_time,
                "client_heartbeat_session_id": self.context.heartbeat_session_id,
                "event_sequence_number": self._increment_sequence(),
                "game_id": title.title_id,
                "game_name": title.display_name,
                "game_metadata": None,
                "game_executable": title.binary_name,
                "game_detection_enabled": True,
                "initial_heartbeat": is_initial,
                "final_heartbeat": is_final,
                "game_session_id": session_token,
                "duration_tracked_ms": duration_ms,
                "rtc_connection_id": None,
                "media_session_id": None,
                "launch_signature": self.context.launch_signature_id,
                "client_app_state": "focused",
                "client_send_timestamp": tracked_time,
            },
        }

    def assemble_complete_session(self, title: DetectableTitle, duration_ms: int) -> list[dict]:
        session_id = str(uuid.uuid4())
        current_time = int(time.time() * 1000)
        origin_time = current_time - duration_ms
        if origin_time < 0:
            origin_time = current_time

        return [
            self.construct_heartbeat_payload(title, 0, session_id, is_initial=True, is_final=False, event_time_ms=origin_time),
            self.construct_launch_payload(title),
            self.construct_heartbeat_payload(title, duration_ms, session_id, is_initial=False, is_final=True, event_time_ms=current_time),
        ]

    def post_telemetry_batch(self, events: Sequence[dict]) -> int:
        envelope = {"token": self.state.analytics_token, "events": list(events)}
        encoded_body = json.dumps(envelope).encode("utf-8")
        network_headers = {
            "accept": "*/*",
            "accept-language": "en-US",
            "authorization": self.state.token,
            "content-type": "application/json",
            "cookie": self.state.cookie,
            "origin": "https://discord.com",
            "referer": "https://discord.com/channels/@me",
            "user-agent": USER_AGENT_IDENTIFIER,
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-US",
            "x-discord-timezone": "UTC",
            "x-super-properties": self.context.encoded_properties,
        }

        request_handle = urllib.request.Request(TELEMETRY_INGEST_URL, data=encoded_body, method="POST", headers=network_headers)
        try:
            with urllib.request.urlopen(request_handle, timeout=15) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code
        except Exception:
            return 0


def segment_collection(items: Sequence[DetectableTitle], chunk_size: int) -> Iterator[Sequence[DetectableTitle]]:
    for idx in range(0, len(items), chunk_size):
        yield items[idx:idx + chunk_size]


class IngestionPipeline:
    def __init__(self, fabricator: TelemetryEventFabricator, terminal: TerminalInterface) -> None:
        self.fabricator = fabricator
        self.terminal = terminal

    def execute_stream(self, titles: Sequence[DetectableTitle], session_builder) -> int:
        total_records = len(titles)
        processed_successfully = 0

        for batch_index, partition in enumerate(segment_collection(titles, DISPATCH_BATCH_LIMIT), start=1):
            accumulated_events = []
            for target in partition:
                accumulated_events.extend(session_builder(target))

            http_status = self.fabricator.post_telemetry_batch(accumulated_events)
            if http_status == 204:
                processed_successfully += len(partition)
                self.terminal.dispatched(f"batch {batch_index}", f"{processed_successfully}/{total_records} titles accepted")
            elif http_status in (401, 403):
                self.terminal.failure(
                    f"batch {batch_index}",
                    f"[{http_status}] Authentication failed. Refresh token/cookie via Option 3."
                )
                return processed_successfully
            else:
                self.terminal.warning(f"batch {batch_index}", f"HTTP {http_status}")

            time.sleep(NETWORK_COOLDOWN_SEC)

        return processed_successfully


USER_AGENT = USER_AGENT_IDENTIFIER
_user_id_from_token = extract_account_snowflake

STREAM_TIERS = [
    (1, "Newcomer", 1),
    (2, "Fledgling", 5),
    (3, "Breakout", 20),
    (4, "Standout", 75),
    (5, "Trendsetter", 150),
    (6, "Headliner", 300),
    (7, "Star", 500),
    (8, "Sensation", 1000),
    (9, "Visionary", 2000),
    (10, "Phenomenon", 5000),
]

OPUS_SILENCE = b"\xf8\xff\xfe"



class Console:
    RED = "\x1b[91m"
    ORANGE = "\x1b[38;2;237;203;64m"
    GREEN = "\x1b[92m"
    YELLOW = "\x1b[93m"
    CYAN = "\x1b[96m"
    WHITE = "\x1b[97m"
    GREY = "\x1b[90m"
    MAGENTA = "\x1b[95m"
    RESET = "\x1b[0m"
    RULE = "─" * 48

    def __init__(self) -> None:
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
        if sys.platform == "win32":
            self._enable_ansi()

    @staticmethod
    def _enable_ansi() -> None:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)

    def _stamp(self) -> str:
        return f"{self.GREY}{time.strftime('%H:%M:%S')}{self.RESET}"

    def _line(self, glyph: str, target: str, detail: str, color: str) -> None:
        print(f"  {self._stamp()} {glyph} {self.WHITE}{target}{self.RESET} {self.GREY}·{self.RESET} {color}{detail}{self.RESET}")

    def ok(self, target: str, detail: str) -> None:
        self._line(f"{self.GREEN}✓{self.RESET}", target, detail, self.GREEN)

    def live(self, target: str, detail: str) -> None:
        self._line(f"{self.MAGENTA}●{self.RESET}", target, detail, self.MAGENTA)

    def warn(self, target: str, detail: str) -> None:
        self._line(f"{self.YELLOW}!{self.RESET}", target, detail, self.YELLOW)

    def err(self, target: str, detail: str) -> None:
        self._line(f"{self.RED}✗{self.RESET}", target, detail, self.RED)

    def info(self, detail: str) -> None:
        print(f"  {self._stamp()} {self.GREY}·{self.RESET} {self.WHITE}{detail}{self.RESET}")

    def rule(self) -> None:
        print(f"  {self.GREY}{self.RULE}{self.RESET}")



class MiniWebSocket:

    def __init__(self, host: str, port: int = 443, path: str = "/") -> None:
        host_clean = host.replace("wss://", "").replace("https://", "").rstrip("/")
        if ":" in host_clean:
            h, p = host_clean.split(":", 1)
            self.host = h
            try:
                self.port = int(p)
            except ValueError:
                self.port = port
        else:
            self.host = host_clean
            self.port = port

        self.path = path
        self.sock: ssl.SSLSocket | None = None
        self.closed = True
        self._lock = threading.RLock()

    def connect(self) -> None:
        raw_sock = socket.create_connection((self.host, self.port), timeout=15)
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)
        sec_key = base64.b64encode(os.urandom(16)).decode("ascii")

        host_hdr = self.host if self.port == 443 else f"{self.host}:{self.port}"
        req = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {host_hdr}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {sec_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"User-Agent: {USER_AGENT}\r\n\r\n"
        )
        self.sock.sendall(req.encode("utf-8"))

        header_data = b""
        while b"\r\n\r\n" not in header_data:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("failed handshake")
            header_data += chunk

        first_line = header_data.split(b"\r\n")[0].decode("utf-8", "ignore")
        if "101" not in first_line:
            raise ConnectionError(f"handshake rejected: {first_line}")
        self.closed = False

    def send(self, data: str) -> None:
        with self._lock:
            if self.closed or not self.sock:
                raise ConnectionError("socket closed")
            try:
                payload = data.encode("utf-8")
                length = len(payload)
                mask_key = os.urandom(4)

                header = bytearray([0x81])
                if length <= 125:
                    header.append(0x80 | length)
                elif length <= 65535:
                    header.append(0x80 | 126)
                    header.extend(length.to_bytes(2, "big"))
                else:
                    header.append(0x80 | 127)
                    header.extend(length.to_bytes(8, "big"))

                header.extend(mask_key)
                masked = bytearray(payload[i] ^ mask_key[i % 4] for i in range(length))
                self.sock.sendall(header + masked)
            except Exception as e:
                self.close()
                raise ConnectionError(f"socket write error: {e}") from e

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("socket closed during read")
            buf.extend(chunk)
        return bytes(buf)

    def recv(self, timeout: float = 5.0) -> dict | None:
        if self.closed or not self.sock:
            return None
        try:
            r, _, _ = select.select([self.sock], [], [], timeout)
            if not r:
                return None
            head = self._recv_exact(2)
        except Exception:
            self.close()
            return None

        opcode = head[0] & 0x0F
        if opcode == 0x8:
            code = 0
            reason = ""
            try:
                c_len = head[1] & 0x7F
                if c_len >= 2:
                    p = self._recv_exact(c_len)
                    code = struct.unpack(">H", p[:2])[0]
                    reason = p[2:].decode("utf-8", "ignore")
            except Exception:
                pass
            self.close()
            return {"op": "close", "code": code, "reason": reason}
        if opcode == 0x9:
            try:
                with self._lock:
                    if self.sock and not self.closed:
                        pong = bytearray([0x8A, 0x80])
                        pong.extend(os.urandom(4))
                        self.sock.sendall(pong)
            except Exception:
                self.close()
            return {"op": "ping"}

        if opcode == 0xA:
            try:
                self._read_payload(head)
            except Exception:
                self.close()
            return {"op": "pong"}

        try:
            fin = bool(head[0] & 0x80)
            payload = self._read_payload(head)
            while not fin:
                nxt = self._recv_exact(2)
                chunk = self._read_payload(nxt)
                if (nxt[0] & 0x0F) in (0x8, 0x9, 0xA):
                    continue
                payload += chunk
                fin = bool(nxt[0] & 0x80)
            return json.loads(payload.decode("utf-8"))
        except Exception:
            self.close()
            return None

    def _read_payload(self, head: bytes) -> bytes:
        length = head[1] & 0x7F
        if length == 126:
            length = int.from_bytes(self._recv_exact(2), "big")
        elif length == 127:
            length = int.from_bytes(self._recv_exact(8), "big")
        return self._recv_exact(length)

    def close(self) -> None:
        self.closed = True
        with self._lock:
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None


class VoiceConnection:

    def __init__(
        self,
        endpoint: str,
        server_id: str,
        user_id: str,
        session_id: str,
        token: str,
        console: Console,
        label: str = "voice",
        is_stream: bool = False,
        stream_key: str = "",
    ) -> None:
        cleaned = endpoint.replace("wss://", "").replace("https://", "").rstrip("/")
        if ":" in cleaned:
            self.host, port_str = cleaned.split(":", 1)
            try:
                self.port = int(port_str)
            except ValueError:
                self.port = 443
        else:
            self.host = cleaned
            self.port = 443
        self.endpoint = f"{self.host}:{self.port}"
        self.server_id = server_id
        self.user_id = user_id
        self.session_id = session_id
        self.token = token
        self.console = console
        self.label = label
        self.is_stream = is_stream
        self.stream_key = stream_key

        self.ws: MiniWebSocket | None = None
        self.udp_sock: socket.socket | None = None
        self.ssrc: int = 0
        self.voice_ip: str = ""
        self.voice_port: int = 0
        self.external_ip: str = ""
        self.external_port: int = 0
        self.secret_key: bytes = b""
        self.encryption_mode: str = ""
        self.heartbeat_interval: float = 13.75
        self.running: bool = False
        self.nonce_counter: int = 0
        self._hb_thread: threading.Thread | None = None
        self._audio_thread: threading.Thread | None = None

    def connect(self) -> bool:
        C = self.console

        try:
            self.ws = MiniWebSocket(self.host, port=self.port, path="/?v=7")
            self.ws.connect()
        except Exception as exc:
            C.err(self.label, f"ws connect failed: {exc}")
            return False

        msg = self._recv_op(8, timeout=10)
        if not msg:
            C.err(self.label, "no Hello from voice server")
            return False
        self.heartbeat_interval = msg.get("d", {}).get("heartbeat_interval", 13750) / 1000.0

        identify_d: dict[str, Any] = {
            "server_id": self.server_id,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "token": self.token,
            "max_dave_protocol_version": 1,
        }
        if self.is_stream:
            if self.stream_key:
                identify_d["stream_key"] = self.stream_key
            identify_d["video"] = True
            identify_d["streams"] = [
                {"type": "screen", "rid": "100", "quality": 100}
            ]
        self.ws.send(json.dumps({"op": 0, "d": identify_d}))

        msg = self._recv_op(2, timeout=10)
        if not msg:
            C.err(self.label, "no Ready from voice server")
            return False

        d = msg.get("d", {})
        self.ssrc = d.get("ssrc", 0)
        self.voice_ip = d.get("ip", "")
        self.voice_port = d.get("port", 0)
        modes = d.get("modes", [])

        preferred = [
            "aead_aes256_gcm_rtpsize",
            "aead_xchacha20_poly1305_rtpsize",
            "xsalsa20_poly1305_lite",
            "xsalsa20_poly1305",
        ]
        for mode in preferred:
            if mode in modes:
                self.encryption_mode = mode
                break
        if not self.encryption_mode and modes:
            self.encryption_mode = modes[0]

        if not self._udp_discovery():
            C.warn(self.label, "UDP discovery failed, using fallback IP")
            self.external_ip = "127.0.0.1"
            self.external_port = random.randint(10000, 60000)

        self.ws.send(json.dumps({
            "op": 1,
            "d": {
                "protocol": "udp",
                "data": {
                    "address": self.external_ip,
                    "port": self.external_port,
                    "mode": self.encryption_mode,
                },
            },
        }))

        msg = self._recv_op(4, timeout=10)
        if msg:
            d = msg.get("d", {})
            self.secret_key = bytes(d.get("secret_key", []))
            self.encryption_mode = d.get("mode", self.encryption_mode)

        self.running = True
        return True

    def _recv_op(self, target_op: int, timeout: float = 10) -> dict | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = max(0.1, deadline - time.time())
            msg = self.ws.recv(timeout=min(remaining, 2.0))
            if msg is None:
                if self.ws.closed:
                    return None
                continue
            if msg.get("op") == "close":
                C = self.console
                code = msg.get("code")
                reason = msg.get("reason")
                C.err(self.label, f"voice server closed: {code} ({reason})")
                return None
            if msg.get("op") == target_op:
                return msg
            if msg.get("op") == 3:
                self._send_heartbeat()
        return None

    def _send_heartbeat(self) -> None:
        if self.ws and not self.ws.closed:
            try:
                nonce = int(time.time() * 1000)
                self.ws.send(json.dumps({"op": 3, "d": nonce}))
            except Exception:
                pass

    def _udp_discovery(self) -> bool:
        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.settimeout(5)

            packet = bytearray(74)
            struct.pack_into(">HHI", packet, 0, 0x0001, 70, self.ssrc)

            self.udp_sock.sendto(bytes(packet), (self.voice_ip, self.voice_port))

            data, _ = self.udp_sock.recvfrom(256)
            if len(data) < 74:
                return False

            ip_start = 8
            ip_end = data.index(0, ip_start)
            self.external_ip = data[ip_start:ip_end].decode("utf-8")
            self.external_port = struct.unpack_from(">H", data, 72)[0]

            return bool(self.external_ip)
        except Exception:
            if self.udp_sock:
                try:
                    self.udp_sock.close()
                except Exception:
                    pass
                self.udp_sock = None
            return False

    def start_heartbeat(self) -> None:
        def _loop():
            while self.running and self.ws and not self.ws.closed:
                self._send_heartbeat()
                try:
                    msg = self.ws.recv(timeout=0.5)
                    if msg and msg.get("op") == 3:
                        self._send_heartbeat()
                except Exception:
                    pass
                time.sleep(max(1.0, self.heartbeat_interval - 0.5))

        self._hb_thread = threading.Thread(target=_loop, daemon=True)
        self._hb_thread.start()

    def send_speaking(self, speaking: bool = True) -> None:
        if self.ws and not self.ws.closed:
            try:
                self.ws.send(json.dumps({
                    "op": 5,
                    "d": {
                        "speaking": 1 if speaking else 0,
                        "delay": 0,
                        "ssrc": self.ssrc,
                    },
                }))
            except Exception:
                pass

    def start_silence_pump(self) -> None:
        if not self.udp_sock or not self.secret_key:
            return

        def _pump():
            seq = 0
            ts = 0
            while self.running:
                try:
                    if HAS_CRYPTO and "aes256_gcm" in self.encryption_mode:
                        self._send_encrypted_silence_gcm(seq, ts)
                    else:
                        keepalive = struct.pack(">I", seq) + b"\xc9"
                        try:
                            self.udp_sock.sendto(keepalive, (self.voice_ip, self.voice_port))
                        except Exception:
                            pass
                    seq = (seq + 1) & 0xFFFF
                    ts = (ts + 960) & 0xFFFFFFFF
                    time.sleep(1.0)
                except Exception:
                    break

        self._audio_thread = threading.Thread(target=_pump, daemon=True)
        self._audio_thread.start()

    def _send_encrypted_silence_gcm(self, seq: int, ts: int) -> None:
        if not self.udp_sock or not self.secret_key:
            return
        try:
            rtp_header = struct.pack(
                ">BBHII",
                0x80,
                0x78,
                seq & 0xFFFF,
                ts & 0xFFFFFFFF,
                self.ssrc,
            )

            self.nonce_counter += 1
            nonce = struct.pack(">I", self.nonce_counter) + b"\x00" * 8

            cipher = AESGCM(self.secret_key[:32])
            encrypted = cipher.encrypt(nonce, OPUS_SILENCE, rtp_header)

            packet = rtp_header + encrypted + struct.pack(">I", self.nonce_counter)
            self.udp_sock.sendto(packet, (self.voice_ip, self.voice_port))
        except Exception:
            pass

    def close(self) -> None:
        self.running = False
        if self.udp_sock:
            try:
                self.udp_sock.close()
            except Exception:
                pass
        if self.ws:
            self.ws.close()


PERMISSION_ADMINISTRATOR = 1 << 3
PERMISSION_STREAM        = 1 << 9
PERMISSION_VIEW_CHANNEL  = 1 << 10
PERMISSION_CONNECT       = 1 << 20
PERMISSION_ALL           = (1 << 63) - 1
STREAM_NEEDS = PERMISSION_VIEW_CHANNEL | PERMISSION_CONNECT | PERMISSION_STREAM
STREAM_MARK = {True: "✓", False: "✗", None: "?"}
STREAM_ORDER = {True: 0, None: 1, False: 2}
_AFK_RE = re.compile(r"(?<![a-z])afk(?![a-z])", re.I)


def is_afk_channel(channel_id: str, name: str, afk_id: str = "") -> bool:
    return (bool(afk_id) and str(channel_id) == str(afk_id)) or bool(_AFK_RE.search(str(name or "")))


def _perm_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def base_permissions(guild_id: str, owner_id: str, me_id: str, roles: Sequence[dict], member_roles: Sequence[str]) -> int:
    if owner_id and owner_id == me_id:
        return PERMISSION_ALL
    by_id = {str(r.get("id")): _perm_int(r.get("permissions")) for r in roles}
    base = by_id.get(str(guild_id), 0)
    for rid in member_roles:
        base |= by_id.get(str(rid), 0)
    return PERMISSION_ALL if base & PERMISSION_ADMINISTRATOR else base


def apply_overwrites(base: int, guild_id: str, me_id: str, member_roles: Sequence[str], overwrites: Sequence[dict]) -> int:
    if base & PERMISSION_ADMINISTRATOR:
        return PERMISSION_ALL
    ow = {str(o.get("id")): o for o in overwrites}
    perms = base
    ev = ow.get(str(guild_id))
    if ev:
        perms = (perms & ~_perm_int(ev.get("deny"))) | _perm_int(ev.get("allow"))
    allow = deny = 0
    for rid in member_roles:
        o = ow.get(str(rid))
        if o:
            allow |= _perm_int(o.get("allow"))
            deny |= _perm_int(o.get("deny"))
    perms = (perms & ~deny) | allow
    mo = ow.get(str(me_id))
    if mo:
        perms = (perms & ~_perm_int(mo.get("deny"))) | _perm_int(mo.get("allow"))
    return perms


def stream_verdict(perms: int | None) -> bool | None:
    if perms is None:
        return None
    return bool(perms & PERMISSION_ADMINISTRATOR) or (perms & STREAM_NEEDS) == STREAM_NEEDS


def fetch_member_roles(token: str, super_props: str, guild_id: str, me_id: str) -> list[str] | None:
    urls = [f"https://discord.com/api/v9/users/@me/guilds/{guild_id}/member"]
    if me_id:
        urls.append(f"https://discord.com/api/v9/guilds/{guild_id}/members/{me_id}")
    for url in urls:
        st, data = _discord_api_get(url, token, super_props)
        if st == 200 and isinstance(data, dict) and isinstance(data.get("roles"), list):
            return [str(x) for x in data["roles"]]
    return None


def _discord_api_get(url: str, token: str, super_props: str = "") -> tuple[int, dict]:
    headers = {
        "authorization": token,
        "user-agent": USER_AGENT,
    }
    if super_props:
        headers["x-super-properties"] = super_props
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return resp.status, data
    except urllib.error.HTTPError as exc:
        try:
            err_data = json.loads(exc.read().decode("utf-8"))
        except Exception:
            err_data = {"message": str(exc.reason)}
        return exc.code, err_data
    except Exception as exc:
        return 0, {"message": str(exc)}


def validate_stream_target(
    token: str,
    super_props: str,
    guild_id: str,
    channel_id: str,
    console: Console,
) -> tuple[bool, str]:
    C = console

    if not guild_id.isdigit():
        C.err("server", f"invalid server ID format: '{guild_id}' (must be numeric digits)")
        return False, "invalid server id format"
    if not channel_id.isdigit():
        C.err("channel", f"invalid channel ID format: '{channel_id}' (must be numeric digits)")
        return False, "invalid channel id format"

    status, user_data = _discord_api_get("https://discord.com/api/v9/users/@me", token, super_props)
    if status == 401:
        C.err("auth", "authentication failed: your discord token is invalid or has expired (HTTP 401).")
        C.info(f"{C.GREY}please update your token using Option 3 in the menu.{C.RESET}")
        return False, "unauthorized"
    if status != 200:
        C.err("auth", f"could not reach discord API (HTTP {status}: {user_data.get('message', 'network error')})")
        return False, "api error"

    g_status, g_data = _discord_api_get(f"https://discord.com/api/v9/guilds/{guild_id}", token, super_props)
    if g_status in (403, 404):
        ug_status, ug_list = _discord_api_get("https://discord.com/api/v9/users/@me/guilds", token, super_props)
        guild_found = None
        if ug_status == 200 and isinstance(ug_list, list):
            guild_found = next((g for g in ug_list if str(g.get("id")) == str(guild_id)), None)

        if not guild_found:
            C.err("server", f"server not found ({guild_id})")
            C.err("server", "either this server does not exist or your account is not a member of it.")
            return False, "server not found"
        guild_name = guild_found.get("name", "Server")
    elif g_status != 200:
        C.err("server", f"server lookup failed (HTTP {g_status}: {g_data.get('message', 'unknown error')})")
        return False, "server lookup error"
    else:
        guild_name = g_data.get("name", "Server")

    C.ok("server", f"server verified: {C.WHITE}{guild_name}{C.RESET} ({guild_id})")

    ch_status, ch_data = _discord_api_get(f"https://discord.com/api/v9/channels/{channel_id}", token, super_props)
    if ch_status in (403, 404):
        C.err("channel", f"channel not found ({channel_id})")
        C.err("channel", "either this channel does not exist or your account lacks access to view it.")
        return False, "channel not found"
    elif ch_status != 200:
        C.err("channel", f"channel lookup failed (HTTP {ch_status}: {ch_data.get('message', 'unknown error')})")
        return False, "channel lookup error"

    ch_name = ch_data.get("name", "channel")
    ch_guild_id = str(ch_data.get("guild_id", ""))
    ch_type = ch_data.get("type")
    afk_id = str(g_data.get("afk_channel_id") or "") if g_status == 200 and isinstance(g_data, dict) else ""
    if ch_type in (2, 13) and is_afk_channel(channel_id, ch_name, afk_id):
        C.err("channel", f"'{ch_name}' is an AFK channel, AFK channels are skipped. Pick another voice channel.")
        return False, "afk channel"

    if ch_guild_id and ch_guild_id != str(guild_id):
        C.err("channel", f"channel mismatch: channel '{ch_name}' belongs to server {ch_guild_id}, NOT {guild_id}.")
        return False, "channel guild mismatch"

    channel_type_names = {
        0: "Text Channel",
        2: "Voice Channel",
        4: "Category",
        5: "Announcement Channel",
        13: "Stage Channel",
        15: "Forum Channel",
    }
    if ch_type not in (2, 13):
        type_name = channel_type_names.get(ch_type, f"Type {ch_type}")
        C.err("channel", f"invalid channel type: '{ch_name}' is a {type_name}, NOT a Voice Channel.")
        C.info(f"{C.GREY}hint: right-click a voice channel (speaker icon) in Discord -> Copy Channel ID.{C.RESET}")
        return False, "not a voice channel"

    type_name = "Stage Channel" if ch_type == 13 else "Voice Channel"
    C.ok("channel", f"voice channel verified: {C.WHITE}#{ch_name}{C.RESET} ({type_name})")

    raw_perms = ch_data.get("permissions")
    if raw_perms is not None:
        try:
            perms = int(raw_perms)
            is_admin = bool(perms & PERMISSION_ADMINISTRATOR)
            can_view = is_admin or bool(perms & PERMISSION_VIEW_CHANNEL)
            can_connect = is_admin or bool(perms & PERMISSION_CONNECT)
            can_stream = is_admin or bool(perms & PERMISSION_STREAM)

            if not can_view:
                C.err("perms", f"missing permission: your account cannot view channel '#{ch_name}' (VIEW_CHANNEL missing).")
                return False, "cannot view channel"
            if not can_connect:
                C.err("perms", f"missing permission: your account cannot connect to channel '#{ch_name}' (CONNECT missing).")
                return False, "cannot connect"
            if not can_stream:
                C.err("perms", f"missing permission: your account cannot Go Live in channel '#{ch_name}' (STREAM / Video missing).")
                C.info(f"{C.GREY}hint: a server administrator must grant your role 'Video / Go Live' permission.{C.RESET}")
                return False, "cannot stream"

            C.ok("perms", f"permissions verified: {C.GREEN}View Channel ✓ · Connect ✓ · Go Live (Stream) ✓{C.RESET}")
            return True, f"server: {guild_name}, channel: #{ch_name}"
        except Exception:
            pass

    C.ok("perms", "voice channel permissions check completed")
    return True, f"server: {guild_name}, channel: #{ch_name}"



def _summarize_guild(g: dict, me_id: str = "") -> dict:
    props = g.get("properties") or {}
    gid = str(g.get("id"))
    afk_id = str(g.get("afk_channel_id") or props.get("afk_channel_id") or "")
    owner_id = str(g.get("owner_id") or props.get("owner_id") or "")
    chans = {str(c.get("id")): c for c in (g.get("channels") or []) if c.get("type") in (2, 13)}
    names = {cid: c.get("name", "voice") for cid, c in chans.items() if not is_afk_channel(cid, c.get("name", ""), afk_id)}
    member_roles = g.get("_member_roles")
    roles = g.get("roles") or []
    base = None
    if me_id and owner_id == me_id:
        base = PERMISSION_ALL
    elif me_id and roles and member_roles is not None:
        base = base_permissions(gid, owner_id, me_id, roles, member_roles)
    counts: dict[str, int] = {}
    for vs in g.get("voice_states") or []:
        cid = str(vs.get("channel_id") or "")
        if cid in names:
            counts[cid] = counts.get(cid, 0) + 1
    all_vcs = []
    for cid in names:
        ok = None
        if base is not None:
            ok = stream_verdict(apply_overwrites(base, gid, me_id, member_roles or [], chans[cid].get("permission_overwrites") or []))
        all_vcs.append((cid, names[cid], counts.get(cid, 0), ok))
    all_vcs.sort(key=lambda v: (STREAM_ORDER[v[3]], -v[2]))
    vcs = [v for v in all_vcs if v[2] > 0]
    best = min((STREAM_ORDER[v[3]] for v in vcs), default=2)
    browse_best = min((STREAM_ORDER[v[3]] for v in all_vcs), default=2)
    return {
        "id": gid,
        "name": g.get("name") or props.get("name") or "Unknown server",
        "members": int(g.get("member_count") or props.get("member_count") or 0),
        "vcs": vcs[:3],
        "all_vcs": all_vcs,
        "voice_total": sum(counts.values()),
        "stream_rank": 2 - best,
        "browse_rank": 2 - browse_best,
        "complete": "channels" in g,
    }


def scan_busy_servers(token: str, props: dict, super_props: str, timeout: float = 15.0, limit: int = 3,
                      debug: dict | None = None, all_out: list | None = None) -> list[dict]:
    dbg = debug if debug is not None else {}
    dbg.update(events={}, close=None, error="", guilds=0, with_channels=0, with_voice=0)
    ws = MiniWebSocket(GATEWAY_URL, path="/?v=9&encoding=json")
    raw: dict[str, dict] = {}
    expected: set[str] = set()
    got_ready, supp_at = False, 0.0
    me_id = extract_account_snowflake(token)
    hb_interval, last_hb, seq = 41.25, time.time(), None
    deadline = time.time() + timeout

    def done() -> bool:
        return bool(expected) and all("channels" in raw[i] and "voice_states" in raw[i] for i in expected)

    try:
        ws.connect()
        while time.time() < deadline:
            if time.time() - last_hb > hb_interval:
                ws.send(json.dumps({"op": 1, "d": seq}))
                last_hb = time.time()
            if (got_ready and done()) or (supp_at and time.time() - supp_at > 2.0):
                break
            msg = ws.recv(timeout=1.0)
            if not msg:
                if ws.closed:
                    dbg["error"] = dbg["error"] or "connection closed"
                    break
                continue
            op, t, d = msg.get("op"), msg.get("t"), msg.get("d") or {}
            name = t or f"op{op}"
            dbg["events"][name] = dbg["events"].get(name, 0) + 1
            if op == "close":
                dbg["close"] = (msg.get("code"), msg.get("reason"))
                break
            if msg.get("s") is not None:
                seq = msg["s"]
            if op == 10:
                hb_interval = d.get("heartbeat_interval", 41250) / 1000.0
                ws.send(json.dumps({"op": 1, "d": seq}))
                last_hb = time.time()
                ws.send(json.dumps({"op": 2, "d": {
                    "token": token, "capabilities": 16381, "properties": props,
                    "presence": {"status": "invisible", "since": 0, "activities": [], "afk": False},
                }}))
            elif op == 0 and t == "READY":
                got_ready = True
                me_id = str((d.get("user") or {}).get("id") or me_id)
                merged = d.get("merged_members") or []
                for i, g in enumerate(d.get("guilds") or []):
                    gid = str(g.get("id"))
                    entry = raw.setdefault(gid, {"id": gid})
                    entry.update(g)
                    expected.add(gid)
                    row = merged[i] if i < len(merged) and isinstance(merged[i], list) else []
                    mine = next((m for m in row if isinstance(m, dict) and str(m.get("user_id") or (m.get("user") or {}).get("id") or "") == me_id), None)
                    if mine is None and row and isinstance(row[0], dict):
                        mine = row[0]
                    if mine and isinstance(mine.get("roles"), list):
                        entry["_member_roles"] = [str(x) for x in mine["roles"]]
            elif op == 0 and t == "READY_SUPPLEMENTAL":
                for g in d.get("guilds") or []:
                    gid = str(g.get("id"))
                    raw.setdefault(gid, {"id": gid})["voice_states"] = g.get("voice_states") or []
                supp_at = time.time()
            elif op == 0 and t == "GUILD_CREATE":
                gid = str(d.get("id"))
                raw.setdefault(gid, {"id": gid}).update(d)
    except Exception as exc:
        dbg["error"] = repr(exc)
    finally:
        ws.close()

    infos = [_summarize_guild(g, me_id) for g in raw.values()]
    if all_out is not None:
        all_out.extend(infos)
    dbg.update(
        guilds=len(raw),
        with_channels=sum(1 for g in raw.values() if "channels" in g),
        with_voice=sum(1 for g in raw.values() if g.get("voice_states")),
    )
    ranked = [g for g in infos if g["vcs"]]
    ranked.sort(key=lambda g: (g["stream_rank"], g["vcs"][0][2], g["voice_total"], g["members"]), reverse=True)
    ranked = ranked[:limit]
    if any(not g["members"] for g in ranked):
        st, data = _discord_api_get("https://discord.com/api/v9/users/@me/guilds?with_counts=true", token, super_props)
        if st == 200 and isinstance(data, list):
            approx = {str(x.get("id")): x.get("approximate_member_count", 0) for x in data}
            for g in ranked:
                g["members"] = g["members"] or int(approx.get(g["id"], 0) or 0)
    return ranked


def rest_guild_vcs(token: str, super_props: str, g: dict, me_id: str, limit: int | None = None) -> list[tuple] | None:
    gid = str(g["id"])
    cst, chans = _discord_api_get(f"https://discord.com/api/v9/guilds/{gid}/channels", token, super_props)
    if cst != 200 or not isinstance(chans, list):
        return None
    gst, gfull = _discord_api_get(f"https://discord.com/api/v9/guilds/{gid}", token, super_props)
    afk_id = str(gfull.get("afk_channel_id") or "") if gst == 200 and isinstance(gfull, dict) else ""
    cands = sorted(
        (c for c in chans if c.get("type") in (2, 13) and not is_afk_channel(str(c.get("id")), c.get("name", ""), afk_id)),
        key=lambda c: c.get("position", 0),
    )[:limit]
    base = PERMISSION_ALL if g.get("owner") else None
    if base is None and g.get("permissions") is not None:
        base = _perm_int(g.get("permissions"))
    member_roles, fetched = None, False
    vcs = []
    for c in cands:
        ow = c.get("permission_overwrites") or []
        ok = None
        if base is not None:
            if base & PERMISSION_ADMINISTRATOR or not ow:
                ok = stream_verdict(base)
            else:
                if not fetched:
                    member_roles, fetched = fetch_member_roles(token, super_props, gid, me_id), True
                if member_roles is not None:
                    ok = stream_verdict(apply_overwrites(base, gid, me_id, member_roles, ow))
        vcs.append((str(c["id"]), c.get("name", "voice"), None, ok))
    vcs.sort(key=lambda v: STREAM_ORDER[v[3]])
    return vcs


def rest_active_servers(token: str, super_props: str, limit: int = 3) -> list[dict]:
    st, data = _discord_api_get("https://discord.com/api/v9/users/@me/guilds?with_counts=true", token, super_props)
    if st != 200 or not isinstance(data, list):
        return []
    me_id = extract_account_snowflake(token)
    data.sort(key=lambda g: (g.get("approximate_presence_count") or 0, g.get("approximate_member_count") or 0), reverse=True)
    out: list[dict] = []
    for g in data[:10]:
        vcs = rest_guild_vcs(token, super_props, g, me_id, limit=6)
        if not vcs:
            continue
        out.append({
            "id": str(g["id"]), "name": g.get("name", "Unknown server"),
            "members": int(g.get("approximate_member_count") or 0), "online": int(g.get("approximate_presence_count") or 0),
            "vcs": vcs[:3], "voice_total": 0,
        })
    out.sort(key=lambda r: 0 if any(v[3] is not False for v in r["vcs"]) else 1)
    return out[:limit]


def format_recommendation(r: dict) -> str:
    members = f"{r['members']:,} members" if r["members"] else "members n/a"
    vcs = ", ".join((f"{name} ({n})" if n is not None else name) + f" {STREAM_MARK[ok]}" for _cid, name, n, ok in r["vcs"])
    online = f" • {r['online']:,} online" if r.get("online") else ""
    tag = "Recommended" if any(v[3] is not False for v in r["vcs"]) else "No stream access"
    return f"{tag} {r['name']} • {members}{online} • {vcs}"


def resolve_server(token: str, super_props: str, text: str) -> tuple[str, str]:
    if text.isdigit():
        return text, ""
    st, data = _discord_api_get("https://discord.com/api/v9/users/@me/guilds", token, super_props)
    if st != 200 or not isinstance(data, list):
        return "", f"could not list your servers (HTTP {st})"
    hits = [g for g in data if str(g.get("name", "")).lower() == text.lower()]
    if not hits:
        return "", f"no server named '{text}' in your account"
    if len(hits) > 1:
        return "", f"{len(hits)} servers are named '{text}', use the server id instead"
    return str(hits[0]["id"]), ""


def resolve_voice_channel(token: str, super_props: str, guild_id: str, text: str) -> tuple[str, str]:
    if text.isdigit():
        return text, ""
    st, data = _discord_api_get(f"https://discord.com/api/v9/guilds/{guild_id}/channels", token, super_props)
    if st != 200 or not isinstance(data, list):
        return "", f"could not list channels (HTTP {st})"
    hits = [c for c in data if c.get("type") in (2, 13) and str(c.get("name", "")).lower() == text.lower()]
    if not hits:
        return "", f"no voice channel named '{text}' in that server"
    if len(hits) > 1:
        return "", f"{len(hits)} voice channels are named '{text}', use the channel id instead"
    return str(hits[0]["id"]), ""


class GatewayStreamEngine:

    def __init__(self, state: AccountSessionState, session: RuntimeClientContext, console: Console) -> None:
        self.state = state
        self.session = session
        self.console = console
        self.ws: MiniWebSocket | None = None
        self.voice_conn: VoiceConnection | None = None
        self.stream_conn: VoiceConnection | None = None
        self.running = False
        self.heartbeat_interval = 41.25
        self.sequence: int | None = None
        self.start_time = 0.0

        self.gateway_session_id = ""
        self.user_id = ""
        self.stream_key = ""

        self.voice_session_id = ""
        self.voice_token = ""
        self.voice_endpoint = ""
        self.voice_connected = False

        self.stream_token = ""
        self.stream_endpoint = ""
        self.stream_connected = False
        self.stream_ever_active = False
        self._stream_recreate_attempts = 0
        self._user_left_vc = False
        self.on_live = None

        self._status_thread: threading.Thread | None = None

    def start_stream(self, guild_id: str, channel_id: str, max_seconds: float = 0.0) -> None:
        C = self.console
        C.rule()
        C.info(f"{C.MAGENTA}Headless Gateway Live Streamer{C.WHITE}")
        C.rule()
        C.info("connecting to discord gateway (wss://gateway.discord.gg)...")

        self.ws = MiniWebSocket(GATEWAY_URL, path="/?v=9&encoding=json")
        try:
            self.ws.connect()
        except Exception as exc:
            C.err("gateway", f"connection failed: {exc}")
            C.rule()
            input(f"  {C.ORANGE}›{C.RESET} press enter to return to menu")
            return

        C.ok("gateway", "connected")
        self.running = True
        self.start_time = time.time()
        self.user_id = _user_id_from_token(self.state.token) or ""
        self.stream_ever_active = False
        self._stream_recreate_attempts = 0
        self._user_left_vc = False

        event_thread = threading.Thread(
            target=self._event_loop,
            args=(guild_id, channel_id),
            daemon=True,
        )
        event_thread.start()

        self._status_thread = threading.Thread(
            target=self._status_display,
            daemon=True,
        )
        self._status_thread.start()

        print()
        C.info(f"{C.GREY}press enter at any time to stop streaming...{C.RESET}")
        deadline = (self.start_time + max_seconds) if max_seconds > 0 else 0.0
        if deadline:
            C.info(f"{C.GREY}auto stop after {max_seconds / 3600.0:g}h{C.RESET}")
        C.rule()
        try:
            import msvcrt
            while self.running:
                if msvcrt.kbhit():
                    ch = msvcrt.getch()
                    if ch in (b'\r', b'\n', b'\x03'):
                        break
                if deadline and time.time() >= deadline:
                    C.info("requested stream time reached, stopping...")
                    break
                time.sleep(0.1)
        except Exception:
            while self.running:
                if deadline and time.time() >= deadline:
                    C.info("requested stream time reached, stopping...")
                    break
                time.sleep(0.5)

        self._cleanup(guild_id)

    def _status_display(self) -> None:
        while self.running:
            time.sleep(60)
            if not self.running:
                break
            elapsed = time.time() - self.start_time
            hours = elapsed / 3600.0
            mins = int(elapsed / 60)
            if self.stream_connected:
                status = f"{self.console.MAGENTA}🔴 LIVE{self.console.RESET}"
            elif self.voice_connected:
                status = f"{self.console.CYAN}⏳ starting stream{self.console.RESET}"
            else:
                status = f"{self.console.YELLOW}⏳ reconnecting{self.console.RESET}"
            self.console.live(
                "stream",
                f"{status} · {mins}m ({hours:.2f}h) elapsed"
            )

    def _reconnect(self, guild_id: str, channel_id: str, can_resume: bool = True) -> bool:
        C = self.console
        if not self.running:
            return False

        self.stream_connected = False
        self.voice_connected = False

        if self.stream_conn:
            try:
                self.stream_conn.close()
            except Exception:
                pass
            self.stream_conn = None

        if self.voice_conn:
            try:
                self.voice_conn.close()
            except Exception:
                pass
            self.voice_conn = None

        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass
            self.ws = None

        attempts = 0
        backoff = 3
        while self.running:
            attempts += 1
            C.warn("gateway", f"reconnecting to gateway in {backoff}s (attempt {attempts})...")
            for _ in range(backoff * 10):
                if not self.running:
                    return False
                time.sleep(0.1)

            try:
                self.ws = MiniWebSocket(GATEWAY_URL, path="/?v=9&encoding=json")
                self.ws.connect()

                hello_msg = None
                for _ in range(15):
                    m = self.ws.recv(timeout=1.0)
                    if isinstance(m, dict) and m.get("op") == "close":
                        code = m.get("code")
                        reason = m.get("reason", "")
                        if code == 4004:
                            C.err("auth", "fatal gateway authentication failure (code 4004: invalid token)")
                            C.err("auth", "please use Option 3 in the menu to update your token.")
                            self.running = False
                            return False
                    if m and m.get("op") == 10:
                        hello_msg = m
                        break
                    time.sleep(0.1)

                if not hello_msg:
                    C.warn("gateway", "did not receive hello from gateway, retrying...")
                    self.ws.close()
                    self.ws = None
                    backoff = min(15, backoff + 2)
                    continue

                d_hello = hello_msg.get("d", {})
                self.heartbeat_interval = d_hello.get("heartbeat_interval", 41250) / 1000.0

                self.ws.send(json.dumps({"op": 1, "d": self.sequence}))

                resumed = False
                if can_resume and self.gateway_session_id and self.sequence is not None:
                    C.info("attempting to resume gateway session (op 6)...")
                    try:
                        self.ws.send(json.dumps({
                            "op": 6,
                            "d": {
                                "token": self.state.token,
                                "session_id": self.gateway_session_id,
                                "seq": self.sequence,
                            },
                        }))

                        res_msg = self.ws.recv(timeout=4.0)
                        if res_msg:
                            op_res = res_msg.get("op")
                            t_res = res_msg.get("t")
                            if op_res == 0 and t_res == "RESUMED":
                                C.ok("gateway", "session resumed successfully")
                                resumed = True
                            elif op_res == 9:
                                C.warn("gateway", "resume failed (invalid session), falling back to identify")
                                time.sleep(1.0)
                            elif op_res == 0 and t_res == "READY":
                                self._handle_dispatch("READY", res_msg.get("d", {}), guild_id, channel_id)
                                resumed = True
                    except Exception:
                        resumed = False

                if not resumed:
                    C.info("sending identify (op 2)...")
                    self.ws.send(json.dumps({
                        "op": 2,
                        "d": {
                            "token": self.state.token,
                            "capabilities": 16381,
                            "properties": self.session.props_dict,
                            "presence": {
                                "status": "online",
                                "since": 0,
                                "activities": [],
                                "afk": False,
                            },
                        },
                    }))

                    test_msg = self.ws.recv(timeout=2.0)
                    if isinstance(test_msg, dict) and test_msg.get("op") == "close":
                        code = test_msg.get("code")
                        if code == 4004:
                            C.err("auth", "fatal gateway authentication failure (code 4004: invalid token)")
                            C.err("auth", "please use Option 3 in the menu to update your token.")
                            self.running = False
                            return False
                    elif isinstance(test_msg, dict) and test_msg.get("op") == 0 and test_msg.get("t") == "READY":
                        self._handle_dispatch("READY", test_msg.get("d", {}), guild_id, channel_id)
                        resumed = True

                if resumed:
                    self.ws.send(json.dumps({
                        "op": 4,
                        "d": {
                            "guild_id": guild_id,
                            "channel_id": channel_id,
                            "self_mute": False,
                            "self_deaf": False,
                            "self_video": False,
                        },
                    }))
                    C.ok("voice", f"re-joining voice channel {C.ORANGE}{channel_id}{C.RESET}")

                C.ok("gateway", "gateway reconnected successfully")
                return True

            except Exception as exc:
                C.warn("gateway", f"reconnect attempt {attempts} failed: {exc}")
                if self.ws:
                    self.ws.close()
                    self.ws = None
                backoff = min(15, backoff + 2)

        return False

    def _event_loop(self, guild_id: str, channel_id: str) -> None:
        last_hb = time.time()

        while self.running:
            try:
                if not self.ws or self.ws.closed:
                    if not self._reconnect(guild_id, channel_id):
                        break
                    last_hb = time.time()
                    continue

                now = time.time()

                if now - last_hb > self.heartbeat_interval:
                    if self.ws and not self.ws.closed:
                        try:
                            self.ws.send(json.dumps({"op": 1, "d": self.sequence}))
                            last_hb = now
                        except Exception as exc:
                            self.console.warn("gateway", f"heartbeat failed ({exc})")
                            if not self._reconnect(guild_id, channel_id):
                                break
                            last_hb = time.time()
                            continue

                msg = self.ws.recv(timeout=1.0)
                if not msg:
                    continue

                if isinstance(msg, dict) and msg.get("op") == "close":
                    code = msg.get("code")
                    reason = msg.get("reason", "")
                    self.console.warn("gateway", f"gateway closed connection (code {code}: {reason})")
                    if code == 4004:
                        self.console.err("auth", "fatal: gateway authentication failed (code 4004: invalid token)")
                        self.console.err("auth", "please use Option 3 in the menu to update your token.")
                        self.running = False
                        break
                    elif code in (4010, 4011, 4012, 4013, 4014):
                        self.console.err("gateway", f"fatal gateway error (code {code}: {reason}) — stopping.")
                        self.running = False
                        break

                    if not self._reconnect(guild_id, channel_id):
                        break
                    last_hb = time.time()
                    continue

                op = msg.get("op")
                seq = msg.get("s")
                t = msg.get("t")
                d = msg.get("d") or {}

                if seq is not None:
                    self.sequence = seq

                if op == 10:
                    self.heartbeat_interval = d.get("heartbeat_interval", 41250) / 1000.0
                    last_hb = time.time()

                    self.ws.send(json.dumps({"op": 1, "d": self.sequence}))

                    self.ws.send(json.dumps({
                        "op": 2,
                        "d": {
                            "token": self.state.token,
                            "capabilities": 16381,
                            "properties": self.session.props_dict,
                            "presence": {
                                "status": "online",
                                "since": 0,
                                "activities": [],
                                "afk": False,
                            },
                        },
                    }))

                elif op == 1:
                    self.ws.send(json.dumps({"op": 1, "d": self.sequence}))
                    last_hb = now

                elif op == 11:
                    pass

                elif op == 0:
                    if t == "RESUMED":
                        self.console.ok("gateway", "gateway session resumed successfully")
                        self.ws.send(json.dumps({
                            "op": 4,
                            "d": {
                                "guild_id": guild_id,
                                "channel_id": channel_id,
                                "self_mute": False,
                                "self_deaf": False,
                                "self_video": False,
                            },
                        }))
                    else:
                        self._handle_dispatch(t, d, guild_id, channel_id)

                elif op == 7:
                    self.console.warn("gateway", "discord requested gateway reconnect (op 7)")
                    if not self._reconnect(guild_id, channel_id, can_resume=True):
                        break
                    last_hb = time.time()

                elif op == 9:
                    resumable = bool(d)
                    self.console.warn("gateway", f"session invalidated (op 9, resumable={resumable})")
                    if not self._reconnect(guild_id, channel_id, can_resume=resumable):
                        break
                    last_hb = time.time()

            except Exception as exc:
                if not self.running:
                    break
                self.console.warn("gateway", f"connection dropped: {exc}")
                if not self._reconnect(guild_id, channel_id):
                    break
                last_hb = time.time()

    def _handle_dispatch(self, event_type: str, d: dict, guild_id: str, channel_id: str) -> None:
        C = self.console

        if event_type == "READY":
            self.gateway_session_id = d.get("session_id", "")
            user_data = d.get("user", {})
            username = user_data.get("username", "?")
            self.user_id = str(user_data.get("id", self.user_id))
            C.ok("auth", f"gateway authenticated ({username})")

            self.ws.send(json.dumps({
                "op": 4,
                "d": {
                    "guild_id": guild_id,
                    "channel_id": channel_id,
                    "self_mute": False,
                    "self_deaf": False,
                    "self_video": False,
                },
            }))
            C.ok("voice", f"joining voice channel {C.ORANGE}{channel_id}{C.RESET}")

        elif event_type == "VOICE_STATE_UPDATE":
            if str(d.get("user_id")) == str(self.user_id):
                active_channel = d.get("channel_id")
                new_session = d.get("session_id", "")
                if new_session:
                    self.voice_session_id = new_session

                if (self.voice_connected or self.stream_connected or self.stream_ever_active):
                    if active_channel is None:
                        C.warn("voice", "user manually disconnected from voice channel in Discord app")
                        C.info("gracefully stopping stream engine and saving accumulated stream hours...")
                        self._user_left_vc = True
                        self.voice_connected = False
                        self.stream_connected = False
                        self.running = False
                        return

                    if str(active_channel) != str(channel_id):
                        C.warn("voice", f"user moved to another voice channel ({active_channel}) in Discord app")
                        C.info("stopping stream on old channel and saving accumulated stream hours...")
                        self._user_left_vc = True
                        self.voice_connected = False
                        self.stream_connected = False
                        self.running = False
                        return

                C.ok("voice", f"voice state updated (session: {self.voice_session_id[:8]}...)")

        elif event_type == "VOICE_SERVER_UPDATE":
            token = d.get("token", "")
            endpoint = d.get("endpoint") or ""
            v_guild = d.get("guild_id", guild_id)

            if not endpoint or not token:
                C.err("voice", "empty voice server endpoint/token")
                return

            if self.voice_connected:
                C.warn("voice", "voice server update received, re-establishing voice connection...")
                if self.voice_conn:
                    self.voice_conn.close()
                self.voice_connected = False

            self.voice_token = token
            self.voice_endpoint = endpoint
            C.ok("voice", f"voice server: {endpoint}")

            session_id = self.voice_session_id or self.gateway_session_id
            self.voice_conn = VoiceConnection(
                endpoint=self.voice_endpoint,
                server_id=v_guild,
                user_id=self.user_id,
                session_id=session_id,
                token=self.voice_token,
                console=C,
                label="voice",
                is_stream=False,
            )

            C.info("performing voice WebSocket handshake...")
            if self.voice_conn.connect():
                self.voice_conn.start_heartbeat()
                self.voice_conn.send_speaking(False)
                self.voice_conn.start_silence_pump()
                self.voice_connected = True
                C.ok("voice", f"{C.GREEN}voice connection established (ssrc={self.voice_conn.ssrc}){C.RESET}")

                time.sleep(0.5)
                C.info("requesting Go Live stream (op 18 Stream Create)...")
                try:
                    self.ws.send(json.dumps({
                        "op": 18,
                        "d": {
                            "type": "guild",
                            "guild_id": guild_id,
                            "channel_id": channel_id,
                            "preferred_region": None,
                        },
                    }))
                except Exception as exc:
                    C.warn("stream", f"stream create send error: {exc}")
            else:
                C.err("voice", "voice WebSocket handshake FAILED, retrying in 3s...")
                def _retry_voice():
                    time.sleep(3.0)
                    if self.running and self.ws and not self.ws.closed:
                        try:
                            self.ws.send(json.dumps({
                                "op": 4,
                                "d": {
                                    "guild_id": guild_id,
                                    "channel_id": channel_id,
                                    "self_mute": False,
                                    "self_deaf": False,
                                    "self_video": False,
                                },
                            }))
                        except Exception:
                            pass
                threading.Thread(target=_retry_voice, daemon=True).start()

        elif event_type == "STREAM_CREATE":
            self.stream_key = d.get("stream_key", "")
            C.ok("stream", f"Go Live created! stream_key: {C.CYAN}{self.stream_key}{C.RESET}")
            first_live = not self.stream_ever_active
            self.stream_connected = True
            self.stream_ever_active = True
            self._stream_recreate_attempts = 0
            if first_live and self.on_live:
                try:
                    self.on_live()
                except Exception as exc:
                    C.warn("watcher", f"could not start the watcher: {exc}")

            if self.voice_conn and self.voice_conn.ws and not self.voice_conn.ws.closed:
                try:
                    video_ssrc = self.voice_conn.ssrc + 1
                    rtx_ssrc = self.voice_conn.ssrc + 2
                    self.voice_conn.ws.send(json.dumps({
                        "op": 12,
                        "d": {
                            "audio_ssrc": self.voice_conn.ssrc,
                            "video_ssrc": video_ssrc,
                            "rtx_ssrc": rtx_ssrc,
                            "streams": [
                                {
                                    "type": "screen",
                                    "rid": "100",
                                    "ssrc": video_ssrc,
                                    "rtx_ssrc": rtx_ssrc,
                                    "active": True,
                                    "quality": 100,
                                    "max_bitrate": 8000000,
                                    "max_framerate": 30,
                                    "max_resolution": {"type": "fixed", "width": 1920, "height": 1080},
                                }
                            ],
                        },
                    }))
                    self.voice_conn.send_speaking(True)
                except Exception:
                    pass

            print()
            C.rule()
            C.live("stream", f"{C.MAGENTA}● BROADCASTING LIVE{C.RESET}, discord shows your account as {C.MAGENTA}LIVE{C.RESET}")
            C.rule()
            print(f"  {C.YELLOW}⚠️  CRITICAL REQUIREMENTS FOR STREAM TIME TO ACCUMULATE:{C.RESET}")
            print(f"  {C.ORANGE}1.{C.RESET} {C.WHITE}An alt account (or friend) {C.YELLOW}MUST be in the voice channel{C.RESET}{C.WHITE} sitting or watching.{C.RESET}")
            print(f"     {C.GREY}› Discord will NOT count streaming hours if you stream alone in an empty channel!{C.RESET}")
            print(f"  {C.ORANGE}2.{C.RESET} {C.WHITE}Ensure {C.YELLOW}'Use data to personalize my Discord experience'{C.RESET}{C.WHITE} is turned {C.GREEN}ON{C.RESET}{C.WHITE}.{C.RESET}")
            print(f"     {C.GREY}› Check in Discord: User Settings (⚙) → Data & Privacy → Personalization.{C.RESET}")
            C.rule()
            if HAS_CRYPTO and self.voice_conn and self.voice_conn.secret_key:
                C.ok("audio", "encrypted silence pump active (cryptography lib found)")
            else:
                C.info(f"{C.GREY}tip: pip install cryptography (enables encrypted audio frames){C.RESET}")

        elif event_type == "STREAM_SERVER_UPDATE":
            token = d.get("token", "")
            endpoint = d.get("endpoint") or ""
            if endpoint and token:
                self.stream_token = token
                self.stream_endpoint = endpoint
                C.ok("stream", f"stream media route: {endpoint}")

        elif event_type == "STREAM_DELETE":
            self.stream_connected = False
            if self.stream_conn:
                self.stream_conn.close()
                self.stream_conn = None

            if not self.running or not self.voice_connected or self._user_left_vc:
                return

            if self._stream_recreate_attempts < 3:
                self._stream_recreate_attempts += 1
                C.warn("stream", f"stream stopped by server, re-requesting Go Live in 2s (attempt {self._stream_recreate_attempts}/3)...")
                def _recreate():
                    time.sleep(2.0)
                    if self.running and self.ws and not self.ws.closed and self.voice_connected and not self._user_left_vc:
                        try:
                            self.ws.send(json.dumps({
                                "op": 18,
                                "d": {
                                    "type": "guild",
                                    "guild_id": guild_id,
                                    "channel_id": channel_id,
                                    "preferred_region": None,
                                },
                            }))
                        except Exception:
                            pass
                threading.Thread(target=_recreate, daemon=True).start()
            else:
                C.err("stream", "stream stopped repeatedly by server — stopping session to prevent rate limits.")
                self.running = False

        elif event_type == "VOICE_CONNECTION_STATUS":
            status = d.get("state", "")
            if status:
                C.info(f"voice connection status: {status}")

    def _cleanup(self, guild_id: str) -> None:
        C = self.console
        self.running = False

        if self.ws and not self.ws.closed and self.stream_key:
            try:
                self.ws.send(json.dumps({
                    "op": 19,
                    "d": {"stream_key": self.stream_key},
                }))
            except Exception:
                pass

        if self.ws and not self.ws.closed and not self._user_left_vc:
            try:
                self.ws.send(json.dumps({
                    "op": 4,
                    "d": {
                        "guild_id": guild_id,
                        "channel_id": None,
                        "self_mute": False,
                        "self_deaf": False,
                        "self_video": False,
                    },
                }))
            except Exception:
                pass

        if self.stream_conn:
            self.stream_conn.close()
        if self.voice_conn:
            self.voice_conn.close()
        if self.ws:
            time.sleep(0.3)
            self.ws.close()

        if (self.stream_connected or self.stream_ever_active) and self.start_time > 0:
            elapsed = time.time() - self.start_time
            hours = elapsed / 3600.0
            if elapsed >= 10:
                self.state.total_stream_hours_claimed += hours
                self.state.total_stream_sessions += 1
                self.state.save()
                print()
                C.ok("stream", f"ended · {elapsed:.0f}s ({hours:.2f}h) streamed live")
                C.info(f"{C.GREY}note: badge progression typically syncs within 24-48 hours.{C.RESET}")
        else:
            print()
            C.info("stream session ended.")

        C.rule()
        input(f"  {C.ORANGE}›{C.RESET} press enter to return to menu")





STAR_REPO = "ItzMeShadow999/BadgeMaxxer"


GITHUB_CLIENT_ID = "Ov23liu4TVIYMEPe5ArO"
STAR_ERROR = ""


def _github_request(url: str, data: dict | None = None, token: str = "",
                    accept: str = "application/vnd.github+json") -> tuple[int, Any]:
    global STAR_ERROR
    headers = {"user-agent": "BadgeMaxxer", "accept": accept}
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
        headers["content-type"] = "application/x-www-form-urlencoded"
    if token:
        headers["authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            raw = exc.read().decode("utf-8", "replace")
        except Exception:
            raw = ""
        STAR_ERROR = f"GitHub rate limit hit (HTTP {status}), try again in a while" if status in (403, 429) else f"HTTP {status}"
    except Exception as exc:
        STAR_ERROR = f"{type(exc).__name__}: {exc}"
        return 0, {}
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, {}


def github_device_login(T: "TerminalInterface") -> str:
    if GITHUB_CLIENT_ID.startswith("PASTE"):
        T.failure("github", "GITHUB_CLIENT_ID is not set in BadgeMaxxer.py (create an OAuth App with Device Flow enabled).")
        return ""
    st, d = _github_request("https://github.com/login/device/code", data={"client_id": GITHUB_CLIENT_ID}, accept="application/json")
    if st != 200 or not isinstance(d, dict) or "device_code" not in d:
        reason = (d.get("error_description") if isinstance(d, dict) else "") or STAR_ERROR or st
        T.failure("github", f"could not start GitHub login ({reason})")
        return ""
    url = d.get("verification_uri", "https://github.com/login/device")
    T.log(f"Open {T.COLOR_PRIMARY}{url}{T.COLOR_TEXT} and enter the code {T.COLOR_PRIMARY}{d['user_code']}{T.COLOR_TEXT}")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    T.log("waiting for you to approve in the browser...")
    interval = int(d.get("interval", 5))
    deadline = time.time() + int(d.get("expires_in", 900))
    while time.time() < deadline:
        time.sleep(interval)
        st, r = _github_request(
            "https://github.com/login/oauth/access_token",
            data={"client_id": GITHUB_CLIENT_ID, "device_code": d["device_code"],
                  "grant_type": "urn:ietf:params:oauth:grant-type:device_code"},
            accept="application/json",
        )
        if st == 0:
            continue
        if isinstance(r, dict) and r.get("access_token"):
            return str(r["access_token"])
        err = r.get("error") if isinstance(r, dict) else None
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval = int(r.get("interval", interval + 5))
            continue
        if err == "access_denied":
            T.failure("github", "login was cancelled")
            return ""
        if err == "expired_token":
            break
        T.failure("github", f"login failed ({err or st})")
        return ""
    T.failure("github", "login timed out, run BadgeMaxxer again")
    return ""


def check_star(token: str) -> tuple[bool | None, int]:
    st, _ = _github_request(f"https://api.github.com/user/starred/{STAR_REPO}", token=token)
    if st == 204:
        return True, st
    if st == 404:
        return False, st
    return None, st


class ApplicationController:
    def __init__(self) -> None:
        self.terminal = TerminalInterface()
        self.stream_console = Console()
        self.state = AccountSessionState.restore()
        self.runtime_context: RuntimeClientContext | None = None
        self.fabricator: TelemetryEventFabricator | None = None
        self.catalog: list[DetectableTitle] = []

    def _star_gate(self, quiet: bool = False) -> bool:
        T = self.terminal
        token = self.state.github_token
        for _ in range(2):
            if not token:
                if quiet:
                    T.failure("star", "GitHub login is no longer valid.")
                    return False
                T.log(f"BadgeMaxxer needs you to log in with GitHub and star https://github.com/{STAR_REPO}")
                token = github_device_login(T)
                if not token:
                    return False
                self.state.github_token = token
                self.state.persist()
            elif not quiet:
                T.log("checking your star...")
            starred, st = check_star(token)
            if st != 401:
                break
            self.state.github_token = ""
            self.state.persist()
            token = ""
        else:
            T.failure("star", "GitHub rejected the login, run BadgeMaxxer again.")
            return False
        if starred is None:
            T.failure("star", f"could not verify your star ({STAR_ERROR or st}). BadgeMaxxer needs this check to run.")
            return False
        if not starred:
            T.failure("star", f"you have not starred {STAR_REPO}. Star it, then run BadgeMaxxer again.")
            return False
        if not quiet:
            T.success("star", "verified, thanks for the star")
        return True

    def start(self) -> None:
        zoom_out_terminal()
        self.terminal.display_header()
        time.sleep(0.3)

        if not self._star_gate():
            self.terminal.failure("star", "Star the repo to use BadgeMaxxer.")
            return

        if not self.state.token:
            self._prompt_account_token()
        else:
            self.terminal.success("auth", "User token loaded from state")

        if not self.state.token:
            self.terminal.failure("token", "Account token is required.")
            return

        if not self.state.cookie:
            self.terminal.log("fetching base cookies from discord.com...")
            base = fetch_base_cookies()
            if base:
                self.state.cookie = base
                self.state.persist()
                self.terminal.success("cookie", "Base cookies fetched and saved (no cf_clearance)")
                self.terminal.log("If requests get blocked (403), add cf_clearance via 'Refresh Credentials & Cookie'.")
        if not self.state.cookie:
            self.terminal.display_header()
            self._prompt_clearance_cookie()
        else:
            self.terminal.success("auth", "Clearance cookie loaded from state")

        if not self.state.cookie:
            self.terminal.failure("cookie", "cf_clearance cookie is required.")
            return

        self.terminal.log("loading detectable games catalog...")
        self.catalog = load_game_catalog()
        if not self.catalog:
            self.terminal.failure("catalog", "Unable to retrieve detectable games catalog.")
            return
        self.terminal.success("catalog", f"{len(self.catalog)} verified titles loaded")

        if not self.state.fingerprint:
            self.terminal.warning("fingerprint", "Executable fingerprint not set (optional for hours, recommended for variety).")

        self.terminal.log("synchronizing analytics credentials...")
        self._renew_session()
        try:
            synchronize_credentials(self.state, self.runtime_context.encoded_properties)
        except Exception as exc:
            self.terminal.failure("auth", str(exc))
            return
        self.terminal.success("auth", "Ingestion pipeline initialized")

        time.sleep(0.5)
        self.render_main_menu()

    def _renew_session(self) -> None:
        self.runtime_context = RuntimeClientContext.initialize()
        self.fabricator = TelemetryEventFabricator(self.state, self.runtime_context)

    def _prompt_account_token(self) -> None:
        T = self.terminal
        T.log("Fetch the token with the Discord console snippet?")
        T.log(TOKEN_SNIPPET)
        print_cookie_help(T, TOKEN_HELP)
        if arrow_menu("Use snippet", ["Yes", "No (enter manually)"]) == 0:
            try:
                if os.name == "nt":
                    subprocess.run(["clip"], input=TOKEN_SNIPPET.encode("ascii"), check=True)
                    T.log("Copied to clipboard.")
            except Exception:
                pass
            T.log("Open Discord (web or desktop), press Ctrl+Shift+I, open Console, paste, press Enter.")
            T.log("The snippet copies your token to the clipboard itself. Come back here and paste it below.")
        else:
            T.log("Paste your Discord account authorization token:")
        val = input(f"  {T.COLOR_MUTED}token:{T.COLOR_RESET} ").strip().strip("\"'`")
        if val:
            self.state.token = val
            self.state.persist()
            self.terminal.success("token", "Saved to local state")

    def _prompt_clearance_cookie(self) -> None:
        print_cookie_help(self.terminal)
        self.terminal.log("Paste your cf_clearance cookie header value:")
        val = extract_cookie_header(input(f"  {self.terminal.COLOR_MUTED}cookie:{self.terminal.COLOR_RESET} "))
        if val:
            self.state.cookie = val
            self.state.persist()
            self.terminal.success("cookie", "Saved to local state")

    def _reconfigure_credentials(self) -> None:
        T = self.terminal
        T.log("Update cookie header? [y/n]")
        ans = input(f"  {T.COLOR_MUTED}›{T.COLOR_RESET} ").strip().lower()
        if ans in ("y", "yes"):
            print_cookie_help(T)
            T.log("Paste fresh cookie header:")
            new_ck = extract_cookie_header(input(f"  {T.COLOR_MUTED}cookie:{T.COLOR_RESET} "))
            if new_ck:
                self.state.cookie = new_ck
                T.success("cookie", "Updated")

        T.log("Refreshing analytics token from Discord...")
        try:
            self.state.fetched_at = 0
            synchronize_credentials(self.state, self.runtime_context.encoded_properties)
        except Exception as exc:
            T.failure("auth", str(exc))
            return
        self._renew_session()
        self.state.persist()
        T.success("auth", "Credentials refreshed successfully")
        time.sleep(1)

    def _ensure_runtime_readiness(self) -> bool:
        if not self.state.cookie:
            self.terminal.failure("cookie", "Missing cookie. Use Option 3 to configure.")
            return False
        if self.state.requires_refresh:
            try:
                synchronize_credentials(self.state, self.runtime_context.encoded_properties)
            except Exception as exc:
                self.terminal.failure("auth", str(exc))
                return False
            self._renew_session()
        return bool(self.state.analytics_token)

    def _pause(self) -> None:
        T = self.terminal
        T.separator()
        input(f"  {T.COLOR_PRIMARY}›{T.COLOR_RESET} Press enter to return to menu")

    def _ask_hours(self, label: str, default: float, allow_zero: bool = False) -> float | None:
        T = self.terminal
        raw = input(f"  {T.COLOR_MUTED}{label} [{default:g}]:{T.COLOR_RESET} ").strip()
        if not raw:
            return default
        try:
            value = float(raw)
        except ValueError:
            T.failure("input", f"Invalid hours specified: {raw}")
            return None
        if value < 0 or (value == 0 and not allow_zero):
            T.failure("input", "Hours must be greater than 0.")
            return None
        return value

    def _pick_number(self, title: str, presets: list, fmt, default, ask_custom):
        options = [fmt(v) for v in presets] + ["Custom...", "Back to Main menu"]
        idx = arrow_menu(title, options, start=presets.index(default) if default in presets else 0)
        if idx is None or idx == len(presets) + 1:
            return BACK_TO_MENU
        if idx == len(presets):
            return ask_custom()
        return presets[idx]

    def _ask_claim_params(self, label: str, default_games: int | None, default_hours: float):
        T = self.terminal
        total = len(self.catalog)
        T.log(f"{T.COLOR_PRIMARY}{label}{T.COLOR_RESET}")

        def custom_games() -> int | None:
            raw = input(f"  {T.COLOR_MUTED}Games count (1-{total}):{T.COLOR_RESET} ").strip()
            if not raw.isdigit() or int(raw) < 1:
                T.failure("input", "Game count must be a whole number of at least 1.")
                return None
            return min(int(raw), total)

        game_presets = sorted({v for v in (1, 3, 5, 10, 25, 50, 100) if v < total} | {total})
        count = self._pick_number(
            "How many games?", game_presets,
            lambda v: f"All ({v})" if v == total else f"{v} game{'s' if v != 1 else ''}",
            min(default_games or total, total), custom_games,
        )
        if count == BACK_TO_MENU or count is None:
            return count
        hour_presets = [0.5, 1.0, 2.0, 5.0, 10.0, 24.0, 50.0, 100.0]
        hours = self._pick_number(
            "Hours per game?", hour_presets, lambda v: f"{v:g}h per game", default_hours,
            lambda: self._ask_hours("Hours per game", default_hours),
        )
        if hours == BACK_TO_MENU or hours is None:
            return hours
        return count, hours

    def _run_claim(self, count: int, hours: float) -> int:
        T = self.terminal
        selected_titles = self._filter_title_selection(count)
        if not selected_titles:
            T.failure("catalog", "No titles selected.")
            return 0

        duration_ms = int(hours * 3600 * 1000)
        total_aggregate = len(selected_titles) * hours
        print()
        T.log(f"Submitting {T.COLOR_PRIMARY}{hours:g}h{T.COLOR_TEXT} across {T.COLOR_PRIMARY}{len(selected_titles)}{T.COLOR_TEXT} titles ({total_aggregate:,.0f}h total)")
        T.separator()

        engine = IngestionPipeline(self.fabricator, self.terminal)
        accepted = engine.execute_stream(
            selected_titles,
            lambda title: self.fabricator.assemble_complete_session(title, duration_ms)
        )

        print()
        T.success("completed", f"{accepted}/{len(selected_titles)} titles processed ({accepted * hours:,.0f}h total)")
        self.state.total_games_claimed += accepted
        self.state.total_hours_claimed += accepted * hours
        self.state.persist()

        T.log(f"{T.COLOR_MUTED}note: discord badge progression updates every 24-48h on analytics sync.{T.COLOR_RESET}")
        return accepted

    def trigger_playtime_ingestion(self, default_games: int | None = None, default_hours: float = 1.0, label: str = "Game Time") -> None:
        if not self._ensure_runtime_readiness():
            self._pause()
            return
        self.terminal.display_header()
        params = self._ask_claim_params(label, default_games, default_hours)
        if params == BACK_TO_MENU:
            return
        if params:
            self._run_claim(*params)
        self._pause()

    def _pick_stream_hours(self, allow_zero: bool = False, fresh_screen: bool = False) -> float | None:
        T = self.terminal
        if fresh_screen:
            T.display_header()
        done = self.state.total_stream_hours_claimed
        options = []
        for tier, name, req in STREAM_TIERS:
            left = req - done
            note = "reached" if left <= 0 else f"+{left:,.1f}h"
            options.append(f"{'●' if left <= 0 else '○'} Tier {tier:2d} · {name:<12s} {req:>5,d}h  {note}")
        options.append("Custom hours...")
        options.append("Back to Main menu")
        T.log(f"{T.COLOR_PRIMARY}Streaming{T.COLOR_RESET} · {done:,.1f}h logged so far")
        idx = arrow_menu("Stream to which tier?", options)
        if idx is None or idx == len(STREAM_TIERS) + 1:
            return BACK_TO_MENU
        if idx == len(STREAM_TIERS):
            return self._ask_hours("Stream hours" + (" (0 to skip)" if allow_zero else ""), STREAM_DEFAULT_HOURS, allow_zero)
        left = STREAM_TIERS[idx][2] - done
        if left <= 0:
            T.warning("stream", "Tier already reached by logged hours. Use Custom hours to stream anyway.")
            return None
        return left

    def trigger_streaming(self) -> None:
        if not self._ensure_runtime_readiness():
            self._pause()
            return
        hours = self._pick_stream_hours(fresh_screen=True)
        if hours == BACK_TO_MENU:
            return
        if hours is None:
            self._pause()
            return
        self.run_gateway_live_streamer(hours)

    def level_up_all(self) -> None:
        T = self.terminal
        if not self._ensure_runtime_readiness():
            self._pause()
            return
        T.display_header()
        T.log("Level up all: press enter to accept each default")
        print()
        time_params = self._ask_claim_params("Game Time", TIME_DEFAULT_GAMES, TIME_DEFAULT_HOURS)
        if time_params == BACK_TO_MENU:
            return
        if not time_params:
            self._pause()
            return
        print()
        variety_params = self._ask_claim_params("Game Variety", None, VARIETY_DEFAULT_HOURS)
        if variety_params == BACK_TO_MENU:
            return
        if not variety_params:
            self._pause()
            return
        print()
        stream_hours = self._pick_stream_hours(allow_zero=True)
        if stream_hours == BACK_TO_MENU:
            return
        if stream_hours is None:
            self._pause()
            return

        print()
        T.separator()
        T.log(f"{T.COLOR_PRIMARY}Game Time{T.COLOR_RESET}")
        self._run_claim(*time_params)
        T.separator()
        T.log(f"{T.COLOR_PRIMARY}Game Variety{T.COLOR_RESET}")
        self._run_claim(*variety_params)
        if stream_hours > 0:
            T.separator()
            T.log(f"{T.COLOR_PRIMARY}Streaming{T.COLOR_RESET}")
            self.run_gateway_live_streamer(stream_hours)
        else:
            self._pause()

    def _filter_title_selection(self, desired_amount: int) -> list[DetectableTitle]:
        existing_pool = {item.title_id for item in self.catalog}
        unprocessed = [item.title_id for item in self.catalog if item.title_id not in self.state.used_games]
        processed = [gid for gid in self.state.used_games if gid in existing_pool]

        if len(unprocessed) >= desired_amount:
            chosen = unprocessed[:desired_amount]
        else:
            chosen = unprocessed
            if processed:
                needed = desired_amount - len(chosen)
                rotated = processed[needed:] + processed[:needed]
                chosen.extend(rotated[:needed])

        self.state.used_games = [gid for gid in self.state.used_games if gid not in chosen] + chosen
        registry = {item.title_id: item for item in self.catalog}
        return [registry[gid] for gid in chosen if gid in registry]

    def configure_executable_fingerprint(self) -> None:
        T = self.terminal
        account_id = extract_account_snowflake(self.state.token)
        if not account_id:
            T.failure("fingerprint", "Valid token required to derive user identity.")
            time.sleep(1)
            return
        if os.name != "nt":
            T.failure("fingerprint", "Fingerprint generation requires Windows OS.")
            time.sleep(1)
            return

        T.log("Generate executable fingerprint bound to account and machine.")
        T.log(f"Account Snowflake: {T.COLOR_PRIMARY}{account_id}{T.COLOR_RESET}")
        T.log("Provide an executable (.exe) path or active game Process ID (PID):")
        raw_input = input(f"  {T.COLOR_MUTED}path or PID:{T.COLOR_RESET} ").strip().strip('"')
        if not raw_input:
            T.log("Operation cancelled.")
            time.sleep(1)
            return

        target_pid = int(raw_input) if raw_input.isdigit() else 0
        target_path = "" if target_pid else raw_input
        if target_path and not Path(target_path).exists():
            T.failure("fingerprint", f"File path does not exist: {target_path}")
            time.sleep(1.5)
            return

        T.log("Generating signature via PowerShell PE analyzer...")
        try:
            signature = build_binary_signature(account_id, file_path=target_path, active_pid=target_pid)
        except Exception as exc:
            T.failure("fingerprint", str(exc))
            time.sleep(2)
            return

        self.state.fingerprint = signature
        self.state.persist()
        T.success("fingerprint", f"Assigned ({len(signature)} chars) · saved to state")
        time.sleep(1.5)

    def inspect_profile(self) -> None:
        T = self.terminal
        if not self.state.token:
            T.failure("auth", "No user token configured.")
            T.separator()
            input(f"  {T.COLOR_PRIMARY}›{T.COLOR_RESET} Press enter to continue")
            return

        T.log("Retrieving profile data from Discord...")
        uid = extract_account_snowflake(self.state.token)
        encoded_props = self.runtime_context.encoded_properties if self.runtime_context else ""
        if not uid:
            try:
                probe_request = urllib.request.Request(
                    REST_IDENTITY_URL,
                    headers={
                        "authorization": self.state.token,
                        "user-agent": USER_AGENT_IDENTIFIER,
                        "x-super-properties": encoded_props,
                    },
                )
                with urllib.request.urlopen(probe_request, timeout=10) as resp:
                    uid = json.loads(resp.read().decode("utf-8")).get("id", "")
            except Exception:
                pass

        if not uid:
            T.failure("profile", "Unable to resolve account identity snowflake.")
            T.separator()
            input(f"  {T.COLOR_PRIMARY}›{T.COLOR_RESET} Press enter to continue")
            return

        target_url = f"{DISCORD_USERS_API}/{uid}/profile?with_mutual_guilds=false&with_mutual_friends_count=false"
        request = urllib.request.Request(
            target_url,
            headers={
                "authorization": self.state.token,
                "user-agent": USER_AGENT_IDENTIFIER,
                "x-super-properties": encoded_props,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as resp:
                profile_payload = json.loads(resp.read().decode("utf-8"))

            user_obj = profile_payload.get("user", {})
            badges_list = profile_payload.get("badges", [])
            T.separator()
            user_handle = user_obj.get("username", "Unknown")
            global_name = user_obj.get("global_name")
            display_name = f"{global_name} (@{user_handle})" if global_name else f"@{user_handle}"
            T.success("account", f"{display_name} · ID: {uid}")

            if badges_list:
                T.log(f"Profile Badges ({len(badges_list)}):")
                for badge in badges_list:
                    bid = badge.get("id", "badge")
                    desc = badge.get("description", "")
                    T.log(f"  {T.COLOR_PRIMARY}•{T.COLOR_RESET} {T.COLOR_TEXT}{bid}{T.COLOR_RESET}: {desc}")
            else:
                T.log("No public badges equipped on profile.")
        except Exception as exc:
            T.failure("profile", f"Failed to retrieve profile: {exc}")

        T.separator()
        input(f"  {T.COLOR_PRIMARY}›{T.COLOR_RESET} Press enter to continue")

    def _choose_stream_target(self) -> tuple[str, str] | None:
        C = self.stream_console
        props = self.runtime_context.encoded_properties
        st, me = _discord_api_get("https://discord.com/api/v9/users/@me", self.state.token, props)
        if st == 401:
            C.err("auth", "your token was rejected (HTTP 401), update it with 'Refresh Credentials & Cookie'")
            time.sleep(1.5)
            return None
        if st == 200:
            C.ok("account", f"signed in as {me.get('global_name') or me.get('username')} ({me.get('id')})")
        C.info("scanning your servers for crowded voice channels (up to 15s)...")
        dbg: dict = {}
        all_guilds: list[dict] = []
        try:
            recs = scan_busy_servers(self.state.token, self.runtime_context.props_dict, self.runtime_context.encoded_properties, debug=dbg, all_out=all_guilds)
        except Exception as exc:
            recs = []
            dbg["error"] = repr(exc)
        if not recs:
            C.warn("scan", "no live voice data from the gateway, falling back to the token API (servers by online members)")
            recs = rest_active_servers(self.state.token, props)
            if recs:
                C.info(f"{C.GREY}live voice counts are not available this way, an alt must join the channel you pick{C.RESET}")
        if not recs:
            C.warn("scan", "nothing to recommend, enter a target manually")
            ev = ", ".join(f"{k}x{v}" for k, v in (dbg.get("events") or {}).items()) or "none"
            C.info(f"{C.GREY}scan debug: events [{ev}] · servers {dbg.get('guilds', 0)} · with channels {dbg.get('with_channels', 0)}"
                   f" · with voice users {dbg.get('with_voice', 0)} · close {dbg.get('close')} · error {dbg.get('error') or 'none'}{C.RESET}")
        print()
        if recs:
            C.info(f"{C.GREY}AFK channels are skipped · ✓ you can Go Live there · ✗ you cannot · ? could not be checked{C.RESET}")
        while True:
            options = [format_recommendation(r) for r in recs]
            options += ["Browse all streamable servers", "Enter server and voice channel manually", "Back to Main menu"]
            idx = arrow_menu("Where do you want to stream?", options)
            if idx is None or idx == len(options) - 1:
                return None
            if idx < len(recs):
                guild_id, channel_id = recs[idx]["id"], recs[idx]["vcs"][0][0]
            elif idx == len(recs):
                guild_id, channel_id = self._browse_stream_targets(all_guilds)
                if not guild_id:
                    continue
            else:
                guild_id, channel_id = self._ask_stream_target_manually()
                if not guild_id:
                    continue
            print()
            C.info("verifying server, voice channel, and streaming permissions...")
            valid, _info = validate_stream_target(
                token=self.state.token,
                super_props=self.runtime_context.encoded_properties,
                guild_id=guild_id,
                channel_id=channel_id,
                console=C,
            )
            if valid:
                self.state.last_guild_id = guild_id
                self.state.last_channel_id = channel_id
                self.state.save()
                return guild_id, channel_id
            print()

    def _browse_stream_targets(self, all_guilds: list[dict]) -> tuple[str, str]:
        C = self.stream_console
        token, props = self.state.token, self.runtime_context.encoded_properties
        me_id = extract_account_snowflake(token)
        servers: list[dict] = []
        if any(g["all_vcs"] for g in all_guilds):
            for g in all_guilds:
                if any(v[3] is not False for v in g["all_vcs"]):
                    servers.append({"id": g["id"], "name": g["name"], "members": g["members"], "vcs": g["all_vcs"], "raw": None,
                                    "rank": (g["browse_rank"], g["voice_total"], g["members"])})
        else:
            C.info("reading your server list...")
            st, data = _discord_api_get("https://discord.com/api/v9/users/@me/guilds?with_counts=true", token, props)
            if st != 200 or not isinstance(data, list):
                C.err("servers", f"could not list your servers (HTTP {st})")
                return "", ""
            for g in data:
                servers.append({"id": str(g["id"]), "name": g.get("name", "Unknown server"), "members": int(g.get("approximate_member_count") or 0),
                                "vcs": None, "raw": g,
                                "rank": (0, int(g.get("approximate_presence_count") or 0), int(g.get("approximate_member_count") or 0))})
        servers.sort(key=lambda sv: sv["rank"], reverse=True)
        if not servers:
            C.warn("servers", "no server where you can Go Live was found")
            return "", ""
        while True:
            opts = []
            for sv in servers:
                members = f"{sv['members']:,} members" if sv["members"] else "members n/a"
                if sv["vcs"] is None:
                    opts.append(f"{sv['name']} • {members}")
                else:
                    k = sum(1 for v in sv["vcs"] if v[3] is not False)
                    opts.append(f"{sv['name']} • {members} • {k} streamable VC{'s' if k != 1 else ''}")
            idx = arrow_menu("Which server?", opts + ["Back"])
            if idx is None or idx == len(servers):
                return "", ""
            sv = servers[idx]
            if sv["vcs"] is None:
                C.info(f"checking voice channels in {sv['name']}...")
                sv["vcs"] = rest_guild_vcs(token, props, sv["raw"], me_id) or []
            ok = [v for v in sv["vcs"] if v[3] is not False]
            if not ok:
                C.warn("channels", f"no voice channel in {sv['name']} where you can Go Live")
                continue
            vopts = [(f"{name} ({n} in VC)" if n else name) + f" {STREAM_MARK[flag]}" for _cid, name, n, flag in ok]
            j = arrow_menu(f"Voice channel in {sv['name']}?", vopts + ["Back to servers"])
            if j is None or j == len(ok):
                continue
            return sv["id"], ok[j][0]

    def _ask_stream_target_manually(self) -> tuple[str, str]:
        C = self.stream_console
        props = self.runtime_context.encoded_properties
        last_g, last_c = self.state.last_guild_id, self.state.last_channel_id
        g_raw = input(f"  {C.GREY}server (id or exact name){f' [{last_g}]' if last_g else ''}:{C.RESET} ").strip() or last_g
        c_raw = input(f"  {C.GREY}voice channel (id or exact name){f' [{last_c}]' if last_c else ''}:{C.RESET} ").strip() or last_c
        if not g_raw or not c_raw:
            C.err("input", "a server and a voice channel are required")
            return "", ""
        guild_id, err = resolve_server(self.state.token, props, g_raw)
        if err:
            C.err("server", err)
            return "", ""
        channel_id, err = resolve_voice_channel(self.state.token, props, guild_id, c_raw)
        if err:
            C.err("channel", err)
            return "", ""
        return guild_id, channel_id

    def run_gateway_live_streamer(self, hours: float = 0.0) -> None:
        target = self._choose_stream_target()
        if not target:
            return
        guild_id, channel_id = target

        engine = GatewayStreamEngine(self.state, self.runtime_context, self.stream_console)
        opened: dict[str, Any] = {}
        engine.on_live = lambda: opened.update(proc=self._open_watcher(guild_id, channel_id))
        try:
            engine.start_stream(guild_id, channel_id, max_seconds=hours * 3600.0)
        finally:
            proc = opened.get("proc")
            if proc is not None and proc.poll() is None:
                proc.terminate()

    def _open_watcher(self, guild_id: str = "", channel_id: str = ""):
        C = self.stream_console
        if not WATCHER_SCRIPT.is_file():
            C.warn("watcher", f"Watcher/stream_watcher.py not found in {WATCHER_DIR}")
            return None
        target = extract_account_snowflake(self.state.token)
        if not target:
            C.err("watcher", "could not read this account's id from the token")
            return None
        if os.name != "nt":
            C.warn("watcher", f"run it in another terminal: python \"{WATCHER_SCRIPT}\" {target}")
            return None
        for package in WATCHER_PACKAGES:
            if importlib.util.find_spec(package) is None:
                C.info(f"installing {package} for the watcher ...")
                if not _install_package(package):
                    C.err("watcher", f"could not install {package}, run: pip install {package}")
                    return None
                importlib.invalidate_caches()
        cmd = [sys.executable, str(WATCHER_SCRIPT), target]
        if guild_id and channel_id:
            cmd += ["--guild", guild_id, "--channel", channel_id]
        proc = subprocess.Popen(cmd, cwd=str(WATCHER_DIR), creationflags=subprocess.CREATE_NEW_CONSOLE)
        C.ok("watcher", "opened in a new window, it asks for your MAIN account token there (hidden, never saved)")
        return proc

    def start_watcher(self) -> None:
        T = self.terminal
        T.display_header()
        T.log(f"{T.COLOR_PRIMARY}Start Watcher{T.COLOR_RESET}")
        T.log("Opens the watcher for your MAIN account. It joins the voice channel of this account and watches its stream.")
        T.log("The main account must be in the same server. The watcher asks for its token in its own window.")
        self._open_watcher()
        self._pause()

    def render_main_menu(self) -> None:
        T = self.terminal
        options = [
            "Level up all",
            "Game Time",
            "Game Variety",
            "Streaming",
            "Start Watcher",
            "Inspect Discord Profile & Badges",
            "Refresh Credentials & Cookie",
            "Configure Executable Fingerprint",
            "Exit",
        ]
        while True:
            T.display_header()
            T.log(f"Detectable Titles: {T.COLOR_PRIMARY}{len(self.catalog)}{T.COLOR_TEXT}")
            T.log(f"Cumulative Logged: {T.COLOR_PRIMARY}{self.state.total_games_claimed}{T.COLOR_TEXT} titles · {T.COLOR_PRIMARY}{self.state.total_hours_claimed:,.0f}h{T.COLOR_TEXT} playtime")
            T.log(f"Total Stream Hours: {T.COLOR_PRIMARY}{self.state.total_stream_hours_claimed:,.1f}h{T.COLOR_TEXT} ({self.state.total_stream_sessions} sessions)")
            print()

            choice = arrow_menu("Select what badge to level", options)
            print()
            if choice is None or choice == 8:
                break
            if not self._star_gate(quiet=True):
                T.failure("star", "Star check failed, BadgeMaxxer is stopping.")
                break
            if choice == 0:
                self.level_up_all()
            elif choice == 1:
                self.trigger_playtime_ingestion(TIME_DEFAULT_GAMES, TIME_DEFAULT_HOURS, "Game Time")
            elif choice == 2:
                self.trigger_playtime_ingestion(None, VARIETY_DEFAULT_HOURS, "Game Variety")
            elif choice == 3:
                self.trigger_streaming()
            elif choice == 4:
                self.start_watcher()
            elif choice == 5:
                self.inspect_profile()
            elif choice == 6:
                self._reconfigure_credentials()
            elif choice == 7:
                self.configure_executable_fingerprint()


def execute_entrypoint() -> None:
    try:
        ApplicationController().start()
    except KeyboardInterrupt:
        print()
        TerminalInterface().warning("exit", "Execution halted by user.")


if __name__ == "__main__":
    execute_entrypoint()
