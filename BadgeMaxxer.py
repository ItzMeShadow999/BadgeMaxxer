#!/usr/bin/env python3
from __future__ import annotations

import atexit
import base64
import codecs
import importlib
import importlib.util
import json
import math
import os
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator, Sequence

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
try:
    import secret_store
except ImportError:
    sys.exit("lib/secret_store.py is missing next to BadgeMaxxer.py. Re-run the installer to get all files.")

SECRET_FIELDS = ("token", "cookie", "analytics_token", "github_token", "fingerprint")

SYSTEM_PYTHON_POSIX = os.name != "nt" and sys.prefix == sys.base_prefix


def _install_package(name: str) -> bool:
    try:
        result = run_with_loader(
            name,
            [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", name],
            timeout=300,
        )
    except Exception:
        return False
    return result.returncode == 0


WORKSPACE_DIR = Path(__file__).resolve().parent
STATE_STORAGE_PATH = WORKSPACE_DIR / "session.json"
WATCHER_DIR = WORKSPACE_DIR / "Watcher"
WATCHER_SCRIPT = WATCHER_DIR / "stream_watcher.py"
WATCHER_FILES = ("stream_watcher.py", "watcher_voice.py", "watcher_common.py")
WATCHER_PACKAGES = ("websockets", "davey")
STREAMER_DIR = WORKSPACE_DIR / "Streamer"
STREAMER_SCRIPT = STREAMER_DIR / "Streamer.js"
STREAMER_STATS = STREAMER_DIR / "streamer_stats.json"
STREAMER_PINS = {"@lng2004/discord.js-selfbot-v13": "3.7.2", "@dank074/discord-video-stream": "7.0.0"}
STREAMER_PACKAGES = tuple(STREAMER_PINS)
STREAMER_NODE_MIN = (22, 18)
DATABASE_STORAGE_PATH = WORKSPACE_DIR / "data" / "games.json"

REST_IDENTITY_URL = "https://discord.com/api/v9/users/@me?with_analytics_token=true"
DISCORD_USERS_API = "https://discord.com/api/v9/users"
DISCORD_INVITES_API = "https://discord.com/api/v9/invites"
SUPPORT_INVITE_CODE = "GB5uSAKRq9"
SUPPORT_INVITE_URL = f"https://discord.gg/{SUPPORT_INVITE_CODE}"
TELEMETRY_INGEST_URL = "https://discord.com/api/v9/science"
UPSTREAM_METRICS_URL = "https://cordapi.dolfi.es/api/v2/properties/windows"
DISCORD_CATALOG_URL = "https://cdn.discordapp.com/detectables/games.json"

DISPATCH_BATCH_LIMIT = 50
TIME_DEFAULT_GAMES = 3
TIME_DEFAULT_HOURS = 10.0
GAME_TIME_MENU = "Game Time (patched by Discord)"
MAX_GAME_HOURS = 24.0
VARIETY_DEFAULT_HOURS = 1.0
STREAM_DEFAULT_HOURS = 1.0
AUTO_GUILD_ID = "1573044682051551262"
AUTO_CHANNEL_ID = "1573245332492656702"
STREAM_ROTATE_SEC = 4 * 3600
STREAM_REJOIN_GAP_SEC = 3.0
NETWORK_COOLDOWN_SEC = 0.3
TOKEN_EXPIRY_THRESHOLD_SEC = 12 * 3600
TOKEN_SNIPPET = (
    "copy(((w=webpackChunkdiscord_app).push([[Symbol()],{},o=>{try{Object.values(o.c)"
    ".some(e=>e.exports?.setToken&&(w.t=e.exports.getToken()))}catch{}}]),w.t))"
)
COOKIE_HELP = (
    "How to get your cookie (it is in the @me request in the Network tab):",
    "1. Open https://discord.com/app in your browser and log in.",
    "2. Press F12 (Ctrl+Shift+I) and open the Network tab.",
    "3. Type @me in the filter box, then reload the page (F5) so the request shows up.",
    "4. Click the @me request (discord.com/api/v9/users/@me).",
    "5. Headers > Request Headers > find cookie and copy its whole value.",
    "   Or: right-click the @me request > Copy > Copy as cURL (bash) and paste that, the cookie is picked out for you.",
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
CREDENTIALS_MENU = "Refresh Credentials & Cookie"
LEVEL_BADGE_IDS = (20, 21, 19, 18)  # Game Time, Game Variety, Streaming, Account Age
ESC_SEQ_TIMEOUT = 0.5

DESKTOP_CLIENT_VERSION = "1.0.9253"
DESKTOP_BUILD_IDENTIFIER = 594031
PLATFORM_BUILD_IDENTIFIER = 88414
PLATFORM_OS_REVISION = "10.0.26200"
CLIENT_LOCALE = "en-GB"
CLIENT_TIMEZONE = "Europe/Oslo"
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


_TOKEN_SHAPE = re.compile(r"[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{20,}")
_PASTE_NOISE = re.compile(r"\x1b\[20[01]~|[​-‍⁠﻿]")


def clean_token(raw: str) -> tuple[str, str]:
    val = _PASTE_NOISE.sub("", raw).strip().strip("\"'`").strip()
    val = re.sub(r"(?i)^(authorization\s*:\s*|bearer\s+)", "", val).strip().strip("\"'`")
    if "webpackChunk" in val or val.startswith("copy("):
        return "", ("That is the console snippet, not the token. Run it in the Discord console first "
                    "(a browser may ask you to type 'allow pasting'), then paste the token it copied.")
    if not _TOKEN_SHAPE.fullmatch(val) or not extract_account_snowflake(val).isdigit():
        return "", "That does not look like a Discord token (three parts separated by dots, no spaces)."
    return val, ""


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

    SUBTITLE = "Discord badge leveling  ·  Game Time (patched)  ·  Game Variety  ·  Streaming"
    MIN_ROWS_FULL = 28
    MIN_ROWS_BODY = 10

    def __init__(self) -> None:
        self.art = [ln.rstrip() for ln in BANNER_ART.strip("\n").split("\n")]
        self.art_width = max(len(ln) for ln in self.art)
        self.pinned = False
        self.region_top = 1

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
        self.pinned = False
        self.region_top = 1
        out = "\x1b]0;BadgeMaxxer\x07\x1b[r\x1b[2J\x1b[3J\x1b[H" + "\n".join(lines) + "\n"
        if rows - top >= self.MIN_ROWS_BODY:
            out += f"\x1b[{top};{rows}r\x1b[{top};1H"
            self.pinned = True
            self.region_top = top
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

TERMINAL_ZOOM_OUT_MAX = 10


def banner_fits() -> bool:
    cols, rows = shutil.get_terminal_size((120, 30))
    return cols > BANNER.art_width and rows >= BANNER.MIN_ROWS_FULL


def zoom_out_terminal() -> None:
    if os.name != "nt" or not sys.stdout.isatty() or banner_fits():
        return
    try:
        if os.environ.get("WT_SESSION"):
            import ctypes
            keybd = ctypes.windll.user32.keybd_event
            for _ in range(TERMINAL_ZOOM_OUT_MAX):
                keybd(0x11, 0, 0, 0)
                keybd(0xBD, 0, 0, 0)
                keybd(0xBD, 0, 2, 0)
                keybd(0x11, 0, 2, 0)
                time.sleep(0.08)
                if banner_fits():
                    break
            time.sleep(0.1)
        else:
            cols, rows = shutil.get_terminal_size((120, 30))
            os.system(f"mode con: cols={max(cols, BANNER.art_width + 2)} lines={max(rows, BANNER.MIN_ROWS_FULL + 1)}")
    except Exception:
        pass


TERMINAL_ZOOM_IN_MAX = 30


def _wt_zoom(vk: int) -> bool:
    import ctypes
    keybd = ctypes.windll.user32.keybd_event
    before = shutil.get_terminal_size((120, 30))
    keybd(0x11, 0, 0, 0)
    keybd(vk, 0, 0, 0)
    keybd(vk, 0, 2, 0)
    keybd(0x11, 0, 2, 0)
    for _ in range(50):
        time.sleep(0.01)
        if shutil.get_terminal_size((120, 30)) != before:
            time.sleep(0.04)
            return True
    return False


def fit_terminal_zoom() -> None:
    if os.name != "nt" or not sys.stdout.isatty() or not os.environ.get("WT_SESSION"):
        zoom_out_terminal()
        return
    try:
        for _ in range(TERMINAL_ZOOM_OUT_MAX):
            if banner_fits():
                break
            if not _wt_zoom(0xBD):
                break
        if banner_fits():
            for _ in range(TERMINAL_ZOOM_IN_MAX):
                if not _wt_zoom(0xBB):
                    break
                if not banner_fits():
                    _wt_zoom(0xBD)
                    break
        time.sleep(0.05)
    except Exception:
        pass


def force_black_console() -> None:
    if os.name != "nt" or not sys.stdout.isatty() or os.environ.get("WT_SESSION"):
        return
    try:
        import ctypes
        from ctypes import wintypes

        class COORD(ctypes.Structure):
            _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

        class SMALL_RECT(ctypes.Structure):
            _fields_ = [("Left", ctypes.c_short), ("Top", ctypes.c_short),
                        ("Right", ctypes.c_short), ("Bottom", ctypes.c_short)]

        class CONSOLE_SCREEN_BUFFER_INFOEX(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.c_ulong),
                ("dwSize", COORD),
                ("dwCursorPosition", COORD),
                ("wAttributes", ctypes.c_ushort),
                ("srWindow", SMALL_RECT),
                ("dwMaximumWindowSize", COORD),
                ("wPopupAttributes", ctypes.c_ushort),
                ("bFullscreenSupported", ctypes.c_int),
                ("ColorTable", ctypes.c_ulong * 16),
            ]

        kernel = ctypes.windll.kernel32
        kernel.GetStdHandle.restype = wintypes.HANDLE
        handle = kernel.GetStdHandle(-11)
        info = CONSOLE_SCREEN_BUFFER_INFOEX()
        info.cbSize = ctypes.sizeof(info)
        if not kernel.GetConsoleScreenBufferInfoEx(handle, ctypes.byref(info)):
            return
        if (info.wAttributes >> 4) & 0xF == 0 and info.ColorTable[0] == 0:
            return
        info.ColorTable[0] = 0
        fg = info.wAttributes & 0x0F
        info.wAttributes = fg if fg else 0x07
        info.srWindow.Right += 1
        info.srWindow.Bottom += 1
        kernel.SetConsoleScreenBufferInfoEx(handle, ctypes.byref(info))
    except Exception:
        pass


POSIX_TERMINALS = {
    "x-terminal-emulator": ["-e"],
    "gnome-terminal": ["--"],
    "ptyxis": ["--"],
    "kgx": ["--"],
    "konsole": ["-e"],
    "xfce4-terminal": ["-x"],
    "mate-terminal": ["-x"],
    "lxterminal": ["-e"],
    "qterminal": ["-e"],
    "terminator": ["-x"],
    "kitty": [],
    "alacritty": ["-e"],
    "foot": [],
    "wezterm": ["start", "--"],
    "ghostty": ["-e"],
    "xterm": ["-e"],
}
DESKTOP_TERMINALS = {
    "KDE": ["konsole"],
    "GNOME": ["ptyxis", "kgx", "gnome-terminal"],
    "XFCE": ["xfce4-terminal"],
    "MATE": ["mate-terminal"],
    "LXQT": ["qterminal"],
    "LXDE": ["lxterminal"],
    "X-CINNAMON": ["gnome-terminal"],
}


def find_terminal_posix() -> list[str] | None:
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return None
    candidates = list(POSIX_TERMINALS.items())
    for desktop in reversed(os.environ.get("XDG_CURRENT_DESKTOP", "").upper().split(":")):
        for name in reversed(DESKTOP_TERMINALS.get(desktop, [])):
            candidates.insert(0, (name, POSIX_TERMINALS[name]))
    preferred = shlex.split(os.environ.get("TERMINAL", ""))
    if preferred:
        name, extra = preferred[0], preferred[1:]
        candidates.insert(0, (name, extra or POSIX_TERMINALS.get(os.path.basename(name), ["-e"])))
    for name, args in candidates:
        path = shutil.which(name)
        if path:
            return [path, *args]
    return None


class PosixWatcherProcess:
    def __init__(self, terminal: subprocess.Popen, cmd: list[str]) -> None:
        self.terminal = terminal
        self.cmdline = "\0".join(cmd)
        self.started = time.time()

    def _watcher_pids(self) -> list[int]:
        pids = []
        try:
            entries = os.listdir("/proc")
        except OSError:
            return pids
        for entry in entries:
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/cmdline", "rb") as fh:
                    if fh.read().decode("utf-8", "ignore").rstrip("\0") == self.cmdline:
                        pids.append(int(entry))
            except OSError:
                pass
        return pids

    def poll(self) -> int | None:
        if self.terminal.poll() is None or self._watcher_pids() or time.time() - self.started < 15:
            return None
        return self.terminal.poll()

    def terminate(self) -> None:
        for pid in self._watcher_pids():
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        if self.terminal.poll() is None:
            self.terminal.terminate()


def copy_to_clipboard_posix(text: str) -> bool:
    commands = []
    if os.environ.get("WAYLAND_DISPLAY"):
        commands.append(["wl-copy"])
    if os.environ.get("DISPLAY"):
        commands += [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
    for cmd in commands:
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode("utf-8"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=5)
                return True
            except Exception:
                continue
    return False


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
        raw = os.read(fd, 1)
        if raw and raw[0] >= 0xC0:
            need = 1 if raw[0] < 0xE0 else 2 if raw[0] < 0xF0 else 3
            while need and select.select([fd], [], [], ESC_SEQ_TIMEOUT)[0]:
                raw += os.read(fd, 1)
                need -= 1
        ch = raw.decode("utf-8", "ignore")
        if raw and not ch:
            return ""
        if ch == "\x1b":
            seq = ""
            while len(seq) < 2 and select.select([fd], [], [], ESC_SEQ_TIMEOUT)[0]:
                part = os.read(fd, 1)
                if not part:
                    break
                seq += part.decode("utf-8", "ignore")
            if not seq:
                return "esc"
            return {"[A": "up", "[B": "down", "[C": "right", "[D": "left", "OA": "up", "OB": "down"}.get(seq, "")
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    if not ch:
        return "esc"
    if ch in ("\r", "\n"):
        return "enter"
    if ch == "\x03":
        raise KeyboardInterrupt
    return ch.lower()


def menu_capacity() -> int:
    rows = shutil.get_terminal_size((120, 30)).lines
    return max(3, rows - BANNER.region_top - 1)


def arrow_menu(title: str, options: Sequence[str], hint: str = "↑/↓ move · enter select", start: int = 0) -> int | None:
    n = len(options)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print(f"  {title}")
        for i, opt in enumerate(options, 1):
            print(f"    {i}. {opt}")
        raw = input("  › ").strip()
        return int(raw) - 1 if raw.isdecimal() and 1 <= int(raw) <= n else None

    sel = start if 0 <= start < n else 0
    view = min(n, menu_capacity())
    off = max(0, min(sel - view // 2, n - view))

    def paint(first: bool) -> None:
        buf: list[str] = []
        if not first:
            buf.append(f"\x1b[{view}A")
        room = max(20, shutil.get_terminal_size((120, 30)).columns - 8)
        for i in range(off, off + view):
            raw = options[i]
            opt = raw if len(raw) <= room else raw[: room - 1] + "…"
            base = GOLD_BOLD if i == sel else "\x1b[37m"
            if opt.startswith("Recommended"):
                opt = "\x1b[92mRecommended" + base + opt[len("Recommended"):]
            more = ""
            if view < n:
                if i == off and off > 0:
                    more = " \x1b[90m▲"
                elif i == off + view - 1 and off + view < n:
                    more = " \x1b[90m▼"
            if i == sel:
                buf.append(f"\r\x1b[2K   {GOLD_BOLD}› {opt}{more}{ANSI_RESET}\n")
            else:
                buf.append(f"\r\x1b[2K     {base}{opt}{more}{ANSI_RESET}\n")
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
            if sel < off:
                off = sel
            elif sel >= off + view:
                off = sel - view + 1
            paint(False)
    finally:
        sys.stdout.write(f"\x1b[{view + 1}A\r\x1b[J\x1b[?25h")
        sys.stdout.flush()


def _cells(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in text)


def _fit_cells(text: str, width: int) -> str:
    """Cut text to at most width terminal cells (CJK characters take two), padded with spaces."""
    if _cells(text) > width:
        out, used = [], 0
        for ch in text:
            w = 2 if unicodedata.east_asian_width(ch) in "WF" else 1
            if used + w > width - 1:
                break
            out.append(ch)
            used += w
        text = "".join(out) + "…"
    return text + " " * max(0, width - _cells(text))


class LineLoader:

    def __init__(self) -> None:
        self.enabled = sys.stdout.isatty()
        self.frame = 0
        self.last_draw = 0.0
        self.active = False
        self.pct: float = 0.0
        self.dl_mb: float = 0.0
        self.total_mb: float = 0.0
        self._two_line = False
        self.sub: str = ""
        self.cur: str = ""
        self.force_bar: bool = False
        self._rows: int = 1

    @staticmethod
    def _width() -> int:
        return max(40, shutil.get_terminal_size((80, 24)).columns)

    def _bar(self, fill: int, width: int) -> str:
        """Return a coloured block bar of the given character width."""
        done = round(fill * width)
        done = max(0, min(done, width))
        filled = "█" * done
        empty  = "░" * (width - done)
        return f"{GOLD}{filled}\x1b[90m{empty}{ANSI_RESET}"

    def _size_str(self, mb: float) -> str:
        if mb < 1.0:
            return f"{mb * 1024:.0f} KB"
        return f"{mb:.1f} MB"

    def update(self, name: str, tail: str, force: bool = False, prefix: str = "Fetching ") -> None:
        if not self.enabled:
            return
        now = time.time()
        if not force and now - self.last_draw < 0.06:
            return
        self.last_draw = now

        w = self._width()
        line_w = min(w, 100) - 5
        end = (tail[:-5] if tail.endswith(" done") else tail).rjust(10)
        name_w = max(8, line_w - len(prefix) - 5 - len(end))
        label = f"{prefix}{_fit_cells(name, name_w)}.... {end}"
        spin = SPIN_FRAMES[self.frame % len(SPIN_FRAMES)]
        self.frame += 1

        if not self.active:
            sys.stdout.write("\x1b[?25l")
            self.active = True

        show_bar = self.force_bar or self.pct > 0.0 or self.dl_mb > 0.0
        rows = [f"  {GOLD}{spin}{ANSI_RESET} \x1b[37m{_fit_cells(label, w - 5)}{ANSI_RESET}"]

        if show_bar:
            pct_str = f"{int(self.pct * 100)}%"
            if self.total_mb > 0:
                size_str = f"{self._size_str(self.dl_mb)} / {self._size_str(self.total_mb)}"
            else:
                size_str = self._size_str(self.dl_mb)
            right_part = f"  {pct_str.rjust(4)}  {size_str}"
            bar_avail = max(10, w - 4 - len(right_part) - 2)
            if self.sub:
                sub = self.sub if len(self.sub) <= w - 8 else self.sub[: w - 9] + "…"
                rows.append(f"    \x1b[90m↳ {ANSI_RESET}\x1b[37m{sub}{ANSI_RESET}")
            rows.append(f"    {self._bar(self.pct, bar_avail)}{ANSI_RESET}\x1b[90m{right_part}{ANSI_RESET}")

        if self._rows > 1:
            sys.stdout.write(f"\x1b[{self._rows - 1}A")
        sys.stdout.write("\r")
        if len(rows) != self._rows:
            sys.stdout.write("\x1b[J")
        sys.stdout.write("\n".join("\x1b[2K" + r for r in rows))
        self._rows = len(rows)
        self._two_line = self._rows > 1
        sys.stdout.flush()

    def clear(self) -> None:
        if not self.enabled or not self.active:
            return
        w = self._width()
        blank = "\r" + " " * (w - 1) + "\r"
        if self._rows > 1:
            sys.stdout.write(f"\r\x1b[{self._rows - 1}A\x1b[J\x1b[?25h")
            self._rows = 1
            self._two_line = False
        else:
            sys.stdout.write(f"{blank}\x1b[?25h")
        sys.stdout.flush()
        self.active = False


import re as _re
_NPM_HTTP_RE  = _re.compile(r"npm http fetch GET 200 .+?(\d+)ms \((\d+) bytes\)", _re.IGNORECASE)
_NPM_STAGE_RE = _re.compile(r"npm timing (reify|resolve|fetch|link|audit)(?:Node)?:(\S+)", _re.IGNORECASE)
_NPM_FETCH_RE = _re.compile(r"http fetch GET \d+ (\S+)", _re.IGNORECASE)
_NPM_TGZ_VER_RE = _re.compile(r"-(\d[\w.+-]*)\.tgz$")


def _parse_npm_progress(line: str, loader: "LineLoader", fetched_bytes: list) -> None:
    m = _NPM_FETCH_RE.search(line)
    if not m:
        return
    path = urllib.parse.unquote(m.group(1).split("://", 1)[-1].split("/", 1)[-1])
    if "/-/" in path:
        name, rest = path.split("/-/", 1)
        v = _NPM_TGZ_VER_RE.search(rest)
        loader.cur = f"{name}@{v.group(1)}" if v else name
    elif path:
        loader.cur = f"resolving {path}"


def _scan_modules(root: str) -> tuple[int, float]:
    count = 0
    size = 0
    for dp, _dn, fn in os.walk(root):
        for f in fn:
            try:
                size += os.path.getsize(os.path.join(dp, f))
            except OSError:
                pass
        if "package.json" in fn:
            parent = os.path.basename(os.path.dirname(dp))
            grand = os.path.basename(os.path.dirname(os.path.dirname(dp)))
            if parent == "node_modules" or (parent.startswith("@") and grand == "node_modules"):
                count += 1
    return count, size / 1_048_576


def _npm_expected_packages(label: str, cmd: list[str], cwd: str | None, loader: "LineLoader") -> int:
    box: dict = {}

    def _dry() -> None:
        try:
            r = subprocess.run(
                cmd + ["--dry-run", "--json"], cwd=cwd, capture_output=True,
                text=True, encoding="utf-8", errors="replace", timeout=120,
            )
            box["out"] = r.stdout or ""
        except Exception:
            box["out"] = ""

    th = threading.Thread(target=_dry, daemon=True)
    th.start()
    loader.force_bar = True
    loader.sub = "resolving dependency tree"
    while th.is_alive():
        loader.update(label, "resolving", prefix="Installing ")
        time.sleep(0.08)
    out = box.get("out", "")
    try:
        data = json.loads(out[out.index("{"):])
        added = data.get("added", 0)
        return len(added) if isinstance(added, list) else int(added)
    except Exception:
        return 0


def run_with_loader(label: str, cmd: list[str], *, cwd: str | None = None, timeout: float | None = None) -> subprocess.CompletedProcess:
    """Run a subprocess while showing a spinner + live progress bar.

    For npm install commands the bar shows N% and MB/MB downloaded in real time.
    For other commands it falls back to a plain spinner.
    """
    loader = LineLoader()
    is_npm = any("npm" in str(c) for c in cmd)
    fetched_bytes: list[int] = [0]
    expected = 0
    if is_npm and "install" in [str(c) for c in cmd] and "--dry-run" not in cmd:
        try:
            expected = _npm_expected_packages(label, [str(c) for c in cmd], cwd, loader)
        finally:
            loader.clear()
    if is_npm:
        loader.force_bar = True

    if is_npm:
        verbose_cmd = [str(c) for c in cmd]
        if "--loglevel" not in " ".join(verbose_cmd):
            verbose_cmd = [verbose_cmd[0]] + ["--loglevel=verbose"] + verbose_cmd[1:]
        proc = subprocess.Popen(
            verbose_cmd, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace",
        )
    else:
        proc = subprocess.Popen(
            cmd, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            encoding="utf-8", errors="replace",
        )

    import threading, queue as _queue
    stderr_lines: list[str] = []
    stdout_lines: list[str] = []
    done_evt = threading.Event()

    def _drain(stream, store: list, parse: bool) -> None:
        for raw in stream:
            store.append(raw)
            if parse:
                _parse_npm_progress(raw, loader, fetched_bytes)
        done_evt.set()

    if is_npm:
        t_err = threading.Thread(target=_drain, args=(proc.stderr, stderr_lines, True), daemon=True)
        t_out = threading.Thread(target=_drain, args=(proc.stdout, stdout_lines, False), daemon=True)
        t_err.start()
        t_out.start()
    else:
        t_out = threading.Thread(target=_drain, args=(proc.stdout, stdout_lines, False), daemon=True)
        t_out.start()

    stop_mon = threading.Event()

    def _monitor() -> None:
        nm = os.path.join(cwd or os.getcwd(), "node_modules")
        base_pk, base_mb = _scan_modules(nm)
        while not stop_mon.is_set():
            pk, mb = _scan_modules(nm)
            done = max(0, pk - base_pk)
            dl = max(0.0, mb - base_mb)
            if expected > 0:
                frac = min(done / expected, 0.99)
                total = max(dl, dl / frac) if frac >= 0.1 else max(dl, 40.0)
                loader.pct = frac
                loader.total_mb = total
                count = f"{min(done, expected)}/{expected} packages"
            else:
                total = max(dl + 5.0, 40.0)
                loader.pct = min(dl / total, 0.95)
                loader.total_mb = total
                count = f"{done} packages"
            loader.dl_mb = dl
            loader.sub = f"{loader.cur}  ({count})" if loader.cur else count
            stop_mon.wait(0.35)

    if is_npm:
        threading.Thread(target=_monitor, daemon=True).start()

    start = time.time()
    timed_out = False
    try:
        while True:
            loader.update(label, "installing", prefix="Installing ")
            try:
                proc.wait(timeout=0.08)
                break
            except subprocess.TimeoutExpired:
                if timeout is not None and time.time() - start > timeout:
                    proc.kill()
                    proc.wait()
                    timed_out = True
                    break
        stop_mon.set()
        if is_npm and not timed_out:
            loader.sub = "done"
            loader.pct = 1.0
            loader.dl_mb = loader.total_mb if loader.total_mb > 0 else loader.dl_mb
        loader.update(label, "timed out" if timed_out else "done", force=True, prefix="Installing ")
    finally:
        loader.clear()

    if is_npm:
        t_err.join(timeout=2)
        t_out.join(timeout=2)
    else:
        t_out.join(timeout=2)

    output = "".join(stdout_lines) + "".join(stderr_lines)
    if timed_out:
        raise subprocess.TimeoutExpired(cmd, timeout, output=output)
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout=output, stderr="")


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
            force_black_console()

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
    r"Cookies|Value|cookie header|cookie|Network tab|Request Headers|authorization|@me)"
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


def read_pasted_line(prompt: str) -> str:
    parts = [input(prompt)]
    while parts[-1].rstrip().endswith(("\\", "^")):
        try:
            parts.append(input())
        except EOFError:
            break
    return " ".join(p.rstrip().rstrip("\\^").strip() for p in parts)


def extract_cookie_header(raw: str) -> str:
    raw = raw.strip()
    m = _COOKIE_IN_PASTE.search(raw)
    if not m and raw.lower().startswith("curl "):
        return ""
    val = (m.group(1) if m else raw).strip()
    if len(val) > 1 and val[0] == val[-1] and val[0] in "'\"":
        val = val[1:-1].strip()
    return val


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
    support_join_for: str = ""

    @classmethod
    def restore(cls) -> "AccountSessionState":
        if STATE_STORAGE_PATH.exists():
            try:
                raw_data = json.loads(STATE_STORAGE_PATH.read_text(encoding="utf-8"))
                if not isinstance(raw_data, dict):
                    raise ValueError("not a JSON object")
            except ValueError as exc:
                broken = STATE_STORAGE_PATH.with_name(f"{STATE_STORAGE_PATH.name}.broken-{int(time.time())}")
                try:
                    os.replace(STATE_STORAGE_PATH, broken)
                    print(f"  session.json could not be read ({exc}), moved it to {broken.name} and started fresh.", file=sys.stderr)
                except OSError:
                    pass
                return cls()
            except OSError:
                return cls()
            try:
                known_keys = set(cls().__dict__.keys())
                instance = cls(**{k: v for k, v in raw_data.items() if k in known_keys and k != "used_games"})
                instance.used_games = raw_data.get("used_games", [])
                migrate = False
                unreadable = set()
                for key in SECRET_FIELDS:
                    stored = str(getattr(instance, key) or "")
                    migrate = migrate or bool(stored and not secret_store.is_protected(stored) and secret_store.available())
                    value = secret_store.reveal(key, stored)
                    if not value and secret_store.is_protected(stored):
                        unreadable.add(key)
                    setattr(instance, key, value)
                instance._unreadable = unreadable
                if migrate:
                    try:
                        instance.persist()
                    except OSError:
                        pass
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
        if not isinstance(existing, dict):
            existing = {}
        # A secret that could not be read (locked keyring, no session) is still empty here.
        # Keep its stored reference instead of overwriting it with nothing.
        unreadable = {key for key in getattr(self, "_unreadable", set()) if not getattr(self, key)}
        kept = {key: existing[key] for key in unreadable if existing.get(key)}
        self._unreadable = unreadable
        existing.update(asdict(self))
        for key in SECRET_FIELDS:
            existing[key] = secret_store.protect(key, str(existing.get(key) or ""))
        existing.update(kept)
        # Write a temporary file and swap it in, so a crash or full disk never leaves a half-written session.json.
        tmp = STATE_STORAGE_PATH.with_name(STATE_STORAGE_PATH.name + ".tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                if os.name != "nt":
                    os.fchmod(fh.fileno(), 0o600)
                fh.write(json.dumps(existing, indent=2))
                fh.flush()
                os.fsync(fh.fileno())
            if os.name == "nt":
                secret_store.restrict_file(tmp, force=True)
            os.replace(tmp, STATE_STORAGE_PATH)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

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
        "system_locale": CLIENT_LOCALE,
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
        if not isinstance(properties_payload, dict):
            raise ValueError("properties is not an object")
    except Exception:
        properties_payload = generate_fallback_properties()

    properties_payload["client_launch_id"] = str(uuid.uuid4())
    properties_payload["launch_signature"] = signature_id
    properties_payload["client_heartbeat_session_id"] = session_id
    serialized = json.dumps(properties_payload, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(serialized).decode("ascii"), properties_payload


class TokenRejected(RuntimeError):
    pass


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
        if exc.code == 401:
            raise TokenRejected("Discord rejected the account token (HTTP 401). It is incomplete or Discord reset it "
                                "(logout, password change), a fresh token is needed.") from exc
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


def solve_captcha_locally(sitekey: str, rqdata: str, terminal, timeout: float = 240.0) -> str:
    import http.server
    result: dict[str, str] = {}
    page = (
        "<!doctype html><meta charset=utf-8><title>Captcha</title>"
        "<body style=\"font-family:sans-serif;background:#111;color:#eee;display:flex;"
        "align-items:center;justify-content:center;height:100vh;margin:0\">"
        "<div><div id=c></div><p id=m>Solve the captcha.</p></div>"
        "<script>var KEY=" + json.dumps(sitekey).replace("</", "<\\/") + ",DATA=" + json.dumps(rqdata or "").replace("</", "<\\/") + ";"
        "function ready(){var id=hcaptcha.render('c',{sitekey:KEY,theme:'dark',callback:function(t){"
        "fetch('/token',{method:'POST',body:JSON.stringify({token:t})}).then(function(){"
        "document.getElementById('m').textContent='Done, you can close this tab.'})}});"
        "if(DATA){try{hcaptcha.setData(id,{rqdata:DATA})}catch(e){}}}</script>"
        "<script src=\"https://js.hcaptcha.com/1/api.js?render=explicit&onload=ready\" async defer></script>"
    ).encode("utf-8")

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

        def do_POST(self) -> None:
            try:
                size = int(self.headers.get("content-length") or 0)
                result["token"] = str(json.loads(self.rfile.read(size).decode("utf-8")).get("token", ""))
            except Exception:
                pass
            self.send_response(204)
            self.end_headers()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}/"
    terminal.log(f"Captcha page: {url} (opened in your browser, waiting up to {int(timeout)}s)")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    deadline = time.time() + timeout
    while time.time() < deadline and not result.get("token"):
        time.sleep(0.3)
    time.sleep(0.3)
    server.shutdown()
    server.server_close()
    return result.get("token", "")


def join_support_server(state: AccountSessionState, super_props: str, terminal) -> None:
    uid = extract_account_snowflake(state.token)
    if not uid or state.support_join_for == uid:
        return
    terminal.log(f"Joining the BadgeMaxxer help server ({SUPPORT_INVITE_URL}) ...")

    def attempt(captcha_key: str = "", rqtoken: str = "") -> tuple[int, dict]:
        headers = {
            "authorization": state.token,
            "content-type": "application/json",
            "origin": "https://discord.com",
            "referer": f"https://discord.com/invite/{SUPPORT_INVITE_CODE}",
            "user-agent": USER_AGENT_IDENTIFIER,
            "x-super-properties": super_props,
            "x-context-properties": base64.b64encode(
                json.dumps({"location": "Join Guild", "location_guild_id": None,
                            "location_channel_id": None, "location_channel_type": None},
                           separators=(",", ":")).encode("utf-8")).decode("ascii"),
            "x-discord-locale": "en-US",
            "x-discord-timezone": "UTC",
            "accept-language": "en-US,en;q=0.9",
            **({"cookie": state.cookie} if state.cookie else {}),
        }
        if captcha_key:
            headers["x-captcha-key"] = captcha_key
        if rqtoken:
            headers["x-captcha-rqtoken"] = rqtoken
        request = urllib.request.Request(
            f"{DISCORD_INVITES_API}/{SUPPORT_INVITE_CODE}",
            data=b"{}", method="POST", headers=headers,
        )
        status, body = 0, {}
        try:
            with urllib.request.urlopen(request, timeout=15) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                body = json.loads(exc.read().decode("utf-8"))
            except Exception:
                pass
        except Exception as exc:
            terminal.warning("support", f"could not reach Discord ({exc}), will try again next start")
            return -1, {}
        return status, body if isinstance(body, dict) else {}

    status, body = attempt()
    if status == -1:
        return
    if "captcha_key" in body and body.get("captcha_sitekey"):
        if str(body.get("captcha_service") or "hcaptcha") != "hcaptcha":
            terminal.warning("support", f"unsupported captcha type, join manually: {SUPPORT_INVITE_URL}")
            state.support_join_for = uid
            state.persist()
            return
        terminal.log("Discord wants a captcha, opening only the captcha ...")
        token = solve_captcha_locally(str(body["captcha_sitekey"]), str(body.get("captcha_rqdata") or ""), terminal)
        if not token:
            terminal.warning("support", "captcha not solved in time, will try again next start")
            return
        status, body = attempt(token, str(body.get("captcha_rqtoken") or ""))
        if status == -1:
            return

    detail = ""
    if body:
        detail = str(body.get("message") or body.get("captcha_key") or body)[:160]
    if status == 200:
        terminal.success("support", "Joined the BadgeMaxxer help server")
    elif status in (401, 429):
        terminal.warning("support", f"join skipped (HTTP {status}), will try again next start")
        return
    elif "captcha_key" in body:
        terminal.warning("support", f"captcha rejected by Discord, join manually: {SUPPORT_INVITE_URL}")
    elif status == 403 or status == 0:
        terminal.warning("support", f"blocked (HTTP {status}) {detail}, check your cookie in the credentials menu, will try again next start. Manual: {SUPPORT_INVITE_URL}")
        return
    else:
        terminal.warning("support", f"could not join (HTTP {status}) {detail}, join manually: {SUPPORT_INVITE_URL}")
    state.support_join_for = uid
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
    try:
        titles = parse_catalog_entries(DATABASE_STORAGE_PATH.read_text(encoding="utf-8"))
        if titles:
            return titles
    except (OSError, ValueError, AttributeError, TypeError):
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
            "rendered_locale": CLIENT_LOCALE,
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
            "accept-language": CLIENT_LOCALE,
            "authorization": self.state.token,
            "content-type": "application/json",
            "cookie": self.state.cookie,
            "origin": "https://discord.com",
            "referer": "https://discord.com/channels/@me",
            "user-agent": USER_AGENT_IDENTIFIER,
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": CLIENT_LOCALE,
            "x-discord-timezone": CLIENT_TIMEZONE,
            "x-super-properties": self.context.encoded_properties,
        }

        request_handle = urllib.request.Request(TELEMETRY_INGEST_URL, data=encoded_body, method="POST", headers=network_headers)
        for attempt in range(3):
            last = attempt == 2
            try:
                with urllib.request.urlopen(request_handle, timeout=15) as response:
                    return response.status
            except urllib.error.HTTPError as error:
                if error.code == 429 and not last:
                    try:
                        wait = float(error.headers.get("Retry-After") or json.loads(error.read() or b"{}").get("retry_after") or 5)
                    except (ValueError, AttributeError, TypeError):
                        wait = 5.0
                    time.sleep(min(max(wait, 1.0), 60.0))
                    continue
                if error.code >= 500 and not last:
                    time.sleep(2.0 * (attempt + 1))
                    continue
                return error.code
            except Exception:
                if not last:
                    time.sleep(2.0 * (attempt + 1))
                    continue
                return 0
        return 0


def segment_collection(items: Sequence[DetectableTitle], chunk_size: int) -> Iterator[Sequence[DetectableTitle]]:
    for idx in range(0, len(items), chunk_size):
        yield items[idx:idx + chunk_size]


class IngestionPipeline:
    def __init__(self, fabricator: TelemetryEventFabricator, terminal: TerminalInterface) -> None:
        self.fabricator = fabricator
        self.terminal = terminal
        self.accepted_ids: list[str] = []

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
                self.accepted_ids.extend(target.title_id for target in partition)
                self.terminal.dispatched(f"batch {batch_index}", f"{processed_successfully}/{total_records} titles accepted")
            elif http_status in (401, 403):
                self.terminal.failure(
                    f"batch {batch_index}",
                    f"[{http_status}] Authentication failed. Use '{CREDENTIALS_MENU}' in the menu to update your token/cookie."
                )
                return processed_successfully
            else:
                reason = "network error" if http_status == 0 else f"HTTP {http_status}"
                self.terminal.warning(f"batch {batch_index}", f"{reason}, batch skipped")

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





STAR_REPO = "ItzMeShadow999/BadgeMaxxer"
FOLLOW_USER = "ItzMeShadow999"


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


def can_open_browser() -> bool:
    if os.name != "nt" and sys.platform != "darwin" and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return False
    try:
        browser = webbrowser.get()
    except webbrowser.Error:
        return False
    return bool(os.environ.get("BROWSER")) or not isinstance(browser, webbrowser.GenericBrowser)


def github_device_login(T: "TerminalInterface") -> str:
    if GITHUB_CLIENT_ID.startswith("PASTE"):
        T.failure("github", "GITHUB_CLIENT_ID is not set in BadgeMaxxer.py (create an OAuth App with Device Flow enabled).")
        return ""
    st, d = _github_request("https://github.com/login/device/code", data={"client_id": GITHUB_CLIENT_ID, "scope": ""}, accept="application/json")
    if st != 200 or not isinstance(d, dict) or "device_code" not in d:
        reason = (d.get("error_description") if isinstance(d, dict) else "") or STAR_ERROR or st
        T.failure("github", f"could not start GitHub login ({reason})")
        return ""
    url = d.get("verification_uri", "https://github.com/login/device")
    T.log(f"Open {T.COLOR_PRIMARY}{url}{T.COLOR_TEXT} and enter the code {T.COLOR_PRIMARY}{d['user_code']}{T.COLOR_TEXT}")
    if can_open_browser():
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
        if st == 429:
            interval += 5
            continue
        if st == 0 or st >= 500:
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


def check_follow(token: str) -> tuple[bool | None, str, int]:
    st, me = _github_request("https://api.github.com/user", token=token)
    login = me.get("login", "") if isinstance(me, dict) else ""
    if st != 200 or not login:
        return None, "", st
    if login.lower() == FOLLOW_USER.lower():
        return True, login, 204
    st, _ = _github_request(f"https://api.github.com/users/{login}/following/{FOLLOW_USER}", token=token)
    if st == 204:
        return True, login, st
    if st == 404:
        return False, login, st
    return None, login, st


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
        followed, login, fst = check_follow(token)
        if followed is None:
            T.failure("follow", f"could not verify your follow ({STAR_ERROR or fst}). BadgeMaxxer needs this check to run.")
            return False
        if not followed:
            T.failure("follow", f"you are not following {FOLLOW_USER}. Follow https://github.com/{FOLLOW_USER}, then run BadgeMaxxer again.")
            return False
        if login and login != self.state.github_user:
            self.state.github_user = login
            self.state.persist()
        if not quiet:
            T.success("star", "verified, thanks for the star")
            T.success("follow", f"verified, thanks for following {FOLLOW_USER}")
        return True

    def start(self) -> None:
        fit_terminal_zoom()
        self.terminal.display_header()
        time.sleep(0.3)

        if not self._star_gate():
            self.terminal.failure("star", "Star the repo and follow ItzMeShadow999 to use BadgeMaxxer.")
            self._pause("exit")
            return

        if not self.state.token:
            self._prompt_account_token()
        else:
            self.terminal.success("auth", "User token loaded from state")

        if not self.state.token:
            self.terminal.failure("token", "Account token is required.")
            self._pause("exit")
            return

        if not self.state.cookie:
            self._choose_cookie()
        else:
            self.terminal.success("auth", "Clearance cookie loaded from state")

        if not self.state.cookie:
            self.terminal.failure("cookie", "cf_clearance cookie is required.")
            self._pause("exit")
            return

        self.terminal.log("loading detectable games catalog...")
        self.catalog = load_game_catalog()
        if not self.catalog:
            self.terminal.failure("catalog", "Unable to retrieve detectable games catalog.")
            self._pause("exit")
            return
        self.terminal.success("catalog", f"{len(self.catalog)} verified titles loaded")

        if not self.state.fingerprint and os.name == "nt":
            self.terminal.warning("fingerprint", "Executable fingerprint not set (optional for hours, recommended for variety).")

        self.terminal.log("synchronizing analytics credentials...")
        self._renew_session()
        try:
            self._synchronize_or_ask_token()
        except Exception as exc:
            self.terminal.failure("auth", str(exc))
            self.terminal.warning("auth", f"Opening the menu anyway, use '{CREDENTIALS_MENU}' to fix your token or cookie.")
            self._pause("continue")
        else:
            self.terminal.success("auth", "Ingestion pipeline initialized")
            join_support_server(self.state, self.runtime_context.encoded_properties, self.terminal)

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
                elif copy_to_clipboard_posix(TOKEN_SNIPPET):
                    T.log("Copied to clipboard.")
                else:
                    T.log("Copy the snippet above manually.")
            except Exception:
                pass
            T.log("Open Discord (web or desktop), press Ctrl+Shift+I, open Console, paste, press Enter.")
            T.log("A browser may refuse the paste until you type: allow pasting. On Linux the desktop app has no console, use the browser.")
            T.log("The snippet copies your token to the clipboard itself. Come back here and paste it below.")
        else:
            T.log("Paste your Discord account authorization token:")
        val = ""
        for _ in range(3):
            raw = input(f"  {T.COLOR_MUTED}token:{T.COLOR_RESET} ")
            if not raw.strip():
                break
            val, problem = clean_token(raw)
            if val:
                break
            T.failure("token", problem)
        if val:
            if val != self.state.token:
                self.state.fetched_at = 0
            self.state.token = val
            self.state.persist()
            self.terminal.success("token", "Saved to local state")

    def _choose_cookie(self, choice: int = -1) -> None:
        T = self.terminal
        if choice < 0:
            choice = arrow_menu("Cookie", ["Auto fetch cookies", "Paste your cookie"])
        if choice == 0:
            T.log("fetching base cookies from discord.com...")
            base = fetch_base_cookies()
            if base:
                self.state.cookie = base
                self.state.persist()
                T.success("cookie", "Base cookies fetched and saved (no cf_clearance)")
                T.log("If requests get blocked (403), choose 'Paste your cookie' and use the cookie from the @me request.")
            else:
                T.failure("cookie", "Could not fetch cookies, choose 'Paste your cookie' instead.")
        elif choice == 1:
            self._prompt_clearance_cookie()

    def _prompt_clearance_cookie(self) -> None:
        print_cookie_help(self.terminal)
        self.terminal.log("Paste your cf_clearance cookie header value:")
        val = extract_cookie_header(read_pasted_line(f"  {self.terminal.COLOR_MUTED}cookie:{self.terminal.COLOR_RESET} "))
        if val:
            self.state.cookie = val
            self.state.persist()
            self.terminal.success("cookie", "Saved to local state")
        else:
            self.terminal.failure("cookie", "No cookie found in the paste, nothing was saved.")

    def _reconfigure_credentials(self) -> None:
        T = self.terminal
        old_id = extract_account_snowflake(self.state.token)
        if arrow_menu("Token", ["Keep current token", "Enter a new token"]) == 1:
            self._prompt_account_token()
            if self.state.fingerprint and extract_account_snowflake(self.state.token) != old_id:
                T.warning("fingerprint", "This token is another account, run 'Configure Executable Fingerprint' again.")
        sel = arrow_menu("Cookie", ["Keep current cookie", "Auto fetch cookies", "Paste your cookie"])
        if sel in (1, 2):
            self._choose_cookie(sel - 1)

        T.log("Refreshing analytics token from Discord...")
        try:
            self.state.fetched_at = 0
            self._synchronize_or_ask_token()
        except Exception as exc:
            T.failure("auth", str(exc))
            self._pause()
            return
        self._renew_session()
        self.state.persist()
        T.success("auth", "Credentials refreshed successfully")
        time.sleep(1)

    def _synchronize_or_ask_token(self) -> None:
        """Refresh the analytics token; when Discord rejects the account token, offer to enter a new one."""
        for attempt in range(3):
            try:
                synchronize_credentials(self.state, self.runtime_context.encoded_properties)
                return
            except TokenRejected as exc:
                if attempt == 2:
                    raise
                self.terminal.failure("auth", str(exc))
                if arrow_menu("Token rejected", ["Enter a new token now", "Skip"]) != 0:
                    raise TokenRejected("The account token was not changed.") from exc
                old = self.state.token
                self._prompt_account_token()
                if self.state.token == old:
                    raise TokenRejected("The account token was not changed.") from exc

    def _ensure_runtime_readiness(self) -> bool:
        if not self.state.cookie:
            self.terminal.failure("cookie", f"Missing cookie. Use '{CREDENTIALS_MENU}' in the menu to configure.")
            return False
        if self.state.requires_refresh:
            try:
                self._synchronize_or_ask_token()
            except Exception as exc:
                self.terminal.failure("auth", str(exc))
                return False
            self._renew_session()
        return bool(self.state.analytics_token)

    def _pause(self, action: str = "return to menu") -> None:
        T = self.terminal
        T.separator()
        input(f"  {T.COLOR_PRIMARY}›{T.COLOR_RESET} Press enter to {action}")

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
        if not math.isfinite(value) or value < 0 or (value == 0 and not allow_zero):
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
            if not raw.isdecimal() or int(raw) < 1:
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
        hour_presets = [v for v in (0.5, 1.0, 2.0, 5.0, 10.0, 24.0, 50.0, 100.0) if v <= MAX_GAME_HOURS]

        def custom_hours() -> float | None:
            value = self._ask_hours(f"Hours per game (max {MAX_GAME_HOURS:g})", min(default_hours, MAX_GAME_HOURS))
            if value is not None and value > MAX_GAME_HOURS:
                T.failure("input", f"Hours per game is capped at {MAX_GAME_HOURS:g}.")
                return None
            return value

        hours = self._pick_number(
            "Hours per game?", hour_presets, lambda v: f"{v:g}h per game", min(default_hours, MAX_GAME_HOURS),
            custom_hours,
        )
        if hours == BACK_TO_MENU or hours is None:
            return hours
        return count, hours

    def _run_claim(self, count: int, hours: float) -> int:
        T = self.terminal
        if hours > MAX_GAME_HOURS:
            T.warning("cap", f"{hours:g}h per game exceeds the {MAX_GAME_HOURS:g}h limit, using {MAX_GAME_HOURS:g}h.")
            hours = MAX_GAME_HOURS
        selected_titles = self._filter_title_selection(count)
        if not selected_titles:
            T.failure("catalog", "No titles selected.")
            return 0

        duration_ms = int(hours * 3600 * 1000)
        total_aggregate = len(selected_titles) * hours
        print()
        T.log(f"Submitting {T.COLOR_PRIMARY}{hours:g}h{T.COLOR_TEXT} across {T.COLOR_PRIMARY}{len(selected_titles)}{T.COLOR_TEXT} titles ({total_aggregate:,.1f}h total)")
        T.separator()

        engine = IngestionPipeline(self.fabricator, self.terminal)
        accepted = engine.execute_stream(
            selected_titles,
            lambda title: self.fabricator.assemble_complete_session(title, duration_ms)
        )

        picked = {title.title_id for title in selected_titles}
        accepted_ids = set(engine.accepted_ids)
        self.state.used_games = [gid for gid in self.state.used_games if gid not in picked or gid in accepted_ids]

        print()
        T.success("completed", f"{accepted}/{len(selected_titles)} titles processed ({accepted * hours:,.1f}h total)")
        self.state.total_games_claimed += accepted
        self.state.total_hours_claimed += accepted * hours
        self.state.persist()

        T.log(f"{T.COLOR_MUTED}note: discord badge progression updates every 24-48h on analytics sync.{T.COLOR_RESET}")
        return accepted

    def _warn_game_time(self) -> None:
        T = self.terminal
        T.warning("game time", "Game Time progress will most likely not increase.")
        T.warning("game time", "Discord has patched this server side, so scripts that claim to boost it no longer count.")
        T.warning("game time", "It still runs, in case Discord starts counting it again.")
        print()

    def trigger_playtime_ingestion(self, default_games: int | None = None, default_hours: float = 1.0, label: str = "Game Time") -> None:
        if not self._star_gate(quiet=True):
            self.terminal.failure("star", f"Star/follow check failed, {label} stopped.")
            self._pause("exit")
            return
        if not self._ensure_runtime_readiness():
            self._pause()
            return
        self.terminal.display_header()
        if label == "Game Time":
            self._warn_game_time()
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
        done = self._streamer_totals()[0]
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
        if not self._star_gate(quiet=True):
            self.terminal.failure("star", "Star/follow check failed, Streaming stopped.")
            self._pause("exit")
            return
        if not self._ensure_runtime_readiness():
            self._pause()
            return
        self.terminal.display_header()
        mode = self._streamer_gate()
        if mode != "headless":
            return
        hours = self._pick_stream_hours(fresh_screen=True)
        if hours == BACK_TO_MENU:
            return
        if hours is None:
            self._pause()
            return
        self.run_gateway_live_streamer(hours, mode)

    def level_up_all(self) -> None:
        T = self.terminal
        if not self._ensure_runtime_readiness():
            self._pause()
            return
        T.display_header()
        T.log("Level up all: press enter to accept each default")
        print()
        self._warn_game_time()
        pick = arrow_menu("Game Time is patched, include it anyway?",
                          ["Skip Game Time", "Include Game Time", "Back to Main menu"])
        if pick is None or pick == 2:
            return
        time_params = None
        if pick == 1:
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
        stream_mode = self._streamer_gate()
        if stream_mode is None:
            return
        stream_hours = 0.0 if stream_mode != "headless" else self._pick_stream_hours(allow_zero=True)
        if stream_hours == BACK_TO_MENU:
            return
        if stream_hours is None:
            self._pause()
            return

        print()
        if time_params:
            T.separator()
            T.log(f"{T.COLOR_PRIMARY}Game Time{T.COLOR_RESET}")
            if not self._star_gate(quiet=True):
                T.failure("star", "Star/follow check failed before Game Time, stopping.")
                self._pause("exit")
                return
            self._run_claim(*time_params)
        T.separator()
        T.log(f"{T.COLOR_PRIMARY}Game Variety{T.COLOR_RESET}")
        if not self._star_gate(quiet=True):
            T.failure("star", "Star/follow check failed before Game Variety, stopping.")
            self._pause("exit")
            return
        self._run_claim(*variety_params)
        if stream_hours > 0:
            T.separator()
            T.log(f"{T.COLOR_PRIMARY}Streaming{T.COLOR_RESET}")
            if not self._star_gate(quiet=True):
                T.failure("star", "Star/follow check failed before Streaming, stopping.")
                self._pause("exit")
                return
            self.run_gateway_live_streamer(stream_hours, stream_mode)
        else:
            self._pause()

    def _filter_title_selection(self, desired_amount: int) -> list[DetectableTitle]:
        existing_pool = {item.title_id for item in self.catalog}
        used = set(self.state.used_games)
        unprocessed = [item.title_id for item in self.catalog if item.title_id not in used]
        processed = [gid for gid in self.state.used_games if gid in existing_pool]

        if len(unprocessed) >= desired_amount:
            chosen = unprocessed[:desired_amount]
        else:
            chosen = unprocessed
            if processed:
                needed = desired_amount - len(chosen)
                chosen.extend(processed[:needed])

        chosen_set = set(chosen)
        self.state.used_games = [gid for gid in self.state.used_games if gid not in chosen_set] + chosen
        registry = {item.title_id: item for item in self.catalog}
        return [registry[gid] for gid in chosen if gid in registry]

    def configure_executable_fingerprint(self) -> None:
        T = self.terminal
        account_id = extract_account_snowflake(self.state.token)
        if not account_id:
            T.failure("fingerprint", "Valid token required to derive user identity.")
            self._pause()
            return
        if os.name != "nt":
            T.failure("fingerprint", "Fingerprint generation requires Windows OS.")
            self._pause()
            return

        T.log("Generate executable fingerprint bound to account and machine.")
        T.log(f"Account Snowflake: {T.COLOR_PRIMARY}{account_id}{T.COLOR_RESET}")
        T.log("Provide an executable (.exe) path or active game Process ID (PID):")
        raw_input = input(f"  {T.COLOR_MUTED}path or PID:{T.COLOR_RESET} ").strip().strip('"')
        if not raw_input:
            T.log("Operation cancelled.")
            time.sleep(1)
            return

        target_pid = int(raw_input) if raw_input.isdecimal() else 0
        target_path = "" if target_pid else raw_input
        if target_path and not Path(target_path).exists():
            T.failure("fingerprint", f"File path does not exist: {target_path}")
            self._pause()
            return

        T.log("Generating signature via PowerShell PE analyzer...")
        try:
            signature = build_binary_signature(account_id, file_path=target_path, active_pid=target_pid)
        except Exception as exc:
            T.failure("fingerprint", str(exc))
            self._pause()
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
                "x-discord-locale": CLIENT_LOCALE,
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
            self._show_badge_progress(encoded_props)
        except Exception as exc:
            T.failure("profile", f"Failed to retrieve profile: {exc}")

        T.separator()
        input(f"  {T.COLOR_PRIMARY}›{T.COLOR_RESET} Press enter to continue")

    def _show_badge_progress(self, encoded_props: str) -> None:
        """Progress of the leveling badges, hidden ones included. Discord answers 404 without x-super-properties."""
        T = self.terminal
        request = urllib.request.Request(
            f"{DISCORD_USERS_API}/@me/badges",
            headers={
                "authorization": self.state.token,
                "user-agent": USER_AGENT_IDENTIFIER,
                "x-super-properties": encoded_props,
                "x-discord-locale": CLIENT_LOCALE,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as resp:
                badges = json.loads(resp.read().decode("utf-8")).get("badges") or []
        except urllib.error.HTTPError as exc:
            T.log(f"{T.COLOR_MUTED}Badge progress is not available (HTTP {exc.code}).{T.COLOR_RESET}")
            return
        except Exception as exc:
            T.log(f"{T.COLOR_MUTED}Badge progress is not available ({exc}).{T.COLOR_RESET}")
            return
        by_id = {b.get("badge_id"): b for b in badges if isinstance(b, dict)}
        rows = [by_id[i] for i in LEVEL_BADGE_IDS if i in by_id]
        if not rows:
            return
        T.log("Badge progress:")
        for badge in rows:
            tiers = {t.get("key"): t for t in badge.get("tiers") or [] if isinstance(t, dict)}
            current = (tiers.get(badge.get("current_tier")) or {}).get("name") or "none"
            line = f"{badge.get('name')}: {badge.get('info_label') or '-'} · tier {current}"
            upcoming = tiers.get(badge.get("next_tier"))
            if upcoming:
                need = (upcoming.get("requirements") or [{}])[0]
                line += f" · next {upcoming.get('name')} at {need.get('threshold')} {need.get('unit', '')}".rstrip()
            elif badge.get("current_tier"):
                line += " · highest tier"
            if badge.get("hidden"):
                line += " · hidden on profile"
            T.log(f"  {T.COLOR_PRIMARY}•{T.COLOR_RESET} {line}")

    def _streamer_gate(self) -> str | None:
        """Returns 'headless' to run Streamer/Streamer.js directly."""
        return "headless"

    def run_gateway_live_streamer(self, hours: float = 0.0, mode: str | None = None) -> None:
        mode = mode or self._streamer_gate()
        if mode != "headless":
            return
        C = self.stream_console
        proc = self._open_streamer()
        if proc is not None:
            if hours > 0:
                C.info(f"When the streamer asks for the duration, enter {hours * 60:.0f} minutes ({hours:,.1f}h).")
            else:
                C.info("When the streamer asks for the duration, enter 0 to stream until you stop it.")
            C.info("The stream and its hour totals are handled in the streamer window.")
            C.info("Once it is live, use 'Start Watcher' in the main menu so the alt watches it.")
        self._pause()

    def _streamer_preflight(self) -> str | None:
        """Streamer.js, Node.js and its npm packages. Installs missing packages. Prints why and returns
        None when it cannot start, else the node executable."""
        C = self.stream_console
        if not STREAMER_SCRIPT.is_file():
            C.warn("streamer", f"missing: {STREAMER_SCRIPT} (put Streamer.js in the Streamer folder next to BadgeMaxxer.py)")
            return None
        node = shutil.which("node")
        if not node:
            C.err("streamer", f"Node.js was not found on PATH, install Node.js {STREAMER_NODE_MIN[0]}.{STREAMER_NODE_MIN[1]} or newer from https://nodejs.org and run BadgeMaxxer again")
            return None
        out = ""
        try:
            out = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=15).stdout.strip()
            version = tuple(int(part) for part in out.lstrip("v").split(".")[:2])
        except Exception:
            version = ()
        if version and version < STREAMER_NODE_MIN:
            C.err("streamer", f"Node.js {out} is too old, the streamer needs Node.js {STREAMER_NODE_MIN[0]}.{STREAMER_NODE_MIN[1]} or newer")
            return None
        missing = [p for p in STREAMER_PACKAGES if not (STREAMER_DIR / "node_modules" / p / "package.json").is_file()]
        if missing:
            npm = shutil.which("npm")
            specs = [f"{p}@{STREAMER_PINS[p]}" for p in missing]
            if not npm:
                C.err("streamer", f"npm was not found, run in {STREAMER_DIR}: npm install {' '.join(specs)}")
                return None
            # --prefix keeps npm in the Streamer folder even when a parent folder has its own package.json
            cmd = [npm, "install", "--prefix", str(STREAMER_DIR), "--no-audit", "--no-fund"]
            if not (STREAMER_DIR / "package.json").is_file():
                cmd += specs
            try:
                result = run_with_loader(", ".join(missing), cmd, cwd=str(STREAMER_DIR), timeout=900)
            except Exception as exc:
                C.err("streamer", f"npm install failed: {exc}")
                return None
            if result.returncode != 0:
                tail = (result.stdout or "").strip().splitlines()[-3:]
                C.err("streamer", f"npm install failed, run in {STREAMER_DIR}: npm install {' '.join(specs)}")
                for line in tail:
                    C.info(line)
                return None
            C.ok("streamer", f"installed {', '.join(missing)}")
        if not shutil.which("ffmpeg"):
            C.warn("streamer", "ffmpeg was not found on PATH, the streamer needs it to make the video feed")
        return node

    def _open_streamer(self):
        C = self.stream_console
        node = self._streamer_preflight()
        if not node:
            return None
        cmd = [node, str(STREAMER_SCRIPT)]
        account = extract_account_snowflake(self.state.token)
        if account.isdigit():
            cmd += ["--expect", account]
        if os.name == "nt":
            proc = subprocess.Popen(cmd, cwd=str(STREAMER_DIR), creationflags=subprocess.CREATE_NEW_CONSOLE)
        else:
            terminal = find_terminal_posix()
            if not terminal:
                C.warn("streamer", f"run it in another terminal: cd \"{STREAMER_DIR}\" && node Streamer.js {' '.join(cmd[2:])}".rstrip())
                return None
            launcher = ["sh", "-c", 'cd "$0" && exec "$@"', str(STREAMER_DIR)]
            window = subprocess.Popen(terminal + launcher + cmd, cwd=str(STREAMER_DIR), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc = PosixWatcherProcess(window, cmd)
        C.ok("streamer", "opened in a new window, it asks for the account token there once (saved to Streamer/streamertoken2.json), then the voice channel and the duration")
        return proc

    def _streamer_totals(self) -> tuple[float, int]:
        """Stream hours and sessions as logged by Streamer.js in Streamer/streamer_stats.json."""
        try:
            data = json.loads(STREAMER_STATS.read_text(encoding="utf-8"))
            return float(data.get("totalHours") or 0.0), int(data.get("sessions") or 0)
        except Exception:
            return self.state.total_stream_hours_claimed, self.state.total_stream_sessions


    def _watcher_preflight(self):
        """Files, account id, a terminal (POSIX) and packages the Watcher needs, installing what is missing.
        Prints why and returns None when it cannot start, else (account id, terminal command)."""
        C = self.stream_console
        absent = [name for name in WATCHER_FILES if not (WATCHER_DIR / name).is_file()]
        if absent:
            C.warn("watcher", f"missing in {WATCHER_DIR}: {', '.join(absent)} (the watcher needs all of {', '.join(WATCHER_FILES)})")
            return None
        target = extract_account_snowflake(self.state.token)
        if not target:
            C.err("watcher", "could not read this account's id from the token")
            return None
        terminal = None
        if os.name != "nt":
            terminal = find_terminal_posix()
            if not terminal:
                C.warn("watcher", f"run it in another terminal: \"{sys.executable}\" \"{WATCHER_SCRIPT}\" {target}")
                return None
        for package in WATCHER_PACKAGES:
            if importlib.util.find_spec(package) is None:
                if not _install_package(package):
                    hint = "use install.sh to set it up in a virtual environment" if SYSTEM_PYTHON_POSIX else f"run: pip install {package}"
                    C.err("watcher", f"could not install {package}, {hint}")
                    return None
                C.ok("watcher", f"installed {package}")
                importlib.invalidate_caches()
        return target, terminal

    def _open_watcher(self, guild_id: str = "", channel_id: str = ""):
        C = self.stream_console
        ready = self._watcher_preflight()
        if not ready:
            return None
        target, terminal = ready
        cmd = [sys.executable, str(WATCHER_SCRIPT), target]
        if guild_id and channel_id:
            cmd += ["--guild", guild_id, "--channel", channel_id]
        if os.name == "nt":
            proc = subprocess.Popen(cmd, cwd=str(WATCHER_DIR), creationflags=subprocess.CREATE_NEW_CONSOLE)
        else:
            launcher = ["sh", "-c", 'cd "$0" && exec "$@"', str(WATCHER_DIR)]
            window = subprocess.Popen(terminal + launcher + cmd, cwd=str(WATCHER_DIR), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc = PosixWatcherProcess(window, cmd)
        C.ok("watcher", "opened in a new window, it asks for an ALT account token there once, the alt is the one that watches (hidden, saved to Watcher/watcher_session.json)")
        return proc

    def start_watcher(self) -> None:
        T = self.terminal
        T.display_header()
        T.log(f"{T.COLOR_PRIMARY}Start Watcher{T.COLOR_RESET}")
        T.log("Opens the watcher on an ALT account. It joins the voice channel of this account and watches its stream.")
        T.log("The alt must be in the same server as this account. The watcher asks for the alt's token in its own window.")
        T.log("Go Live on this account in the Discord app, the watcher then finds the stream by itself.")
        T.log("If it cannot find it within 15s it asks for the server and voice channel ids.")
        self._open_watcher()
        self._pause()

    def render_main_menu(self) -> None:
        T = self.terminal
        options = [
            "Level up all",
            GAME_TIME_MENU,
            "Game Variety",
            "Streaming",
            "Start Watcher",
            "Inspect Discord Profile & Badges",
            CREDENTIALS_MENU,
            "Configure Executable Fingerprint",
            "Exit",
        ]
        while True:
            T.display_header()
            T.log(f"Detectable Titles: {T.COLOR_PRIMARY}{len(self.catalog)}{T.COLOR_TEXT}")
            T.log(f"Cumulative Logged: {T.COLOR_PRIMARY}{self.state.total_games_claimed}{T.COLOR_TEXT} titles · {T.COLOR_PRIMARY}{self.state.total_hours_claimed:,.1f}h{T.COLOR_TEXT} playtime")
            stream_hours, stream_sessions = self._streamer_totals()
            T.log(f"Total Stream Hours: {T.COLOR_PRIMARY}{stream_hours:,.1f}h{T.COLOR_TEXT} ({stream_sessions} sessions)")
            print()

            choice = arrow_menu("Select what badge to level", options)
            print()
            if choice is None or choice == 8:
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
    except EOFError:
        print()
        TerminalInterface().warning("exit", "No interactive terminal (stdin closed). Run BadgeMaxxer from a terminal window.")
        sys.exit(1)


if __name__ == "__main__":
    execute_entrypoint()
