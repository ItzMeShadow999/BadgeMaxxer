#!/usr/bin/env python3
from __future__ import annotations

import atexit
import getpass
import json
import os
import select
import shutil
import sys
import time
import urllib.error
import urllib.request
from typing import Sequence

API_URL = "https://discord.com/api/v9/hypesquad/online"

HOUSES = {1: "Bravery", 2: "Brilliance", 3: "Balance"}

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

ESC_SEQ_TIMEOUT = 0.5

PICKER_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(PICKER_DIR)
SESSION_PATH = os.path.join(ROOT_DIR, "session.json")
LIB_DIR = os.path.join(ROOT_DIR, "lib")
SECRET_STORE_PATH = os.path.join(LIB_DIR, "secret_store.py")

BANNER_ART = r"""

   ▄▄▄  ▄▄▄                     ▄▄▄▄▄                              ▄▄▄▄▄▄
  █▀██  ██                     ██▀▀▀▀█▄                      █▄   █▀██▀▀▀█▄
    ██  ██                     ▀██▄  ▄▀                      ██     ██▄▄▄█▀▀▀       ▄▄           ▄
    ██████   ██ ██ ████▄ ▄█▀█▄   ▀██▄▄  ▄████ ██ ██ ▄▀▀█▄ ▄████     ██▀▀▀  ██ ▄███▀ ██ ▄█▀ ▄█▀█▄ ████▄
    ██  ██   ██▄██ ██ ██ ██▄█▀ ▄   ▀██▄ ██ ██ ██ ██ ▄█▀██ ██ ██   ▄ ██     ██ ██    ████   ██▄█▀ ██
  ▀██▀  ▀██▄▄▄▀██▀▄████▀▄▀█▄▄▄ ▀██████▀▄▀████▄▀██▀█▄▀█▄██▄█▀███   ▀██▀    ▄██▄▀███▄▄██ ▀█▄▄▀█▄▄▄▄█▀
               ██  ██                      ██
             ▀▀▀   ▀                        ▀
"""

GRAD_STOPS = ((144, 121, 222), (225, 113, 95), (63, 203, 179))
HOUSE_RGB = {1: GRAD_STOPS[0], 2: GRAD_STOPS[1], 3: GRAD_STOPS[2]}

ANSI_RESET = "\x1b[0m"
MUTED = "\x1b[38;2;178;178;188m"
TEXT = "\x1b[38;2;200;200;206m"


def fg(rgb: tuple[int, int, int], bold: bool = False) -> str:
    return f"\x1b[{'1;' if bold else ''}38;2;{rgb[0]};{rgb[1]};{rgb[2]}m"


ACCENT = fg(GRAD_STOPS[1])
ACCENT_BOLD = fg(GRAD_STOPS[1], True)
ACCENT_DIM = fg((205, 178, 195))
OK_COLOR = fg(GRAD_STOPS[2])
ERR_COLOR = fg(GRAD_STOPS[1])


def grad_at(t: float) -> tuple[int, int, int]:
    t = max(0.0, min(1.0, t))
    s = t * (len(GRAD_STOPS) - 1)
    i = min(int(s), len(GRAD_STOPS) - 2)
    f = s - i
    a, b = GRAD_STOPS[i], GRAD_STOPS[i + 1]
    return (int(a[0] + (b[0] - a[0]) * f), int(a[1] + (b[1] - a[1]) * f), int(a[2] + (b[2] - a[2]) * f))


def grad_text(text: str) -> str:
    span = max(1, len(text) - 1)
    out: list[str] = []
    last = -1
    for c, ch in enumerate(text):
        if ch == " ":
            out.append(ch)
            continue
        q = round(c / span * 24)
        if q != last:
            out.append(fg(grad_at(q / 24)))
            last = q
        out.append(ch)
    out.append(ANSI_RESET)
    return "".join(out)


class Banner:

    SUBTITLE = "Discord HypeSquad house picker  ·  Bravery  ·  Brilliance  ·  Balance"
    TITLE = "HypeSquad Picker"
    MIN_ROWS_FULL = 16
    MIN_ROWS_BODY = 9
    CREDIT = "- By ItzMeShadow999"
    CREDIT_URL = "https://github.com/ItzMeShadow999"

    def __init__(self) -> None:
        lines = [ln.rstrip() for ln in BANNER_ART.strip("\n").split("\n")]
        while lines and not lines[0].strip():
            lines.pop(0)
        while lines and not lines[-1].strip():
            lines.pop()
        self.art = lines
        self.art_width = max(len(ln) for ln in self.art)
        self.pinned = False
        self.region_top = 1

    def credit_link(self) -> str:
        return f"\x1b]8;;{self.CREDIT_URL}\x1b\\{fg((130, 228, 210))}{self.CREDIT}{ANSI_RESET}\x1b]8;;\x1b\\"

    def fits(self) -> bool:
        cols, rows = shutil.get_terminal_size((120, 30))
        return cols > self.art_width and rows >= self.MIN_ROWS_FULL

    def build(self, cols: int, rows: int) -> list[str]:
        if cols > self.art_width and rows >= self.MIN_ROWS_FULL:
            height = len(self.art)
            lines: list[str] = []
            credit_row = height - 1
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
                        out.append(fg(grad_at(q / 24)))
                        last = q
                    out.append(ch)
                out.append(ANSI_RESET)
                if with_credit:
                    out.append(self.credit_link())
                lines.append("".join(out))
            lines.append(ACCENT_DIM + "  " + self.SUBTITLE[: max(0, cols - 3)] + ANSI_RESET)
            return lines
        width = max(20, min(cols - 2, 64))
        sub_room = max(0, cols - 2 - len(self.TITLE) - 2)
        sub = ("  ·  " + self.SUBTITLE)[:sub_room]
        tail = ("  " + self.credit_link()) if sub_room >= len("  ·  " + self.SUBTITLE) + 2 + len(self.CREDIT) else ""
        return [
            grad_text("━" * width),
            "  " + grad_text(self.TITLE) + ACCENT_DIM + sub + ANSI_RESET + tail,
            grad_text("━" * width),
        ]

    def draw(self) -> None:
        if not sys.stdout.isatty():
            print(self.TITLE)
            return
        cols, rows = shutil.get_terminal_size((120, 30))
        lines = self.build(cols, rows)
        top = len(lines) + 1
        self.pinned = False
        self.region_top = 1
        out = f"\x1b]0;{self.TITLE}\x07\x1b[r\x1b[2J\x1b[3J\x1b[H" + "\n".join(lines) + "\n"
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


def prepare_terminal() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if sys.platform == "win32":
        try:
            import ctypes
            kernel = ctypes.windll.kernel32
            handle = kernel.GetStdHandle(-11)
            flags = ctypes.c_uint32()
            if kernel.GetConsoleMode(handle, ctypes.byref(flags)):
                kernel.SetConsoleMode(handle, flags.value | 0x0004)
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


def arrow_menu(
    title: str,
    options: Sequence[str],
    hint: str = "↑/↓ move · enter select · esc exit",
    start: int = 0,
    colors: Sequence[tuple[int, int, int] | None] | None = None,
) -> int | None:
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
            rgb = colors[i] if colors and colors[i] else GRAD_STOPS[1]
            more = ""
            if view < n:
                if i == off and off > 0:
                    more = f" {MUTED}▲"
                elif i == off + view - 1 and off + view < n:
                    more = f" {MUTED}▼"
            if i == sel:
                buf.append(f"\r\x1b[2K   {fg(rgb, True)}› {opt}{more}{ANSI_RESET}\n")
            else:
                buf.append(f"\r\x1b[2K     {TEXT}{opt}{more}{ANSI_RESET}\n")
        sys.stdout.write("".join(buf))
        sys.stdout.flush()

    sys.stdout.write("\x1b[?25l")
    sys.stdout.write(f"  {ACCENT_BOLD}{title}{ANSI_RESET}  {MUTED}{hint}{ANSI_RESET}\n")
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


def call(method: str, token: str, body: dict | None = None) -> tuple[int, str]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {
        "Authorization": token,
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Origin": "https://discord.com",
        "Referer": "https://discord.com/channels/@me",
    }
    if data is not None:
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(API_URL, data=data, method=method, headers=headers)

    for _ in range(3):
        try:
            with urllib.request.urlopen(request, timeout=15) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as err:
            text = err.read().decode("utf-8", errors="replace")
            if err.code == 429:
                wait = 2.0
                try:
                    wait = float(json.loads(text).get("retry_after", wait))
                except (ValueError, AttributeError, TypeError):
                    pass
                print(f"  {MUTED}Rate limited, waiting {wait:.1f}s{ANSI_RESET}")
                time.sleep(min(wait, 30.0) + 0.2)
                continue
            return err.code, text
        except urllib.error.URLError as err:
            return 0, str(err.reason)
    return 429, "Still rate limited after retries"


def result_line(status: int, text: str, success_msg: str) -> str:
    if status in (200, 204):
        return f"  {OK_COLOR}▪ {success_msg}{ANSI_RESET}"
    if status == 401:
        msg = "401: token rejected (invalid or expired)."
    elif status == 403:
        msg = "403: blocked (Cloudflare challenge or account restriction)."
    elif status == 0:
        msg = "Network error: " + text
    else:
        msg = f"HTTP {status}: {text[:300]}"
    return f"  {ERR_COLOR}▪ {msg}{ANSI_RESET}"


def validate_token(token: str) -> tuple[bool, str]:
    request = urllib.request.Request(
        "https://discord.com/api/v9/users/@me",
        method="GET",
        headers={
            "Authorization": token,
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Origin": "https://discord.com",
            "Referer": "https://discord.com/channels/@me",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as resp:
            info = json.loads(resp.read().decode("utf-8", errors="replace"))
            name = info.get("global_name") or info.get("username") or "unknown"
            return True, name
    except urllib.error.HTTPError as err:
        if err.code == 401:
            return False, "401: token rejected (invalid or expired)."
        if err.code == 403:
            return False, "403: blocked (Cloudflare challenge or account restriction)."
        if err.code == 429:
            return False, "429: rate limited, wait a bit and try again."
        return False, f"HTTP {err.code}"
    except urllib.error.URLError as err:
        return False, f"Network error: {err.reason}"
    except (ValueError, AttributeError):
        return False, "Unexpected response while checking the token."


TOKEN_KEYS = ("token", "user_token", "discord_token", "main_token", "authorization")
ACCOUNT_KEYS = ("main", "main_account", "account", "accounts")


def extract_token(data: object) -> tuple[str, str]:
    if isinstance(data, dict):
        for key in TOKEN_KEYS:
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return key, value.strip().strip('"')
        for key in ACCOUNT_KEYS:
            found = extract_token(data.get(key))
            if found[1]:
                return found
    elif isinstance(data, list):
        for item in data:
            found = extract_token(item)
            if found[1]:
                return found
    return "", ""


def decrypt_stored(field: str, stored: str) -> tuple[str, str]:
    if not stored.startswith(("dpapi1:", "keyring:")):
        return stored, ""
    if not os.path.isfile(SECRET_STORE_PATH):
        return "", f"token is encrypted but {SECRET_STORE_PATH} was not found."
    try:
        import importlib.util
        for folder in (ROOT_DIR, LIB_DIR):
            if folder not in sys.path:
                sys.path.insert(0, folder)
        spec = importlib.util.spec_from_file_location("badgemaxxer_secret_store", SECRET_STORE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as err:
        return "", f"could not load secret_store.py ({err})."
    names = [field] + [k for k in TOKEN_KEYS if k != field]
    for name in names:
        try:
            plain = module.reveal(name, stored)
        except Exception:
            plain = ""
        if plain:
            return plain.strip().strip('"'), ""
    return "", "could not decrypt the token (wrong Windows user, locked keyring, or different install folder)."


def load_session_token() -> tuple[str, str, str]:
    if not os.path.isfile(SESSION_PATH):
        return "", "", f"not found at {SESSION_PATH}"
    try:
        with open(SESSION_PATH, "r", encoding="utf-8") as fh:
            field, stored = extract_token(json.load(fh))
    except (OSError, ValueError) as err:
        return "", "", f"could not read it ({err})."
    if not stored:
        return "", "", "no token found in it."
    token, why = decrypt_stored(field, stored)
    if token:
        return token, SESSION_PATH, ""
    return "", "", why


def masked_input(prompt: str) -> str:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return getpass.getpass(prompt)

    sys.stdout.write(prompt)
    sys.stdout.flush()
    chars: list[str] = []

    def handle(ch: str) -> bool:
        if ch in ("\r", "\n"):
            return True
        if ch == "\x03":
            raise KeyboardInterrupt
        if ch == "\x04" and not chars:
            raise EOFError
        if ch in ("\x7f", "\b"):
            if chars:
                chars.pop()
                sys.stdout.write("\b \b")
                sys.stdout.flush()
            return False
        if ch.isprintable():
            chars.append(ch)
            sys.stdout.write("*")
            sys.stdout.flush()
        return False

    if os.name == "nt":
        import msvcrt
        while True:
            ch = msvcrt.getwch()
            if ch in ("\x00", "\xe0"):
                msvcrt.getwch()
                continue
            if handle(ch):
                break
    else:
        import termios
        import tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            buf = b""
            done = False
            while not done:
                buf += os.read(fd, 1)
                try:
                    text = buf.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                buf = b""
                for ch in text:
                    if handle(ch):
                        done = True
                        break
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    sys.stdout.write("\n")
    sys.stdout.flush()
    return "".join(chars)


def ask_token() -> str:
    print(f"  {ACCENT_BOLD}Token{ANSI_RESET}  {MUTED}paste it and press enter{ANSI_RESET}")
    token = masked_input("  › ").strip().strip('"')
    if not token:
        raise SystemExit("No token. Exiting.")
    return token


def main() -> None:
    prepare_terminal()
    BANNER.draw()
    token = ""
    saved, saved_path, note = load_session_token()
    if note and not saved:
        print(f"  {ERR_COLOR}▪ session.json: {note}{ANSI_RESET}")
        print(f"  {MUTED}Falling back to manual entry.{ANSI_RESET}")
        print()
    if saved:
        print(f"  {MUTED}Found session.json, checking saved token...{ANSI_RESET}")
        ok, info = validate_token(saved)
        if ok:
            token = saved
            print(f"  {OK_COLOR}▪ Using main account from session.json: {info}.{ANSI_RESET}")
            time.sleep(1.0)
        else:
            print(f"  {ERR_COLOR}▪ session.json token failed: {info}{ANSI_RESET}")
            print(f"  {MUTED}Falling back to manual entry.{ANSI_RESET}")
            print()

    while not token:
        candidate = ask_token()
        print(f"  {MUTED}Checking token...{ANSI_RESET}")
        ok, info = validate_token(candidate)
        if ok:
            token = candidate
            print(f"  {OK_COLOR}▪ Token valid, logged in as {info}.{ANSI_RESET}")
            time.sleep(1.0)
            break
        print(f"  {ERR_COLOR}▪ {info}{ANSI_RESET}")
        print()

    options = [HOUSES[1], HOUSES[2], HOUSES[3], "Leave house", "Exit"]
    colors = [HOUSE_RGB[1], HOUSE_RGB[2], HOUSE_RGB[3], None, None]
    last = ""
    start = 0
    while True:
        BANNER.draw()
        if last:
            print(last)
            print()
        choice = arrow_menu("HypeSquad", options, start=start, colors=colors)
        if choice is None or choice == 4:
            return
        start = choice
        if choice in (0, 1, 2):
            house_id = choice + 1
            status, text = call("POST", token, {"house_id": house_id})
            last = result_line(status, text, f"HypeSquad {HOUSES[house_id]} applied.")
        else:
            status, text = call("DELETE", token)
            last = result_line(status, text, "Left HypeSquad.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print()
