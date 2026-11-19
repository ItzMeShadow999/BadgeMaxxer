"""
watcher_common.py

Shared pieces for the stream watcher: dependency check, constants, the redacted
debug log, token storage, small async helpers and the gateway client properties.

Part of the Watcher package (stream_watcher.py, watcher_voice.py, watcher_common.py).
Keep the three files in the same folder.
"""

import asyncio
import getpass
import json
import os
import platform
import sys
import threading
import time
import urllib.request

missing = []
try:
    import websockets
except ImportError:
    missing.append("websockets")
try:
    import davey
except ImportError:
    missing.append("davey")
if missing:
    print("Missing dependency. Run: pip install " + " ".join(missing))
    try:
        input("Press Enter to exit...")
    except EOFError:
        pass
    sys.exit(1)

GATEWAY_URL = "wss://gateway.discord.gg/?v=9&encoding=json"
ORIGIN = "https://discord.com"
LOCATE_WAIT_SECONDS = 15
STEP_TIMEOUT = 15
TEARDOWN_PAUSE = 1.5
STABLE_SECONDS = 60
DEFAULT_MAX_ATTEMPTS = 8
MAX_SESSION_SECONDS = 9.5 * 3600

CAPABILITIES = 16381
PROPERTIES_URL = "https://cordapi.dolfi.es/api/v2/properties/windows"
FALLBACK_BUILD_NUMBER = 594031
CLIENT_PROPERTIES = {
    "os": "Windows",
    "browser": "Chrome",
    "device": "",
    "system_locale": "en-US",
    "browser_user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "browser_version": "124.0.0.0",
    "os_version": "10",
    "referrer": "",
    "referring_domain": "",
    "release_channel": "stable",
    "client_build_number": FALLBACK_BUILD_NUMBER,
    "client_event_source": None,
}

GATEWAY_CLOSE_CODES = {
    4004: "authentication failed (bad or expired token)",
    4003: "not authenticated",
    4002: "payload not understood",
    4005: "already authenticated",
    4007: "invalid sequence",
    4008: "rate limited",
    4009: "session timed out",
    4010: "invalid shard",
    4011: "sharding required",
    4012: "invalid API version",
    4013: "invalid intents",
    4014: "disallowed intents",
}
FATAL_GATEWAY_CODES = {4004, 4010, 4011, 4012, 4013, 4014}

VOICE_CLOSE_CODES = {
    4001: "unknown opcode",
    4002: "failed to decode payload",
    4003: "not authenticated",
    4004: "authentication failed",
    4005: "already authenticated",
    4006: "session no longer valid",
    4009: "session timeout",
    4011: "server not found",
    4012: "unknown protocol",
    4014: "disconnected",
    4015: "voice server crashed",
    4016: "unknown encryption mode",
    4017: "end-to-end encryption (DAVE) required",
    4020: "bad request",
    4021: "rate limited",
    4022: "call terminated",
}

MODES = ("aead_xchacha20_poly1305_rtpsize", "aead_aes256_gcm_rtpsize")
SECRET_KEYS = {"token", "secret_key"}
LOGGED_EVENTS = {"RESUMED", "VOICE_STATE_UPDATE", "VOICE_SERVER_UPDATE", "STREAM_CREATE", "STREAM_SERVER_UPDATE", "STREAM_DELETE"}


class DebugLog:
    """Writes a redacted trace to a file. Secrets never reach the file."""

    def __init__(self):
        self.fh = None
        self.path = None
        self.secrets = set()

    def open(self, path):
        self.path = os.path.abspath(path)
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            self.fh = os.fdopen(fd, "w", encoding="utf-8")
            if os.name != "nt":
                os.fchmod(fd, 0o600)
        except OSError:
            self.fh = None
        self.write("env", f"python {platform.python_version()} on {platform.platform()}, "
                          f"websockets {getattr(websockets, '__version__', '?')}, "
                          f"davey {getattr(davey, '__version__', '?')}")

    def add_secret(self, value):
        if value and len(str(value)) > 6:
            self.secrets.add(str(value))

    def clean_text(self, text):
        for secret in self.secrets:
            text = text.replace(secret, "<redacted>")
        return text

    def redact(self, obj):
        if isinstance(obj, dict):
            out = {}
            for key, value in obj.items():
                if key in SECRET_KEYS:
                    self.add_secret(value if isinstance(value, str) else None)
                    out[key] = "<redacted>"
                else:
                    out[key] = self.redact(value)
            return out
        if isinstance(obj, list):
            return [self.redact(v) for v in obj]
        return obj

    def write(self, kind, text):
        if not self.fh:
            return
        try:
            self.fh.write(f"{time.strftime('%H:%M:%S')} {kind:<8} {self.clean_text(text)}\n")
            self.fh.flush()
        except (OSError, ValueError):
            pass

    def frame(self, kind, direction, obj):
        try:
            text = json.dumps(self.redact(obj), separators=(",", ":"))
        except (TypeError, ValueError):
            text = repr(obj)
        if len(text) > 1500:
            text = text[:1500] + "...(cut)"
        self.write(kind, f"{direction} {text}")


DBG = DebugLog()


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)
    DBG.write("log", msg)


def close_code(exc):
    return getattr(getattr(exc, "rcvd", None), "code", None) or getattr(exc, "code", None)


def ask_digits(prompt, allow_blank=False):
    while True:
        raw = input(prompt).strip()
        if not raw and allow_blank:
            return ""
        if raw.isdigit():
            return raw
        print("Enter a numeric ID.")


_INPUT_THREADS = []


def async_input(prompt):
    """input() in a daemon thread so Ctrl+C is never blocked by it.

    The thread is remembered so exit_pause() can let a still-open prompt take the
    final Enter instead of fighting it for stdin.
    """
    loop = asyncio.get_running_loop()
    fut = loop.create_future()

    def deliver(setter, value):
        def apply():
            if not fut.done():
                setter(value)
        try:
            loop.call_soon_threadsafe(apply)
        except RuntimeError:
            pass

    def worker():
        try:
            value = input(prompt)
        except BaseException as exc:
            deliver(fut.set_exception, exc)
            return
        deliver(fut.set_result, value)

    fut.add_done_callback(lambda f: f.cancelled() or f.exception())
    thread = threading.Thread(target=worker, daemon=True)
    _INPUT_THREADS.append(thread)
    thread.start()
    return fut


def exit_pause():
    """'Press Enter to exit...' that cannot collide with an unanswered async_input prompt."""
    pending = [t for t in _INPUT_THREADS if t.is_alive()]
    try:
        if pending:
            print("Press Enter to exit...", flush=True)
            for thread in pending:
                thread.join()
        else:
            input("Press Enter to exit...")
    except (EOFError, KeyboardInterrupt):
        pass


TOKEN_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "watcher_session.json")


def load_saved_token():
    try:
        with open(TOKEN_PATH, encoding="utf-8") as fh:
            return str(json.load(fh).get("token", "")).strip()
    except (OSError, ValueError, AttributeError):
        return ""


def save_token(token):
    try:
        if os.name == "nt":
            with open(TOKEN_PATH, "w", encoding="utf-8") as fh:
                json.dump({"token": token}, fh, indent=2)
        else:
            fd = os.open(TOKEN_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                os.fchmod(fh.fileno(), 0o600)
                json.dump({"token": token}, fh, indent=2)
    except OSError as exc:
        print(f"Could not save the token ({exc}).")
        return
    try:
        os.chmod(TOKEN_PATH, 0o600)
    except OSError:
        pass


def forget_token():
    try:
        os.remove(TOKEN_PATH)
    except OSError:
        pass


def get_token():
    token = os.environ.get("DISCORD_MAIN_TOKEN", "").strip()
    save = False
    if not token:
        token = load_saved_token()
        if token:
            print("Main account token loaded from watcher_session.json.")
    if not token:
        token = getpass.getpass("Main account token (hidden, saved to watcher_session.json): ").strip()
        save = True
    token = token.strip('"').strip("'")
    if not token:
        sys.exit("No token provided.")
    if " " in token or len(token) < 30:
        print("That does not look like a user token (too short or contains spaces).")
    if save:
        save_token(token)
    return token


def load_client_properties(timeout=10):
    """Current client properties for the gateway identify, as (properties, source).

    Uses the same public properties endpoint BadgeMaxxer uses (an empty POST, no
    credentials). Falls back to CLIENT_PROPERTIES, which carries a real build
    number instead of 0.
    """
    request = urllib.request.Request(
        PROPERTIES_URL,
        method="POST",
        data=b"{}",
        headers={"content-type": "application/json",
                 "user-agent": CLIENT_PROPERTIES["browser_user_agent"]},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            props = json.loads(resp.read().decode("utf-8"))["properties"]
        if isinstance(props, dict) and int(props.get("client_build_number", 0)) > 0:
            props.setdefault("client_event_source", None)
            return props, "live"
    except Exception:
        pass
    return dict(CLIENT_PROPERTIES), "fallback"


async def wait_any(events, timeout):
    tasks = [asyncio.create_task(e.wait()) for e in events]
    try:
        await asyncio.wait(tasks, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
    return [e for e in events if e.is_set()]


async def wait_all(events, timeout):
    deadline = time.time() + timeout
    for e in events:
        remaining = deadline - time.time()
        if remaining <= 0:
            return False
        try:
            await asyncio.wait_for(e.wait(), remaining)
        except asyncio.TimeoutError:
            return False
    return True
