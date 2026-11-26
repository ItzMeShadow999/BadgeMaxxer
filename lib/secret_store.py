from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

DPAPI_TAG = "dpapi1:"
KEYRING_TAG = "keyring:"
SERVICE = "badgemaxxer"

_warned: set[str] = set()
_restricted: set[str] = set()
# Keyring items are per install folder, so two copies of BadgeMaxxer never share a token.
_SCOPE = hashlib.sha256(str(Path(__file__).resolve().parent.parent).encode("utf-8")).hexdigest()[:12]


def _item(name: str) -> str:
    return f"{name}@{_SCOPE}"


def _warn(key: str, message: str) -> None:
    if key not in _warned:
        _warned.add(key)
        print(f"  secret store: {message}", file=sys.stderr)


def _dpapi(encrypt: bool, data: bytes, name: str) -> bytes | None:
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def make(raw: bytes):
        buf = ctypes.create_string_buffer(raw, len(raw))
        return Blob(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    blob_p = ctypes.POINTER(Blob)
    if encrypt:
        crypt32.CryptProtectData.argtypes = [blob_p, wintypes.LPCWSTR, blob_p, ctypes.c_void_p,
                                             ctypes.c_void_p, wintypes.DWORD, blob_p]
        crypt32.CryptProtectData.restype = wintypes.BOOL
        fn, first = crypt32.CryptProtectData, "BadgeMaxxer"
    else:
        crypt32.CryptUnprotectData.argtypes = [blob_p, ctypes.c_void_p, blob_p, ctypes.c_void_p,
                                               ctypes.c_void_p, wintypes.DWORD, blob_p]
        crypt32.CryptUnprotectData.restype = wintypes.BOOL
        fn, first = crypt32.CryptUnprotectData, None

    data_in, keep_data = make(data)
    entropy, keep_entropy = make(b"BadgeMaxxer:" + name.encode("utf-8"))
    data_out = Blob()
    ok = fn(ctypes.byref(data_in), first, ctypes.byref(entropy), None, None, 0x1, ctypes.byref(data_out))
    del keep_data, keep_entropy
    if not ok:
        return None
    try:
        return ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(data_out.pbData, ctypes.c_void_p))


def _keyring_tool_present() -> bool:
    return os.name != "nt" and shutil.which("secret-tool") is not None


def _secret_tool(args: list[str], data: bytes | None = None) -> bytes | None:
    try:
        done = subprocess.run(["secret-tool", *args], input=data, capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def available() -> bool:
    return os.name == "nt" or _keyring_tool_present()


def is_protected(stored: str) -> bool:
    return stored.startswith((DPAPI_TAG, KEYRING_TAG))


def protect(name: str, value: str) -> str:
    if not value:
        return ""
    if os.name == "nt":
        try:
            blob = _dpapi(True, value.encode("utf-8"), name)
        except Exception:
            blob = None
        if blob:
            return DPAPI_TAG + base64.b64encode(blob).decode("ascii")
        _warn("dpapi", "Windows DPAPI failed, secrets are stored in plaintext.")
        return value
    if _keyring_tool_present():
        done = _secret_tool(["store", "--label", f"BadgeMaxxer {name}", "service", SERVICE, "name", _item(name)],
                            value.encode("utf-8"))
        if done is not None:
            return KEYRING_TAG + _item(name)
        _warn("keyring", "could not reach the desktop keyring (locked or no session), "
                         "secrets are stored in plaintext with mode 0600.")
        return value
    _warn("nostore", "install libsecret's secret-tool to keep secrets in the desktop keyring, "
                     "until then they are stored in plaintext with mode 0600.")
    return value


def reveal(name: str, stored: str) -> str:
    if not stored:
        return ""
    if stored.startswith(DPAPI_TAG):
        if os.name != "nt":
            return ""
        try:
            raw = _dpapi(False, base64.b64decode(stored[len(DPAPI_TAG):]), name)
        except Exception:
            return ""
        return raw.decode("utf-8", "replace") if raw else ""
    if stored.startswith(KEYRING_TAG):
        out = _secret_tool(["lookup", "service", SERVICE, "name", stored[len(KEYRING_TAG):]])
        if out is None:
            _warn("keyring-read", "could not read from the desktop keyring (locked, no session or secret-tool missing). "
                                  "Saved secrets stay there and are used again once the keyring can be reached.")
            return ""
        return out.decode("utf-8", "replace")
    return stored


def discard(name: str) -> None:
    if _keyring_tool_present():
        _secret_tool(["clear", "service", SERVICE, "name", _item(name)])


def restrict_file(path: str | os.PathLike, force: bool = False) -> None:
    if os.name != "nt":
        return
    target = Path(path)
    key = str(target.resolve())
    if key in _restricted and target.exists() and not force:
        return
    _restricted.add(key)
    user = os.environ.get("USERNAME", "")
    if not user:
        _warn("acl", "could not read the Windows user name, file permissions were not tightened.")
        return
    domain = os.environ.get("USERDOMAIN", "")
    who = f"{domain}\\{user}" if domain else user
    try:
        target.touch(exist_ok=True)
        done = subprocess.run(["icacls", str(target), "/inheritance:r", "/grant:r", f"{who}:F"],
                              capture_output=True, timeout=15)
        failed = done.returncode != 0
    except (OSError, subprocess.SubprocessError):
        failed = True
    if failed:
        _warn("acl", f"could not tighten permissions on {target.name}.")


if __name__ == "__main__":
    token = protect("selftest", "abc.123_secret")
    assert reveal("selftest", token) == "abc.123_secret", "round trip failed"
    assert reveal("selftest", "legacy-plain") == "legacy-plain", "legacy value must pass through"
    assert protect("selftest", "") == "" and reveal("selftest", "") == ""
    print("ok:", "protected" if is_protected(token) else "plaintext fallback (no store available)")
