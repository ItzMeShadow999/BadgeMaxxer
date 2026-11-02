#!/usr/bin/env python3
"""
stream_watcher.py

Script for the MAIN account. It logs in with the main account token, finds the
voice channel of the account that is Go Live streaming (the BadgeMaxxer
account), joins it with a real voice connection and opens a viewer connection
on their stream. Voice and stream connections use Discord's end-to-end
encryption (DAVE) through the "davey" library.

Built to keep going:
  * reconnects and resumes the Discord gateway when the connection drops
  * retries failed attempts, and on errors such as 4006 automatically rotates
    through different session ID / group ID combinations
  * waits for the target to go live and re-watches when the stream restarts
  * writes a redacted debug log (watcher_debug.log) you can paste when asked

Token handling: read from the DISCORD_MAIN_TOKEN environment variable, else
from watcher_session.json (saved on first run), else typed at a hidden prompt
and saved there. A token from the environment variable is never saved. The
token is never written to the debug log, and is deliberately NOT read from
BadgeMaxxer's session.json (that file holds the other account's token). A
rejected token (4004) is deleted automatically; --reset-token forgets it.

Requires: pip install websockets davey

Usage:
  python stream_watcher.py
  python stream_watcher.py 1065604516399026176
  python stream_watcher.py 1065604516399026176 --guild 123 --channel 456
Stop with Ctrl+C (leaves the stream and the voice channel cleanly).
"""

import argparse
import asyncio
import getpass
import json
import os
import platform
import random
import socket
import struct
import sys
import threading
import time
import traceback
import uuid

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
    "client_build_number": 0,
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
QUIET_EVENTS = {"READY", "GUILD_CREATE", "READY_SUPPLEMENTAL", "SESSIONS_REPLACE"}


class DebugLog:
    """Writes a redacted trace to a file. Secrets never reach the file."""

    def __init__(self):
        self.fh = None
        self.path = None
        self.secrets = set()

    def open(self, path):
        self.path = os.path.abspath(path)
        try:
            self.fh = open(self.path, "w", encoding="utf-8")
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


def async_input(prompt):
    """input() in a daemon thread so Ctrl+C is never blocked by it."""
    loop = asyncio.get_running_loop()
    fut = loop.create_future()

    def worker():
        try:
            value = input(prompt)
        except BaseException as exc:
            loop.call_soon_threadsafe(lambda e=exc: fut.done() or fut.set_exception(e))
            return
        loop.call_soon_threadsafe(lambda: fut.done() or fut.set_result(value))

    threading.Thread(target=worker, daemon=True).start()
    return fut


TOKEN_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "watcher_session.json")


def load_saved_token():
    try:
        with open(TOKEN_PATH, encoding="utf-8") as fh:
            return str(json.load(fh).get("token", "")).strip()
    except (OSError, ValueError, AttributeError):
        return ""


def save_token(token):
    try:
        with open(TOKEN_PATH, "w", encoding="utf-8") as fh:
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


class VoiceLink:
    def __init__(self, label, endpoint, server_id, user_id, session_id, token,
                 group_id, keypair, video=False, keep_port=True):
        self.keep_port = keep_port
        self.label = label
        self.endpoint = endpoint
        self.server_id = server_id
        self.user_id = user_id
        self.session_id = session_id
        self.token = token
        self.group_id = group_id
        self.keypair = keypair
        self.video = video

        DBG.add_secret(token)
        self.ws = None
        self.task = None
        self.seq_ack = -1
        self.ssrc = None
        self.mode = None
        self.sock = None
        self.bg = []
        self.last_ack = time.time()

        self.ready = asyncio.Event()
        self.dave_ready = asyncio.Event()
        self.closed = asyncio.Event()
        self.closed_code = None
        self.closed_reason = ""

        self.dave = None
        self.dave_version = 0
        self.pending = {}

    def say(self, msg):
        log(f"[{self.label}] {msg}")

    def spawn(self, coro):
        task = asyncio.create_task(coro)

        def done(t):
            if not t.cancelled() and t.exception():
                self.say(f"background task error: {t.exception()!r}")

        task.add_done_callback(done)
        self.bg.append(task)
        return task

    async def send_json(self, op, data):
        DBG.frame(self.label, ">", {"op": op, "d": data})
        await self.ws.send(json.dumps({"op": op, "d": data}))

    async def send_binary(self, op, payload):
        DBG.write(self.label, f"> bin op={op} len={len(payload)}")
        await self.ws.send(bytes([op]) + payload)

    def url(self):
        host, _, port = self.endpoint.partition(":")
        if self.keep_port and port and port != "80":
            return f"wss://{host}:{port}/?v=8"
        return f"wss://{host}/?v=8"

    async def run(self):
        try:
            self.say(f"connecting to {self.url().split('/?')[0]}")
            async with websockets.connect(self.url(), max_size=None) as ws:
                self.ws = ws
                await self.identify()
                async for raw in ws:
                    if isinstance(raw, (bytes, bytearray)):
                        await self.on_binary(bytes(raw))
                    else:
                        await self.on_text(json.loads(raw))
                self.closed_code = getattr(ws, "close_code", None)
        except websockets.ConnectionClosed as exc:
            self.closed_code = close_code(exc)
        except Exception as exc:
            self.closed_reason = repr(exc)
        finally:
            for t in self.bg:
                t.cancel()
            if self.sock:
                try:
                    self.sock.close()
                except OSError:
                    pass
            meaning = VOICE_CLOSE_CODES.get(self.closed_code, "")
            if self.closed_reason:
                self.say(f"connection failed: {self.closed_reason}")
            else:
                self.say(f"closed: {self.closed_code} {meaning}".rstrip())
            self.closed.set()

    async def identify(self):
        data = {
            "server_id": str(self.server_id),
            "user_id": str(self.user_id),
            "session_id": self.session_id,
            "token": self.token,
            "max_dave_protocol_version": davey.DAVE_PROTOCOL_VERSION,
        }
        if self.video:
            data["video"] = True
            data["streams"] = [{"type": "screen", "rid": "100", "quality": 100}]
        await self.send_json(0, data)

    async def heartbeat(self, interval):
        while True:
            if time.time() - self.last_ack > max(interval * 4, 20):
                self.say("no heartbeat reply, dropping the connection")
                await self.ws.close(code=4000)
                return
            await self.send_json(3, {"t": int(time.time() * 1000), "seq_ack": self.seq_ack})
            await asyncio.sleep(interval)

    async def udp_keepalive(self):
        counter = 0
        while True:
            await asyncio.sleep(5)
            counter += 1
            try:
                self.sock.send(struct.pack(">Q", counter))
            except OSError:
                pass


    async def on_text(self, msg):
        DBG.frame(self.label, "<", msg)
        op = msg.get("op")
        data = msg.get("d") or {}
        if "seq" in msg:
            self.seq_ack = msg["seq"]
        if op == 8:
            interval = min(data.get("heartbeat_interval", 5000) / 1000.0, 5.0)
            self.last_ack = time.time()
            self.spawn(self.heartbeat(interval))
        elif op == 6:
            self.last_ack = time.time()
        elif op == 2:
            await self.on_ready(data)
        elif op == 4:
            await self.on_session(data)
        elif self.dave is not None:
            if op == 21:
                await self.dave_prepare_transition(data)
            elif op == 22:
                self.dave_execute(data.get("transition_id"))
            elif op == 24:
                await self.dave_prepare_epoch(data)

    def discover_blocking(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        packet = bytearray(74)
        struct.pack_into(">H", packet, 0, 1)
        struct.pack_into(">H", packet, 2, 70)
        struct.pack_into(">I", packet, 4, self.ssrc)
        for _ in range(3):
            sock.send(bytes(packet))
            try:
                reply = sock.recv(2048)
            except socket.timeout:
                continue
            if len(reply) == 74 and reply[1] == 2:
                my_ip = reply[8:reply.index(0, 8)].decode("ascii")
                my_port = struct.unpack_from(">H", reply, 72)[0]
                sock.setblocking(False)
                return sock, my_ip, my_port
        sock.close()
        raise socket.timeout("no reply to UDP discovery")

    async def on_ready(self, data):
        self.ssrc = data["ssrc"]
        modes = data.get("modes", [])
        mode = next((m for m in MODES if m in modes), modes[0] if modes else MODES[0])
        loop = asyncio.get_running_loop()
        try:
            self.sock, my_ip, my_port = await loop.run_in_executor(
                None, self.discover_blocking, data["ip"], data["port"])
        except (OSError, ValueError) as exc:
            self.say(f"UDP handshake failed ({exc}). Your firewall or network may block UDP.")
            return
        await self.send_json(1, {
            "protocol": "udp",
            "address": my_ip,
            "port": my_port,
            "mode": mode,
            "data": {"address": my_ip, "port": my_port, "mode": mode},
            "codecs": [
                {"name": "opus", "type": "audio", "priority": 1000, "payload_type": 120},
                {"name": "H264", "type": "video", "priority": 1000,
                 "payload_type": 101, "rtx_payload_type": 102},
            ],
            "rtc_connection_id": str(uuid.uuid4()),
            "experiments": [],
        })
        self.spawn(self.udp_keepalive())

    async def on_session(self, data):
        self.mode = data.get("mode")
        self.dave_version = data.get("dave_protocol_version", 0)
        self.ready.set()
        self.say(f"connected, mode {self.mode}, DAVE v{self.dave_version}")
        if self.dave_version > 0:
            await self.reinit_dave()
        else:
            self.dave_ready.set()


    async def reinit_dave(self):
        if self.dave_version > 0:
            uid, gid = int(self.user_id), int(self.group_id)
            if self.dave is None:
                self.dave = davey.DaveSession(self.dave_version, uid, gid, self.keypair)
            else:
                self.dave.reinit(self.dave_version, uid, gid, self.keypair)
            await self.send_binary(26, self.dave.get_serialized_key_package())
            self.say("sent MLS key package")
        elif self.dave is not None:
            self.dave.reset()
            self.dave.set_passthrough_mode(True, 10)

    def check_dave_ready(self):
        if self.dave is not None and self.dave.ready and not self.dave_ready.is_set():
            self.dave_ready.set()
            self.say("end-to-end encryption established")

    async def dave_prepare_transition(self, data):
        tid = data.get("transition_id")
        self.pending[tid] = data.get("protocol_version", 0)
        if tid == 0:
            self.dave_execute(0)
        else:
            if self.pending[tid] == 0:
                self.dave.set_passthrough_mode(True, 120)
            await self.send_json(23, {"transition_id": tid})

    def dave_execute(self, tid):
        if tid not in self.pending:
            return
        old = self.dave_version
        self.dave_version = self.pending.pop(tid)
        if old != self.dave_version and self.dave_version == 0:
            self.say("call downgraded to non-E2EE")
            self.dave_ready.set()
        self.check_dave_ready()

    async def dave_prepare_epoch(self, data):
        if data.get("epoch") == 1:
            self.dave_version = data.get("protocol_version", self.dave_version)
            await self.reinit_dave()

    async def apply_mls(self, fn, payload, tid, what):
        try:
            fn(payload)
        except Exception as exc:
            self.say(f"MLS {what} failed ({exc}), asking for a fresh start")
            await self.send_json(31, {"transition_id": tid})
            await self.reinit_dave()
            return
        self.say(f"MLS {what} processed")
        if tid != 0:
            self.pending[tid] = self.dave_version
            await self.send_json(23, {"transition_id": tid})
        self.check_dave_ready()

    async def on_binary(self, msg):
        if len(msg) < 3:
            return
        self.seq_ack = struct.unpack_from(">H", msg, 0)[0]
        op = msg[2]
        DBG.write(self.label, f"< bin op={op} len={len(msg)}")
        if self.dave is None:
            return
        try:
            if op == 25:
                self.dave.set_external_sender(msg[3:])
            elif op == 27:
                kind = (davey.ProposalsOperationType.append if msg[3] == 0
                        else davey.ProposalsOperationType.revoke)
                result = self.dave.process_proposals(kind, msg[4:])
                if isinstance(result, davey.CommitWelcome):
                    body = result.commit + result.welcome if result.welcome else result.commit
                    await self.send_binary(28, body)
            elif op == 29:
                tid = struct.unpack_from(">H", msg, 3)[0]
                await self.apply_mls(self.dave.process_commit, msg[5:], tid, "commit")
            elif op == 30:
                tid = struct.unpack_from(">H", msg, 3)[0]
                await self.apply_mls(self.dave.process_welcome, msg[5:], tid, "welcome")
        except Exception as exc:
            self.say(f"DAVE opcode {op} failed: {exc}")


class StreamWatcher:
    def __init__(self, token, target_id, max_attempts=DEFAULT_MAX_ATTEMPTS, preset=None):
        self.token = token
        DBG.add_secret(token)
        self.target_id = target_id
        self.max_attempts = max_attempts
        self.keypair = davey.generate_p256_keypair()

        self.ws = None
        self.seq = None
        self.me = None
        self.session_id = None
        self.resume_url = None
        self.acked = True
        self.connected = asyncio.Event()
        self.fatal = False
        self.ready_count = 0
        self.locator_started = False

        self.target_loc = preset
        self.target_live = bool(preset)
        self.live_event = asyncio.Event()
        if preset:
            self.live_event.set()
        self.voice_session_id = None

        self.main_idx = 0
        self.stream_idx = 0
        self.history = []
        self.supervisor = None
        self.tasks = []
        self.stream_ready = asyncio.Event()

        self.reset_attempt_state()

    def reset_attempt_state(self):
        self.joined_channel = None
        self.joined_event = asyncio.Event()
        self.voice_server = None
        self.voice_server_event = asyncio.Event()
        self.stream_key = None
        self.rtc_server_id = None
        self.rtc_channel_id = None
        self.stream_token = None
        self.stream_endpoint = None
        self.stream_create_event = asyncio.Event()
        self.stream_server_event = asyncio.Event()
        self.stream_deleted = asyncio.Event()
        self.stream_delete_reason = None
        self.main_link = None
        self.stream_link = None

    def spawn(self, coro):
        task = asyncio.create_task(coro)

        def done(t):
            if not t.cancelled() and t.exception():
                log(f"Background task error: {t.exception()!r}")
                DBG.write("trace", "".join(traceback.format_exception(
                    type(t.exception()), t.exception(), t.exception().__traceback__)))

        task.add_done_callback(done)
        self.tasks.append(task)
        return task


    async def send_raw(self, op, data):
        DBG.frame("gateway", ">", {"op": op, "d": data})
        await self.ws.send(json.dumps({"op": op, "d": data}))

    async def send(self, op, data):
        await asyncio.wait_for(self.connected.wait(), 30)
        await self.send_raw(op, data)

    async def try_send(self, op, data, timeout=4):
        try:
            await asyncio.wait_for(self.send(op, data), timeout)
        except Exception:
            pass

    async def heartbeat_loop(self, ws, interval):
        await asyncio.sleep(interval * random.random())
        while True:
            if not self.acked:
                log("Gateway stopped answering, reconnecting.")
                await ws.close(code=4000)
                return
            self.acked = False
            await ws.send(json.dumps({"op": 1, "d": self.seq}))
            await asyncio.sleep(interval)

    async def identify(self):
        await self.send_raw(2, {
            "token": self.token,
            "capabilities": CAPABILITIES,
            "properties": CLIENT_PROPERTIES,
            "presence": {"status": "online", "since": 0, "activities": [], "afk": False},
            "compress": False,
            "client_state": {"guild_versions": {}},
        })

    async def run(self):
        failures = 0
        try:
            while not self.fatal:
                try:
                    outcome = await self.connect_once()
                    failures = 0
                except (OSError, websockets.WebSocketException, asyncio.TimeoutError) as exc:
                    failures += 1
                    outcome = "network error"
                    log(f"Gateway connection error: {exc!r}")
                if self.fatal:
                    break
                if failures >= 8:
                    log("Could not reach Discord after 8 tries. Check your internet connection.")
                    break
                delay = min(2 ** failures, 30) if failures else 1
                log(f"Reconnecting to the gateway in {delay}s ({outcome}).")
                await asyncio.sleep(delay)
        finally:
            await self.cleanup()

    async def connect_once(self):
        resuming = bool(self.session_id and self.seq is not None)
        url = self.resume_url or GATEWAY_URL
        hb = None
        async with websockets.connect(url, max_size=None, origin=ORIGIN) as ws:
            self.ws = ws
            self.acked = True
            try:
                async for raw in ws:
                    msg = json.loads(raw)
                    op = msg.get("op")
                    if msg.get("s") is not None:
                        self.seq = msg["s"]
                    if op == 10:
                        interval = msg["d"]["heartbeat_interval"] / 1000.0
                        hb = asyncio.create_task(self.heartbeat_loop(ws, interval))
                        if resuming:
                            log("Resuming the gateway session.")
                            await self.send_raw(6, {"token": self.token,
                                                    "session_id": self.session_id,
                                                    "seq": self.seq})
                        else:
                            await self.identify()
                    elif op == 11:
                        self.acked = True
                    elif op == 1:
                        await ws.send(json.dumps({"op": 1, "d": self.seq}))
                    elif op == 7:
                        log("Gateway asked for a reconnect.")
                        return "reconnect requested"
                    elif op == 9:
                        if not msg.get("d"):
                            self.session_id = self.seq = self.resume_url = None
                        await asyncio.sleep(1 + random.random() * 4)
                        return "invalid session"
                    elif op == 0:
                        await self.dispatch(msg.get("t"), msg.get("d") or {})
                return "closed"
            except websockets.ConnectionClosed as exc:
                code = close_code(exc)
                log(f"Gateway closed the connection: {code} "
                    f"{GATEWAY_CLOSE_CODES.get(code, '')}".rstrip())
                if code in FATAL_GATEWAY_CODES:
                    self.fatal = True
                    if code == 4004:
                        forget_token()
                        log("Saved token removed. Run the watcher again to enter a new one.")
                elif code in (4007, 4009):
                    self.session_id = self.seq = self.resume_url = None
                return f"closed {code}"
            finally:
                if hb:
                    hb.cancel()
                self.connected.clear()
                self.ws = None

    async def cleanup(self):
        await self.teardown(pause=0)
        for t in self.tasks:
            t.cancel()


    async def dispatch(self, name, d):
        if name in QUIET_EVENTS:
            DBG.write("gateway", f"< {name} (omitted)")
        else:
            DBG.frame("gateway", "<", {"t": name, "d": d})

        if name == "READY":
            first = self.ready_count == 0
            self.me = d["user"]["id"]
            self.session_id = d.get("session_id")
            base = d.get("resume_gateway_url")
            self.resume_url = f"{base}/?v=9&encoding=json" if base else None
            log(f"Logged in as {d['user'].get('username', '?')} ({self.me})")
            if self.me == self.target_id:
                log("The target user ID is the same as this account. Use the OTHER account's ID.")
                self.fatal = True
                await self.ws.close()
                return
            self.ready_count += 1
            if not first:
                await self.restart_after_new_session()
            self.connected.set()
            for guild in d.get("guilds", []):
                self.scan_guild(guild)
            self.start_supervisor()
            if not self.locator_started:
                self.locator_started = True
                self.spawn(self.locator())
        elif name == "RESUMED":
            self.connected.set()
            log("Gateway session resumed.")
        elif name == "GUILD_CREATE":
            self.scan_guild(d)
        elif name == "VOICE_STATE_UPDATE":
            self.on_voice_state(d)
        elif name == "VOICE_SERVER_UPDATE":
            if (self.joined_channel and d.get("guild_id") == self.joined_channel[0]
                    and d.get("endpoint")):
                DBG.add_secret(d.get("token"))
                self.voice_server = d
                self.voice_server_event.set()
        elif name == "STREAM_CREATE":
            if d.get("stream_key") == self.stream_key:
                self.rtc_server_id = d.get("rtc_server_id")
                self.rtc_channel_id = d.get("rtc_channel_id")
                log(f"Stream found, region {d.get('region', '?')} "
                    f"(fields: {', '.join(sorted(d.keys()))})")
                self.stream_create_event.set()
        elif name == "STREAM_SERVER_UPDATE":
            if d.get("stream_key") == self.stream_key:
                DBG.add_secret(d.get("token"))
                self.stream_token = d.get("token")
                self.stream_endpoint = d.get("endpoint")
                self.stream_server_event.set()
        elif name == "STREAM_DELETE":
            if d.get("stream_key") == self.stream_key:
                self.stream_delete_reason = d.get("reason")
                log(f"Stream deleted by Discord (reason: {self.stream_delete_reason}).")
                self.stream_deleted.set()

    async def restart_after_new_session(self):
        log("Discord started a fresh session, restarting the watch.")
        if self.supervisor:
            self.supervisor.cancel()
            self.supervisor = None
        self.reset_attempt_state()
        self.voice_session_id = None

    def scan_guild(self, guild):
        if guild.get("unavailable"):
            return
        for vs in guild.get("voice_states", []):
            if vs.get("user_id") == self.target_id:
                self.note_target(guild.get("id"), vs.get("channel_id"), bool(vs.get("self_stream")))

    def note_target(self, guild_id, channel_id, live):
        if not channel_id:
            if self.target_loc:
                log("Target left voice.")
            self.target_loc = None
            self.target_live = False
            self.live_event.clear()
            return
        first = self.target_loc is None
        self.target_loc = (guild_id, channel_id)
        self.target_live = live
        if first:
            log(f"Target is in voice channel {channel_id} (guild {guild_id}), "
                f"{'streaming' if live else 'not streaming yet'}.")
        if live:
            self.live_event.set()
        else:
            self.live_event.clear()

    def on_voice_state(self, d):
        uid = d.get("user_id")
        if uid == self.target_id:
            self.note_target(d.get("guild_id"), d.get("channel_id"), bool(d.get("self_stream")))
        elif uid == self.me:
            if d.get("session_id"):
                self.voice_session_id = d["session_id"]
            if (d.get("channel_id") and self.joined_channel
                    and d["channel_id"] == self.joined_channel[1]):
                self.joined_event.set()

    async def locator(self):
        await asyncio.sleep(LOCATE_WAIT_SECONDS)
        if self.target_loc:
            return
        log("Could not find that user in any voice channel the main account can see.")
        print("Enter the guild ID and voice channel ID manually, or press Enter to keep waiting.")
        try:
            guild_id = (await async_input("Guild ID: ")).strip()
            if not guild_id:
                log("Waiting for the target to appear in voice.")
                return
            channel_id = (await async_input("Voice channel ID: ")).strip()
        except EOFError:
            return
        if not (guild_id.isdigit() and channel_id.isdigit()):
            log("Those IDs are not numeric. Waiting for the target to appear in voice.")
            return
        self.target_loc = (guild_id, channel_id)
        self.target_live = True
        self.live_event.set()


    def start_supervisor(self):
        if self.supervisor is None or self.supervisor.done():
            self.supervisor = self.spawn(self.supervise())

    def session_candidates(self):
        values = []
        for value in (self.voice_session_id, self.session_id):
            if value and value not in values:
                values.append(value)
        return values

    def stream_strategy(self):
        sids = self.session_candidates()
        sid_names = {}
        for name, value in (("voice", self.voice_session_id), ("gateway", self.session_id)):
            if value:
                sid_names.setdefault(value, name)
        rtc = self.rtc_channel_id or self.rtc_server_id
        minus_one = None
        if self.rtc_server_id and str(self.rtc_server_id).isdigit():
            minus_one = str(int(self.rtc_server_id) - 1)
        groups = []
        for name, value in (("rtc_server-1", minus_one), ("rtc", rtc),
                            ("channel", self.joined_channel[1]),
                            ("rtc_server", self.rtc_server_id)):
            if value and value not in [g[1] for g in groups]:
                groups.append((name, value))
        port = str(self.stream_endpoint or "").partition(":")[2]
        port_options = [True, False] if port and port not in ("80", "443") else [True]
        combos = []
        for video in (True, False):
            for gname, gval in groups:
                for sid in sids:
                    for keep in port_options:
                        combos.append({
                            "session_id": sid, "group_id": gval, "video": video, "keep_port": keep,
                            "desc": (f"session={sid_names[sid]}, group={gname}, video={video}, "
                                     f"port={'kept' if keep else 'stripped'}")})
        return combos[self.stream_idx % len(combos)]

    async def supervise(self):
        attempts = 0
        while True:
            await self.live_event.wait()
            if not self.target_loc:
                self.live_event.clear()
                continue
            attempts += 1
            guild_id, channel_id = self.target_loc
            started = time.time()
            try:
                outcome = await self.attempt(attempts, guild_id, channel_id)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                DBG.write("trace", traceback.format_exc())
                outcome = ("failed", f"unexpected error {exc!r}", None, None)
            held = time.time() - started
            await self.teardown()

            if outcome[0] in ("ended", "cycle"):
                attempts = 0
                if outcome[0] == "ended":
                    log("Stream ended. Waiting for the target to go live again.")
                    self.live_event.clear()
                continue

            _, reason, which, code = outcome
            self.history.append(f"attempt {attempts}: {reason}")
            if held >= STABLE_SECONDS:
                attempts = 1
            elif which == "voice":
                self.main_idx += 1
            elif which == "stream":
                self.stream_idx += 1
            if attempts >= self.max_attempts:
                await self.give_up()
                return
            delay = min(2 * attempts, 15)
            log(f"Attempt failed ({reason}). Retrying in {delay}s with another approach.")
            await asyncio.sleep(delay)

    async def give_up(self):
        log(f"Giving up after {self.max_attempts} attempts. What happened:")
        for line in self.history[-self.max_attempts:]:
            log(f"  {line}")
        if DBG.path:
            log(f"Debug log (tokens removed): {DBG.path}")
        self.fatal = True
        if self.ws:
            await self.ws.close()

    async def attempt(self, n, guild_id, channel_id):
        session_deadline = time.time() + MAX_SESSION_SECONDS
        self.reset_attempt_state()
        self.joined_channel = (guild_id, channel_id)
        log(f"Attempt {n}/{self.max_attempts}: joining voice channel (muted).")
        await self.send(4, {"guild_id": guild_id, "channel_id": channel_id,
                            "self_mute": True, "self_deaf": False, "self_video": False})
        if not await wait_all([self.joined_event, self.voice_server_event], STEP_TIMEOUT):
            return ("failed", "Discord never returned voice server details "
                              "(no permission to connect, or channel full?)", "join", None)

        candidates = self.session_candidates()
        DBG.write("ids", f"voice_session={self.voice_session_id} gateway_session={self.session_id}")
        main_sid = candidates[self.main_idx % len(candidates)]
        sid_label = "voice" if main_sid == self.voice_session_id else "gateway"
        vs = self.voice_server
        link = VoiceLink("voice", vs["endpoint"], guild_id, self.me, main_sid,
                         vs["token"], channel_id, self.keypair)
        self.main_link = link
        link.task = self.spawn(link.run())
        log(f"Main voice connection using {sid_label} session id.")
        await wait_any([link.ready, link.closed], STEP_TIMEOUT)
        if link.closed.is_set():
            return ("failed", f"main voice closed {link.closed_code} "
                              f"{VOICE_CLOSE_CODES.get(link.closed_code, '')}".strip(),
                    "voice", link.closed_code)
        if not link.ready.is_set():
            return ("failed", "main voice connection never completed", "voice", None)
        await wait_any([link.dave_ready, link.closed], STEP_TIMEOUT)
        if link.closed.is_set():
            return ("failed", f"main voice closed {link.closed_code} "
                              f"{VOICE_CLOSE_CODES.get(link.closed_code, '')}".strip(),
                    "voice", link.closed_code)
        if not link.dave_ready.is_set():
            log("Voice encryption not confirmed yet, continuing anyway.")

        self.stream_key = f"guild:{guild_id}:{channel_id}:{self.target_id}"
        log("Requesting to watch the stream.")
        await self.send(20, {"stream_key": self.stream_key})
        deadline = time.time() + STEP_TIMEOUT
        while True:
            if self.stream_deleted.is_set():
                return ("failed", f"Discord refused the stream request "
                                  f"({self.stream_delete_reason})", "request", None)
            if self.stream_create_event.is_set() and self.stream_server_event.is_set():
                break
            if time.time() > deadline:
                return ("failed", "no stream details received", "request", None)
            if link.closed.is_set():
                return ("failed", f"main voice closed {link.closed_code}", "voice",
                        link.closed_code)
            await asyncio.sleep(0.1)

        strat = self.stream_strategy()
        log(f"Stream connection: {strat['desc']}")
        slink = VoiceLink("stream", self.stream_endpoint, self.rtc_server_id, self.me,
                          strat["session_id"], self.stream_token, strat["group_id"],
                          self.keypair, video=strat["video"], keep_port=strat["keep_port"])
        self.stream_link = slink
        slink.task = self.spawn(slink.run())
        await wait_any([slink.ready, slink.closed], STEP_TIMEOUT)
        if slink.closed.is_set() or not slink.ready.is_set():
            code = slink.closed_code
            return ("failed", f"stream closed {code} {VOICE_CLOSE_CODES.get(code, '')} "
                              f"[{strat['desc']}]".replace("  ", " "), "stream", code)
        await wait_any([slink.dave_ready, slink.closed], STEP_TIMEOUT)
        if slink.closed.is_set():
            code = slink.closed_code
            return ("failed", f"stream closed {code} {VOICE_CLOSE_CODES.get(code, '')} "
                              f"[{strat['desc']}]".replace("  ", " "), "stream", code)
        if not slink.dave_ready.is_set():
            log("Stream encryption not confirmed yet, staying connected.")
        self.stream_ready.set()
        log("Watching the stream. Press Ctrl+C to stop.")

        remaining = session_deadline - time.time()
        await wait_any([slink.closed, link.closed, self.stream_deleted], max(remaining, 0))
        if self.stream_deleted.is_set():
            return ("ended",)
        if slink.closed.is_set():
            return ("failed", f"stream connection dropped ({slink.closed_code})",
                    "stream", slink.closed_code)
        if link.closed.is_set():
            return ("failed", f"voice connection dropped ({link.closed_code})",
                    "voice", link.closed_code)
        log(f"Session hit the {MAX_SESSION_SECONDS / 3600:g}h cap, cycling the connection.")
        return ("cycle",)

    async def teardown(self, pause=TEARDOWN_PAUSE):
        if self.stream_key:
            await self.try_send(19, {"stream_key": self.stream_key})
        if self.joined_channel:
            await self.try_send(4, {"guild_id": self.joined_channel[0], "channel_id": None,
                                    "self_mute": True, "self_deaf": False, "self_video": False})
        for link in (self.stream_link, self.main_link):
            if link is None:
                continue
            if link.ws is not None:
                try:
                    await link.ws.close()
                except Exception:
                    pass
            if getattr(link, "task", None):
                link.task.cancel()
        if pause and (self.stream_key or self.joined_channel):
            await asyncio.sleep(pause)
        self.reset_attempt_state()


def parse_args():
    ap = argparse.ArgumentParser(description="Watch a Go Live stream from the main account.")
    ap.add_argument("user_id", nargs="?", help="user ID of the account that is streaming")
    ap.add_argument("--guild", help="guild ID (skips auto-detection)")
    ap.add_argument("--channel", help="voice channel ID (skips auto-detection)")
    ap.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS,
                    help="how many attempts before giving up")
    ap.add_argument("--log", default="watcher_debug.log", help="debug log path")
    ap.add_argument("--reset-token", action="store_true", help="forget the saved token and ask again")
    return ap.parse_args()


async def main(args):
    print("Stream watcher (main account)")
    DBG.open(args.log)
    target_id = args.user_id
    if not target_id or not target_id.isdigit():
        target_id = ask_digits("User ID of the account to watch: ")
    preset = None
    if args.guild and args.channel and args.guild.isdigit() and args.channel.isdigit():
        preset = (args.guild, args.channel)
    if args.reset_token:
        forget_token()
    token = get_token()
    watcher = StreamWatcher(token, target_id, max_attempts=max(1, args.max_attempts), preset=preset)
    log("Connecting to the gateway.")
    await watcher.run()
    if watcher.history:
        log(f"Debug log (tokens removed): {DBG.path}")


if __name__ == "__main__":
    try:
        asyncio.run(main(parse_args()))
    except KeyboardInterrupt:
        log("Stopped.")
    except Exception as exc:
        log(f"Error: {exc!r}")
        DBG.write("trace", traceback.format_exc())
        traceback.print_exc()
    try:
        input("Press Enter to exit...")
    except EOFError:
        pass
