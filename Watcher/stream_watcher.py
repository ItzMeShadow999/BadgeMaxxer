#!/usr/bin/env python3
"""
stream_watcher.py

Script for an ALT account. It logs in with the alt account token, finds the
voice channel of the account that is Go Live streaming (the main account, the
one BadgeMaxxer uses), joins it with a real voice connection and opens a viewer connection
on their stream. Voice and stream connections use Discord's end-to-end
encryption (DAVE) through the "davey" library.

Files (keep them in the same folder):
  stream_watcher.py   this file: the watcher logic and the command line
  watcher_voice.py    VoiceLink, one voice websocket with UDP discovery and DAVE
  watcher_common.py   constants, redacted debug log, token storage, helpers

Built to keep going:
  * reconnects and resumes the Discord gateway when the connection drops
  * retries failed attempts, and on errors such as 4006 automatically rotates
    through different session ID / group ID combinations
  * waits for the target to go live and re-watches when the stream restarts
  * writes a redacted debug log (watcher_debug.log) you can paste when asked

Token handling: read from the DISCORD_ALT_TOKEN environment variable (the old
DISCORD_MAIN_TOKEN name still works), else from watcher_session.json (saved on
first run), else typed at a prompt that shows * and saved there. A token from the
environment variable is never saved. The
token is never written to the debug log, and is deliberately NOT read from
BadgeMaxxer's session.json (that file holds the other account's token). A
rejected token (4004) is deleted automatically; --reset-token forgets it.
watcher_session.json and watcher_debug.log are git-ignored, never commit them.

Requires the packages websockets and davey, which the BadgeMaxxer installers
install. BadgeMaxxer starts the watcher from its Start Watcher menu entry.

Usage, from the BadgeMaxxer folder with the Python that runs BadgeMaxxer
(Linux: the installer's .venv/bin/python, Windows: py -3):
  .venv/bin/python Watcher/stream_watcher.py
  .venv/bin/python Watcher/stream_watcher.py 1065604516399026176
  .venv/bin/python Watcher/stream_watcher.py 1065604516399026176 --guild 123 --channel 456
Stop with Ctrl+C (leaves the stream and the voice channel cleanly). On Linux,
closing the terminal window or a SIGTERM does the same.
"""

import argparse
import asyncio
import json
import os
import random
import signal
import time
import traceback

from watcher_common import (
    CAPABILITIES,
    CLIENT_PROPERTIES,
    DBG,
    DEFAULT_MAX_ATTEMPTS,
    FATAL_GATEWAY_CODES,
    GATEWAY_CLOSE_CODES,
    GATEWAY_OFFLINE_LIMIT,
    GATEWAY_URL,
    LOCATE_WAIT_SECONDS,
    LOGGED_EVENTS,
    MAX_SESSION_SECONDS,
    ORIGIN,
    STABLE_SECONDS,
    STEP_TIMEOUT,
    TEARDOWN_PAUSE,
    VOICE_CLOSE_CODES,
    ask_digits,
    async_input,
    close_code,
    davey,
    exit_pause,
    forget_token,
    get_token,
    join_support_server,
    load_client_properties,
    log,
    token_user_id,
    wait_all,
    wait_any,
    websockets,
)
from watcher_voice import VoiceLink


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

        self.properties = None
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
        self.tasks = [t for t in self.tasks if not t.done()]
        self.tasks.append(task)
        return task

    def close_links(self):
        """Cancel both voice links right away (their own cleanup closes sockets and tasks)."""
        for link in (self.stream_link, self.main_link):
            task = getattr(link, "task", None)
            if task is not None and not task.done():
                task.cancel()


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
        try:
            await asyncio.sleep(interval * random.random())
            while True:
                if not self.acked:
                    log("Gateway stopped answering, reconnecting.")
                    await ws.close(code=4000)
                    return
                self.acked = False
                await ws.send(json.dumps({"op": 1, "d": self.seq}))
                await asyncio.sleep(interval)
        except (websockets.ConnectionClosed, OSError):
            return

    async def identify(self):
        await self.send_raw(2, {
            "token": self.token,
            "capabilities": CAPABILITIES,
            "properties": self.properties or CLIENT_PROPERTIES,
            "presence": {"status": "online", "since": 0, "activities": [], "afk": False},
            "compress": False,
            "client_state": {"guild_versions": {}},
        })

    async def run(self):
        failures = 0
        offline_since = None
        loop = asyncio.get_running_loop()
        self.properties, source = await loop.run_in_executor(None, load_client_properties)
        log(f"Client properties: {source}, build {self.properties.get('client_build_number')}.")
        try:
            while not self.fatal:
                try:
                    outcome = await self.connect_once()
                    failures = 0
                    offline_since = None
                except (OSError, websockets.WebSocketException, asyncio.TimeoutError) as exc:
                    failures += 1
                    if offline_since is None:
                        offline_since = time.monotonic()
                    outcome = "network error"
                    log(f"Gateway connection error: {exc!r}")
                    if failures >= 2 and self.resume_url:
                        log("Resume address not reachable, using the main gateway address.")
                        self.resume_url = None
                if self.fatal:
                    break
                if offline_since is not None and time.monotonic() - offline_since >= GATEWAY_OFFLINE_LIMIT:
                    log(f"Could not reach Discord for {GATEWAY_OFFLINE_LIMIT // 60} minutes. "
                        "Check your internet connection.")
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
                        await ws.close(code=4000)
                        return "reconnect requested"
                    elif op == 9:
                        if not msg.get("d"):
                            self.session_id = self.seq = self.resume_url = None
                        await ws.close(code=4000)
                        await asyncio.sleep(1 + random.random() * 4)
                        return "invalid session"
                    elif op == 0:
                        await self.dispatch(msg.get("t"), msg.get("d") or {})
                return "closed"
            except asyncio.CancelledError:
                await self.leave_voice()
                raise
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

    async def leave_voice(self):
        if self.ws is None:
            return
        try:
            if self.stream_key:
                await asyncio.wait_for(self.send_raw(19, {"stream_key": self.stream_key}), 2)
            if self.joined_channel:
                await asyncio.wait_for(self.send_raw(4, {"guild_id": self.joined_channel[0],
                                                         "channel_id": None, "self_mute": True,
                                                         "self_deaf": False, "self_video": False}), 2)
        except Exception:
            pass
        self.stream_key = None
        self.joined_channel = None

    async def cleanup(self):
        await self.teardown(pause=0)
        for t in self.tasks:
            t.cancel()


    async def dispatch(self, name, d):
        if name in LOGGED_EVENTS:
            DBG.frame("gateway", "<", {"t": name, "d": d})
        else:
            DBG.write("gateway", f"< {name} (omitted)")

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
        elif name == "READY_SUPPLEMENTAL":
            for guild in d.get("guilds", []):
                self.scan_guild(guild)
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
        self.close_links()
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
        log("Could not find that user in any voice channel the alt account can see.")
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
        for name, value in (("rtc", rtc), ("rtc_server-1", minus_one),
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
                self.close_links()
                raise
            except Exception as exc:
                DBG.write("trace", traceback.format_exc())
                outcome = ("failed", f"unexpected error {exc!r}", None, None)
            held = time.time() - started
            delete_reason = self.stream_delete_reason
            was_live = self.target_live
            if outcome[0] == "ended" and not was_live:
                self.live_event.clear()
            await self.teardown()

            # Live before and after teardown (the voice state of a real stream end can
            # arrive just after STREAM_DELETE): Discord dropped only this viewer, retry.
            if outcome[0] == "ended" and was_live and self.target_live:
                outcome = ("failed", f"stream deleted with reason {delete_reason} "
                                     "while the target is still live", None, None)
            if outcome[0] in ("ended", "cycle"):
                attempts = 0
                if outcome[0] == "ended":
                    log("Stream ended. Waiting for the target to go live again.")
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
                          self.keypair, video=strat["video"], keep_port=strat["keep_port"],
                          channel_id=self.rtc_channel_id)
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
        can_send = self.connected.is_set() or bool(pause)
        if self.stream_key and can_send:
            await self.try_send(19, {"stream_key": self.stream_key})
        if self.joined_channel and can_send:
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
    ap = argparse.ArgumentParser(description="Watch a Go Live stream from an alt account.")
    ap.add_argument("user_id", nargs="?", help="user ID of the account that is streaming")
    ap.add_argument("--guild", help="guild ID (skips auto-detection)")
    ap.add_argument("--channel", help="voice channel ID (skips auto-detection)")
    ap.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS,
                    help="how many attempts before giving up")
    ap.add_argument("--log", default="watcher_debug.log", help="debug log path")
    ap.add_argument("--reset-token", action="store_true", help="forget the saved token and ask again")
    return ap.parse_args()


def prepare(args):
    """Prompts and the help server join, run before the event loop so one Ctrl+C stops them."""
    print("Stream watcher (alt account)")
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
    retries = 0
    while token_user_id(token) == target_id:
        print("That token belongs to the account being watched. The watcher needs the token of a different (alt) account.")
        forget_token()
        if retries == 3:
            raise SystemExit("Still the same account as the one being watched, stopping.")
        retries += 1
        token = get_token(fresh=True)
    join_support_server(token)
    return token, target_id, preset


def stop_on_signals(task):
    """On POSIX, SIGTERM and SIGHUP (terminal closed) cancel the main task once, so the
    Ctrl+C cleanup runs and the alt leaves the stream and the voice channel."""
    if os.name == "nt":
        return
    loop = asyncio.get_running_loop()
    stopping = False

    def stop():
        nonlocal stopping
        if not stopping:
            stopping = True
            task.cancel()

    for sig in (signal.SIGTERM, signal.SIGHUP):
        loop.add_signal_handler(sig, stop)


async def main(args, token, target_id, preset):
    stop_on_signals(asyncio.current_task())
    watcher = StreamWatcher(token, target_id, max_attempts=max(1, args.max_attempts), preset=preset)
    log("Connecting to the gateway.")
    await watcher.run()
    if watcher.history:
        log(f"Debug log (tokens removed): {DBG.path}")


if __name__ == "__main__":
    try:
        args = parse_args()
        token, target_id, preset = prepare(args)
        asyncio.run(main(args, token, target_id, preset))
    except (KeyboardInterrupt, asyncio.CancelledError):
        log("Stopped.")
    except EOFError:
        log("No interactive terminal (stdin closed). Run the watcher from a terminal window.")
    except Exception as exc:
        log(f"Error: {exc!r}")
        DBG.write("trace", traceback.format_exc())
        traceback.print_exc()
    exit_pause()
