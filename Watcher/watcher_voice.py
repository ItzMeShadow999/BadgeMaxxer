"""
watcher_voice.py

VoiceLink: one Discord voice websocket (v8) with UDP discovery and DAVE
end-to-end encryption through "davey". The watcher uses one link for the main
voice connection and one for the stream it is watching.

Part of the Watcher package (stream_watcher.py, watcher_voice.py, watcher_common.py).
"""

import asyncio
import json
import socket
import struct
import time
import uuid

from watcher_common import (
    MODES,
    VOICE_CLOSE_CODES,
    DBG,
    close_code,
    davey,
    log,
    websockets,
)


class VoiceLink:
    def __init__(self, label, endpoint, server_id, user_id, session_id, token,
                 group_id, keypair, video=False, keep_port=True, channel_id=None):
        self.keep_port = keep_port
        self.channel_id = channel_id
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
        if self.channel_id:
            data["channel_id"] = str(self.channel_id)
        if self.video:
            data["video"] = True
            data["streams"] = [{"type": "screen", "rid": "100", "quality": 100}]
        await self.send_json(0, data)

    async def heartbeat(self, interval):
        try:
            while True:
                if time.time() - self.last_ack > max(interval * 4, 20):
                    self.say("no heartbeat reply, dropping the connection")
                    await self.ws.close(code=4000)
                    return
                await self.send_json(3, {"t": int(time.time() * 1000), "seq_ack": self.seq_ack})
                await asyncio.sleep(interval)
        except (websockets.ConnectionClosed, OSError):
            return

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
        elif op == 21:
            await self.dave_prepare_transition(data)
        elif op == 22:
            self.dave_execute(data.get("transition_id"))
        elif op == 24:
            await self.dave_prepare_epoch(data)

    def discover_blocking(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
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
            raise socket.timeout("no reply to UDP discovery")
        except BaseException:
            sock.close()
            raise

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
            if self.pending[tid] == 0 and self.dave is not None:
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
