const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const readline = require("readline");
const { spawn, execFile } = require("child_process");

const CONFIG = {
  tokenFile: path.join(__dirname, "streamertoken2.json"),
  statsFile: path.join(__dirname, "streamer_stats.json"),
  ffmpeg: "ffmpeg",
  videoFile: path.join(__dirname, "assets", "video.mp4"),
  width: 320,
  height: 180,
  fps: 10,
  bitrateKbps: 120,
  maxBitrateKbps: 160,
  withAudio: true,
  autoRestart: true,
  restartDelayMs: 4000,
  defaultDurationMin: 0,
  settleMs: 30000,
  joinTimeoutMs: 60000,
  joinTries: 5,
  preFeedMs: 5000,
  endWaitMs: 12000,
  statusEverySec: 10,
  onlyCountWithViewers: true,
  science: true,
  preview: true,
  previewEveryMs: 300000,
  op4Flags: 2,
  op41: true,
  op22: true,
  op16: false,
  qos: false,
  qosEveryMs: 41000,
  debug: true,
  extraEvents: true,
  userPremiumTier: "auto",
  startSciWithViewer: true,
  viewerGraceMs: 3000,
  checkConsent: true,
  grantConsent: false,
};

const sleep = ms => new Promise(r => setTimeout(r, ms));
const uuid = () => crypto.randomUUID();
const causeOf = e => String((e && e.cause && (e.cause.code || e.cause.message)) || (e && e.message) || e);
const log = (tag, msg) => console.log(`  ${new Date().toTimeString().slice(0, 8)} ${tag} · ${msg}`);

const fmtTimer = s => {
  s = Math.max(0, Math.floor(s));
  const p = n => String(n).padStart(2, "0");
  return `${p(Math.floor(s / 3600))}h:${p(Math.floor((s % 3600) / 60))}m:${p(s % 60)}s`;
};
const hostOf = ep => String(ep || "").replace(/^wss?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
const regionOf = host => {
  const h = String(host || "").split(".")[0];
  const m = h.match(/^((?:c-)?[a-z]+)\d/);
  return m ? m[1] : (h.replace(/\d+$/, "").replace(/-+$/, "") || null);
};
const rnd = (a, b) => a + Math.floor(Math.random() * (b - a + 1));

const VOICE_BACKEND = "0.22.4";
const STREAM_BACKEND = "0.22.4+shauno.link.protocol.awareness-e5c426be5";
const RTC_WORKER = "1.7.10";
const backendFor = host => (String(host || "").startsWith("c-") ? STREAM_BACKEND : VOICE_BACKEND);

const parseChannelRef = raw => {
  raw = String(raw || "").trim();
  if (!raw) return null;
  const m = raw.match(/channels\/(\d+|@me)\/(\d{17,21})/);
  if (m) return { guildId: /^\d+$/.test(m[1]) ? m[1] : null, channelId: m[2] };
  const all = raw.match(/\d{17,21}/g);
  return all ? { guildId: null, channelId: all[all.length - 1] } : null;
};

const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9253 Chrome/148.0.7778.280 Electron/42.7.1 Safari/537.36";
const PROPERTIES_URL = "https://cordapi.dolfi.es/api/v2/properties/windows";
const localProps = () => ({
  os: "Windows", browser: "Discord Client", release_channel: "stable", client_version: "1.0.9253",
  os_version: "10.0.26200", os_arch: "x64", app_arch: "x64", system_locale: "en-US", has_client_mods: false,
  browser_user_agent: UA, browser_version: "42.7.1", os_sdk_version: "26200",
  client_build_number: 594031, native_build_number: 88414, client_event_source: null, client_app_state: "focused",
});

async function makeIdentity() {
  let props = null;
  try {
    const r = await fetch(PROPERTIES_URL, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": UA },
      body: "{}",
      signal: AbortSignal.timeout(10000),
    });
    props = (await r.json()).properties;
  } catch {}
  if (!props) props = localProps();
  const ids = { launchId: uuid(), launchSignature: uuid(), heartbeatSession: uuid() };
  props.client_launch_id = ids.launchId;
  props.launch_signature = ids.launchSignature;
  props.client_heartbeat_session_id = ids.heartbeatSession;
  return { ...ids, launchTs: Date.now(), props, superProps: Buffer.from(JSON.stringify(props)).toString("base64") };
}

function makeScience(token, ident) {
  let analytics = null;
  let seq = rnd(15, 34);
  const uuidBase = Buffer.concat([crypto.randomBytes(16), crypto.randomBytes(2), Buffer.from([0, 0])]);
  const clientUuid = n => { const b = Buffer.alloc(24); uuidBase.copy(b); b.writeUInt32LE(Math.max(n, 0) >>> 0, 20); return b.toString("base64"); };
  const getAnalytics = async () => {
    if (analytics) return analytics;
    try {
      const r = await fetch("https://discord.com/api/v9/users/@me?with_analytics_token=true", {
        headers: { authorization: token, "user-agent": UA, "x-super-properties": ident.superProps },
        signal: AbortSignal.timeout(10000),
      });
      if (r.ok) analytics = (await r.json()).analytics_token || null;
    } catch (e) { log("science", "analytics token fetch failed: " + causeOf(e)); }
    return analytics;
  };
  const post = async events => {
    let tok = await getAnalytics();
    for (let i = 0; !tok && i < 2; i++) { await sleep(4000); tok = await getAnalytics(); }
    if (!tok) return [false, "no analytics token"];
    const now = Date.now();
    const body = {
      token: tok,
      events: events.map(([type, props, ago = 0]) => {
        const n = ++seq;
        const track = now - ago;
        return {
          type,
          properties: {
            client_track_timestamp: track,
            client_heartbeat_session_id: ident.heartbeatSession,
            event_sequence_number: n,
            ...props,
            client_performance_memory: 0,
            accessibility_features: 524544,
            rendered_locale: "en-US",
            uptime_app: Math.max(0, Math.floor((track - ident.launchTs) / 1000)),
            launch_signature: ident.launchSignature,
            client_rtc_state: "RTC_CONNECTED",
            client_app_state: "focused",
            client_viewport_width: 1100,
            client_viewport_height: 720,
            ...props,
            client_uuid: clientUuid(n - 3),
            client_send_timestamp: now,
          },
        };
      }),
    };
    try {
      const r = await fetch("https://discord.com/api/v9/science", {
        method: "POST",
        headers: {
          authorization: token, "content-type": "application/json", origin: "https://discord.com",
          referer: "https://discord.com/channels/@me", "user-agent": UA, "x-super-properties": ident.superProps,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10000),
      });
      return [r.status === 204, String(r.status)];
    } catch (e) {
      return [false, String((e && e.cause && e.cause.code) || (e && e.message) || e)];
    }
  };
  return { post };
}

async function consentCheck(token, ident, grant) {
  const headers = {
    authorization: token, "content-type": "application/json", origin: "https://discord.com",
    referer: "https://discord.com/channels/@me", "user-agent": UA, "x-super-properties": ident.superProps,
  };
  const url = "https://discord.com/api/v9/users/@me/consent";
  try {
    const r = await fetch(url, { headers, signal: AbortSignal.timeout(10000) });
    if (!r.ok) { log("consent", `read failed: HTTP ${r.status}`); return; }
    const j = await r.json();
    const off = ["personalization", "usage_statistics"].filter(k => !(j[k] && j[k].consented));
    if (!off.length) { log("consent", "personalization and usage_statistics are both on"); return; }
    log("consent", `OFF: ${off.join(", ")} (streaming badge progress will not count)`);
    if (!grant) { log("consent", "turn on Data & Privacy > Use data to personalize my Discord experience, or set grantConsent: true"); return; }
    const p = await fetch(url, { method: "POST", headers, body: JSON.stringify({ grant: off, revoke: [] }), signal: AbortSignal.timeout(10000) });
    log("consent", `grant ${off.join(", ")} -> HTTP ${p.status}`);
  } catch (e) { log("consent", "check failed: " + causeOf(e)); }
}

const GUILD_TIER = { NONE: 0, TIER_1: 1, TIER_2: 2, TIER_3: 3 };

const connEvents = (c, o) => {
  const part = o.ctx === "stream" ? { participant_type: "streamer" } : {};
  const aw = rnd(100, 400), au = rnd(60, 250), cn = rnd(500, 900), ice = rnd(80, 300), rc = rnd(100, 320);
  const total = aw + au + cn + ice + rc + rnd(0, 12);
  return [
    ["voice_connection_connecting", {
      input_device: "Default", input_device_count: 1, output_device: "Default", output_device_count: 1,
      camera_device: "Default", camera_device_count: 1, guild_id: c.guildId, channel_id: c.channelId,
      rtc_connection_id: o.rtc, hostname: o.host || null, connect_count: 1, context: o.ctx, channel_type: 2,
      ...part, is_muted: true, join_voice_id: o.joinId, connection_serial: o.serial, client_rtc_state: o.state,
    }, o.ago[0]],
    ["voice_connection_success", {
      guild_id: c.guildId, channel_id: c.channelId, channel_type: 2, rtc_connection_id: o.rtc, context: o.ctx,
      voice_backend_version: o.backend, rtc_worker_backend_version: RTC_WORKER, hostname: o.host || null,
      port: 19302, protocol: "webrtc", cloudflare_best_region: null, connect_time: total, connect_count: 1,
      audio_subsystem: "standard", audio_layer: "", automatic_audio_subsystem: true, media_session_id: o.msid,
      ...part, join_voice_id: o.joinId, is_camera_enabled: false, video_supported: true,
      state_awaiting_endpoint_ms: aw, state_authenticating_ms: au, state_connecting_ms: cn, state_disconnected_ms: 0,
      state_ice_checking_ms: ice, state_no_route_ms: 0, state_rtc_connecting_ms: rc, state_rtc_disconnected_ms: 0,
    }, o.ago[1]],
    ["voice_connection_ttc_collected", {
      rtc_connection_id: o.rtc, hostname: o.host || null, time_1_creation_to_connect: aw, time_2_media_engine_connect: rnd(5, 20),
      time_5_scheduling_connected_callback: null, time_6_state_connected_to_end_measure: null, connect_count: 1,
      rtc_connecting_native_connect: null, rtc_connecting_native_codecs: null, rtc_connecting_native_crypto_modes: null,
      select_protocol_duration_ms: rnd(70, 180),
    }, o.ago[2]],
  ];
};

const buildDaveEvent = (c, roster, sinceMs) => ["secure_frames_transition", {
  guild_id: c.guildId, channel_id: c.channelId, channel_type: 2, rtc_connection_id: c.srtc, context: "stream",
  voice_backend_version: backendFor(c.streamHost), rtc_worker_backend_version: RTC_WORKER,
  media_session_id: c.streamMsid, parent_media_session_id: c.voiceMsid, sender_user_id: c.userId,
  transition_id: 0, protocol_version: 1, start_to_init_duration: rnd(600, 1200), init_duration: rnd(8, 25),
  last_proposals_duration: rnd(15, 45), total_proposals_size: 250 * roster, total_commit_welcome_size: 580 * roster,
  commit_wait_duration: rnd(25, 70), commit_duration: rnd(2, 8), commit_size: 100 * roster + 3, commit_error: false,
  active_transition_count: 1, time_since_creation: sinceMs, users_added_count: roster, users_removed_count: 0,
  roster_size_after: roster, alone_wait_duration: 0, time_to_dave_group_excluding_wait: sinceMs + rnd(800, 1300),
  client_app_state: "unfocused",
}];

const buildStartedEvents = c => {
  const base = { guild_id: c.guildId, channel_id: c.channelId, channel_type: 2 };
  const vrtc = uuid();
  const joinId = uuid();
  c.srtc = uuid();
  const vback = backendFor(c.voiceHost), sback = backendFor(c.streamHost);
  const vsc = c.voiceStates || 1;
  const x = CONFIG.extraEvents;
  const ut = CONFIG.userPremiumTier;
  const vconn = x ? connEvents(c, { rtc: vrtc, ctx: "default", host: c.voiceHost, msid: c.voiceMsid, joinId, serial: 0, backend: vback, state: "AWAITING_ENDPOINT", ago: [8818, 7304, 7304] }) : [];
  const sconn = x ? connEvents(c, { rtc: c.srtc, ctx: "stream", host: c.streamHost, msid: c.streamMsid, joinId: null, serial: 1, backend: sback, state: "RTC_CONNECTED", ago: [1055, 0, 0] }) : [];
  const settings = ago => ["stream_settings_update", {
    user_premium_tier: ut, guild_premium_tier: c.guildTier || 0, stream_quality_user_premium_tier: ut ? 1 : 0,
    stream_quality_guild_premium_tier: 2, stream_quality_preset: 3, stream_quality_resolution: c.height,
    stream_quality_frame_rate: c.fps, soundshare_enabled: !!c.withAudio, stream_drawing_enabled: true,
  }, ago];
  return [
    ["join_voice_channel", {
      location: null, channel_id: c.channelId, channel_type: 2, channel_bitrate: c.bitrate || 64000,
      guild_id: c.guildId, game_name: "", game_platform: null, was_moved: false,
      join_voice_id: joinId, custom_status_count: 0, voice_state_count: vsc, video_stream_count: 0, video_enabled: false,
      client_rtc_state: "DISCONNECTED",
    }, 9264],
    ...vconn.slice(0, 1),
    ["media_session_joined", {
      ...base, rtc_connection_id: vrtc, context: "default", voice_backend_version: vback,
      rtc_worker_backend_version: RTC_WORKER, media_session_id: c.voiceMsid, client_rtc_state: "RTC_CONNECTING",
    }, 7594],
    ...vconn.slice(1),
    ...(x ? [settings(4528), settings(1732)] : []),
    ["video_input_toggled", {
      video_input_type: "screen", video_toggle_source: "app", enabled_inputs: ["screen"], preview_enabled: true,
      video_input_resolution: c.height, video_input_frame_rate: c.fps,
      soundshare_session: null, share_game_name: null, share_game_id: null, quality_preset: 3,
      game_platform: null, game_name: null, game_exe_name: null, game_id: null,
      channel_id: c.channelId, channel_type: 2, guild_id: c.guildId,
      media_session_id: c.voiceMsid, voice_state_count: vsc, video_stream_count: 0, video_enabled: false,
    }, 1689],
    ...(x ? [["video_layout_toggled", {
      video_layout: "pip", channel_id: c.channelId, channel_type: 2, guild_id: c.guildId,
      media_session_id: c.voiceMsid, voice_state_count: vsc, video_stream_count: 0, video_enabled: false,
      game_name: null, game_id: null,
    }, 1689]] : []),
    ...sconn.slice(0, 1),
    ["media_session_joined", {
      ...base, rtc_connection_id: c.srtc, context: "stream", voice_backend_version: sback,
      rtc_worker_backend_version: RTC_WORKER, media_session_id: c.streamMsid, parent_media_session_id: c.voiceMsid,
    }, 117],
    ["video_stream_started", {
      channel_id: c.channelId, rtc_connection_id: c.srtc,
      media_session_id: c.streamMsid, parent_media_session_id: c.voiceMsid, sender_user_id: c.userId,
      context: "stream", guild_id: c.guildId, stream_region: c.streamRegion || regionOf(c.streamHost) || regionOf(c.voiceHost),
      stream_source_type: "window", guild_region: regionOf(c.voiceHost),
      participant_type: "streamer", video_layout: "theatre", client_event_source: "APP",
      voice_backend_version: sback, rtc_worker_backend_version: RTC_WORKER,
      video_input_resolution: c.height, video_input_frame_rate: c.fps,
      soundshare_session: null, share_game_name: null, share_game_id: null, quality_preset: 3,
      connection_type: "unknown", effective_connection_speed: "unknown", source_location_stack: ["rtc panel"],
    }, 106],
    ...sconn.slice(1),
  ];
};

const zeros = names => Object.fromEntries(names.map(n => [n, 0]));
const nulls = names => Object.fromEntries(names.map(n => [n, null]));
const withPct = (pre, ps) => ps.map(p => pre + p);

const buildEndedEvent = (c, seconds) => {
  const dur = Math.max(1, Math.round(seconds));
  const enc = Math.max(dur - 1, 0);
  const slow = Math.max(dur - 5, 0);
  const f = c.fps;
  const jit = (x, lo, hi) => +(x * (lo + Math.random() * (hi - lo))).toFixed(3);
  const underF = n => (n > f ? slow : n === f ? Math.round(slow * 0.8) : 0);
  const major = c.width, minor = c.height;
  const tgt = c.bitrateTarget, tmax = c.bitrateMax;
  const frames = Math.max(0, Math.round(f * enc * 0.998));
  return ["video_stream_ended", {
    codec_asymmetric_session: false,
    codec_h264_encode_duration_sec: enc,
    ...zeros(["codec_h265_encode_duration_sec", "codec_vp8_encode_duration_sec", "codec_vp9_encode_duration_sec", "codec_av1_encode_duration_sec", "codec_unknown_encode_duration_sec",
      "duration_connection_type_wifi", "duration_connection_type_cellular", "duration_connection_type_ethernet", "duration_connection_type_bluetooth", "duration_connection_type_other"]),
    duration_connection_type_unknown: enc,
    duration_connection_type_none: 0,
    ...zeros(["duration_effective_connection_speed_2g", "duration_effective_connection_speed_3g", "duration_effective_connection_speed_4g", "duration_effective_connection_speed_5g"]),
    duration_effective_connection_speed_unknown: enc,
    num_layout_changes: 0, duration_layout_fullscreen: 0, duration_layout_theatre: dur + 2,
    ...zeros(["duration_layout_pip", "duration_layout_popout", "duration_layout_portrait", "duration_layout_landscape", "duration_layout_minimized"]),
    target_fps: f, target_resolution_height: c.height, stream_settings_changed: false, num_auto_quality_changes: 0,
    duration: dur, duration_aggregation: enc, duration_stopped_receiving: 0,
    duration_stream_under_8mbps: slow, duration_stream_under_7mbps: slow, duration_stream_under_6mbps: slow, duration_stream_under_5mbps: slow,
    duration_stream_under_4mbps: slow, duration_stream_under_3mbps: slow, duration_stream_under_2mbps: slow, duration_stream_under_1_5mbps: slow,
    duration_stream_under_1mbps: slow, duration_stream_under_0_5mbps: slow, duration_stream_at_0mbps: slow,
    duration_fps_under_60: underF(60), duration_fps_under_55: underF(55), duration_fps_under_50: underF(50), duration_fps_under_45: underF(45),
    duration_fps_under_40: underF(40), duration_fps_under_35: underF(35), duration_fps_under_30: underF(30), duration_fps_under_25: underF(25),
    duration_fps_under_20: underF(20), duration_fps_under_15: underF(15), duration_fps_under_10: underF(10), duration_fps_under_5: underF(5), duration_fps_at_0: 0,
    avg_resolution: minor, avg_minor_resolution: minor, avg_major_resolution: major, min_resolution_width: null, min_resolution_height: null,
    duration_resolution_under_720: minor < 720 ? slow : 0, duration_resolution_under_480: minor < 480 ? slow : 0, duration_resolution_under_360: minor < 360 ? slow : 0,
    num_pauses: 0, duration_paused: 0, duration_zero_receivers: c.zeroRecvSec || 0, duration_video_stopped: 0,
    ...zeros(["duration_hq_simulcast_stream_watched", "duration_lq_simulcast_stream_watched", "duration_hq_simulcast_stream_eligible", "duration_lq_simulcast_stream_eligible",
      "num_quality_changes", "duration_window_occluded", "duration_incoming_video_stopped_for_occlusion", "num_window_occlusion_changes"]),
    fps_percentile1: jit(f, 0.97, 0.985), fps_percentile5: jit(f, 0.978, 0.99), fps_percentile10: jit(f, 0.98, 0.992),
    fps_percentile25: jit(f, 0.99, 0.996), fps_percentile50: jit(f, 0.996, 0.999), fps_percentile75: jit(f, 0.997, 1),
    ...zeros(withPct("bitrate_percentile", [1, 5, 10, 25, 50, 75, 99])),
    ...Object.fromEntries(withPct("resolution_percentile", [1, 5, 10, 25, 50, 75]).map(k => [k, minor])),
    ...zeros(withPct("inbound_bitrate_estimate_percentile", [1, 5, 10, 25, 50, 75, 99])),
    ...zeros(withPct("local_want_percentile", [1, 5, 10, 25, 50, 75, 90, 95])),
    average_local_want: 0, duration_video_effect: 0, cryptor_max_attempts: 0,
    ...zeros(["ffmpeg", "dav1d", "vp8_libvpx", "electron", "videotoolbox", "uncategorized", "unknown", "exynos", "webrtc", "qualcomm", "mediatek", "d3d11videodecoder", "android"].map(n => "duration_decoder_" + n)),
    ...zeros(withPct("client_performance_cpu_percentile", [25, 50, 75, 90, 95]).concat(["client_performance_cpu_mean"])),
    ...zeros(withPct("client_performance_memory_percentile", [25, 50, 75, 90, 95]).concat(["client_performance_memory_min", "client_performance_memory_max", "client_performance_memory_mean"])),
    ...zeros(["sender_freeze_count", "sender_total_freezes_duration", "sender_total_frames_duration", "consecutive_static_color_frames_max"]),
    avg_bitrate: 0, avg_fps: f, num_bytes: 0, num_packets_lost: 0, num_packets: 0, num_frames: frames,
    ...zeros(["", "_no_output", "_timeout", "_generic", "_fallback", "_parameter", "_other"].map(n => "num_frames_codec_error" + n)),
    time_to_first_frame_ms: rnd(900, 1400), num_frames_dropped: 0, num_nacks: 0, num_plis: 0, qp_sum: null, num_keyframes: 1,
    cryptor_passthrough_count: 0, cryptor_success_count: 0, cryptor_failure_count: 0, cryptor_duration: 0, cryptor_attempts: 0,
    cryptor_missing_key_count: 0, cryptor_invalid_nonce_count: 0, cryptor_failure_after_success_count: 0,
    ...zeros(["decode_errors", "decoder_reboots", "score_errors", "frame_drops", "size_mismatches"].map(n => "encoder_quality_" + n)),
    unique_captured_fps: jit(f, 0.99, 0.999),
    target_bitrate_network: tgt, ...Object.fromEntries(withPct("target_bitrate_network_percentile", [1, 5, 10, 25, 50, 75, 99]).map(k => [k, tgt])),
    target_bitrate_max: tmax, outbound_bandwidth_estimate: 0,
    ...Object.fromEntries(withPct("outbound_bandwidth_surplus_percentile", [1, 5, 10, 25, 50, 75, 99]).map(k => [k, -tgt])),
    ...zeros(["nvidia_cuda", "nvidia_direct3d", "nvidia_vulkan", "openh264", "videotoolbox", "amd_direct3d", "amd_vaapi", "intel", "intel_direct3d", "intel_vaapi", "vp8_libvpx", "uncategorized"].map(n => "duration_encoder_" + n)),
    ...zeros(["wmf_chrome", "exynos", "qualcomm", "mediatek", "wmf_sw", "wmf_hw", "wmf_direct3d"].map(n => "duration_encoder_" + n)),
    duration_encoder_unknown: enc,
    average_encode_time_ms: (rnd(20, 70) / 10).toFixed(1),
    ...nulls(["average_encoder_vmaf_score", ...withPct("encoder_vmaf_score_percentile", [1, 5, 10, 25, 50, 75]), "average_encoder_psnr_db", ...withPct("encoder_psnr_db_percentile", [1, 5, 10, 25, 50, 75])]),
    average_outbound_want: 100,
    ...nulls(["frames_dropped_rate_limiter", "frames_dropped_encoder_queue", "frames_dropped_congestion_window", "frames_dropped_encoder"]),
    ...zeros(["duration_hq_simulcast_stream_encoded", "duration_lq_simulcast_stream_encoded", "duration_both_simulcast_streams_encoded", "duration_fps_bandwidth_limited", "duration_resolution_bandwidth_limited"]),
    ...nulls(withPct("video_entropy_percentile", [1, 5, 10, 25, 50, 75, 99])),
    ...zeros(["attach_requested_count", "capturing_count", "capture_stopped_count", "hooked_count", "recv_connect_count", "recv_disconnect_count", "recv_started_count", "recv_stopped_count",
      "recv_failed_count", "recv_format_count", "send_announce_count", "send_start_count", "send_stop_count", "malformed_trace_count", "audio_detected_count",
      "state_transition_detached_count", "state_transition_waiting_count", "state_transition_attached_count", "state_transition_started_count", "state_transition_playing_count",
      "state_transition_silence_count", "unknown_event_count", "first_pid", "last_pid", "unique_pids"].map(n => "soundshare_" + n)),
    soundshare_first_session: null, soundshare_last_session: null,
    channel_id: c.channelId, rtc_connection_id: c.srtc || null, media_session_id: c.streamMsid, parent_media_session_id: c.voiceMsid,
    sender_user_id: c.userId, context: "stream", guild_id: c.guildId,
    stream_region: c.streamRegion || regionOf(c.streamHost) || regionOf(c.voiceHost), stream_source_type: "window", guild_region: "",
    participant_type: "streamer", video_layout: "theatre", client_event_source: "APP",
    voice_backend_version: backendFor(c.streamHost), rtc_worker_backend_version: RTC_WORKER,
    clips_enabled: false, clips_buffer_length: 30000, bandwidth_estimation_experiment: null, app_hardware_acceleration_enabled: true,
    channel_type: 2, max_viewers: c.maxViewers || 0, hostname: c.streamHost || null, hardware_enabled: true, device_performance_class: null,
    soundshare_experimental: false, quality_preset: 3, discord_is_elevated: null, reason: "stream-end",
    sfu_migration: false, sfu_gap_ms: 0, num_sfu_migrations: 0, sfu_address: c.sfuAddress || null,
    client_rtc_state: "DISCONNECTED",
  }];
};

function grabFrame(videoFile) {
  const input = videoFile
    ? ["-ss", "1", "-i", videoFile]
    : ["-f", "lavfi", "-i", `testsrc2=size=${CONFIG.width}x${CONFIG.height}:rate=1`];
  const args = ["-hide_banner", "-loglevel", "error", ...input, "-frames:v", "1", "-vf", "scale=320:-2", "-f", "image2", "-c:v", "mjpeg", "pipe:1"];
  return new Promise(res => {
    execFile(CONFIG.ffmpeg, args, { encoding: "buffer", maxBuffer: 8 * 1024 * 1024, timeout: 30000 }, (err, stdout) => res(err ? null : stdout));
  });
}

async function previewLoop(token, ident, streamKey, videoFile, alive) {
  const url = "https://discord.com/api/v9/streams/" + encodeURIComponent(streamKey) + "/preview";
  const headers = {
    authorization: token, "user-agent": UA, "x-super-properties": ident.superProps,
    origin: "https://discord.com", referer: "https://discord.com/channels/@me",
  };
  for (let i = 0; i < 8; i++) { if (!alive()) return; await sleep(1000); }
  let n = 0;
  while (alive()) {
    n++;
    const jpg = await grabFrame(videoFile);
    if (!jpg || !jpg.length) { log("preview", "frame grab returned nothing (is ffmpeg installed?)"); return; }
    const thumb = "data:image/jpeg;base64," + jpg.toString("base64");
    let up, back;
    try {
      up = (await fetch(url, { method: "POST", headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify({ thumbnail: thumb }), signal: AbortSignal.timeout(15000) })).status;
    } catch (e) { up = causeOf(e); }
    try {
      back = (await fetch(url + "?version=" + Date.now(), { headers, signal: AbortSignal.timeout(15000) })).status;
    } catch (e) { back = causeOf(e); }
    log("preview", `upload #${n} -> ${up}, read back -> ${back}`);
    for (let i = 0; i < CONFIG.previewEveryMs / 1000; i++) { if (!alive()) return; await sleep(1000); }
  }
}

function countViewers(client, channel, streamViewerIds) {
  const ids = new Set(streamViewerIds);
  try { for (const m of channel.members.values()) ids.add(m.id); } catch {}
  ids.delete(client.user.id);
  return ids.size;
}

function handleVoiceMessage(kind, ws, msg, state) {
  const d = msg.d || {};
  if (msg.op === 2) {
    if (CONFIG.op16 && !state.op16Sent.has(ws)) {
      state.op16Sent.add(ws);
      try { ws.send(JSON.stringify({ op: 16, d: {} })); } catch {}
    }
  } else if (msg.op === 4 && d.media_session_id) {
    state.msid[kind] = String(d.media_session_id);
  } else if (msg.op === 15) {
    const total = Object.values(d.pixelCounts || {}).reduce((a, b) => a + Number(b || 0), 0);
    if (state.pixels[kind] !== total) {
      state.pixels[kind] = total;
      log(kind, `server reports viewer pixel demand: ${total} (any=${d.any})`);
    }
  }
}

function hookWs(kind, ws, state) {
  if (!ws || typeof ws.on !== "function" || state.hooked.has(ws)) return;
  state.hooked.add(ws);
  log("hook", "attached to " + kind + " socket");
  ws.on("message", (data, isBinary) => {
    let text;
    if (typeof data === "string") text = data;
    else if (isBinary) return;
    else { try { text = data.toString("utf8"); } catch { return; } }
    let msg;
    try { msg = JSON.parse(text); } catch { return; }
    handleVoiceMessage(kind, ws, msg, state);
  });
}

function patchVoiceSockets(state) {
  const feed = (sock, url, text) => {
    const host = hostOf(url);
    const kind = host && host === state.streamHost ? "stream"
      : host && host === state.voiceHost ? "voice"
      : (state.msid.voice ? "stream" : "voice");
    if (!state.hookSaid) { state.hookSaid = true; log("hook", "voice socket messages are being read"); }
    handleVoiceMessage(kind, sock, JSON.parse(text), state);
  };
  const patch = WS => {
    if (!WS || !WS.prototype || typeof WS.prototype.emit !== "function" || WS.prototype.__tokerEmit) return false;
    const origEmit = WS.prototype.emit;
    WS.prototype.emit = function (ev, data, isBinary) {
      if (ev === "message" && !isBinary) {
        try {
          const url = String(this.url || this._url || "");
          if (/discord\.media/.test(url)) {
            const text = typeof data === "string" ? data : Buffer.isBuffer(data) ? data.toString("utf8") : "";
            if (text && text[0] === "{") feed(this, url, text);
          }
        } catch {}
      }
      return origEmit.apply(this, arguments);
    };
    WS.prototype.__tokerEmit = true;
    return true;
  };
  let n = 0;
  try { if (patch(require("ws"))) n++; } catch {}
  for (const [k, m] of Object.entries(require.cache)) {
    if (/node_modules[\\/]ws[\\/]lib[\\/]websocket\.js$/.test(k) && m && m.exports && patch(m.exports)) n++;
  }
  const NW = globalThis.WebSocket;
  if (typeof NW === "function" && !NW.__tokerWs) {
    class W extends NW {
      constructor(...a) {
        super(...a);
        try {
          const url = String(a[0]);
          if (/discord\.media/.test(url)) this.addEventListener("message", ev => {
            try { if (typeof ev.data === "string" && ev.data[0] === "{") feed(this, url, ev.data); } catch {}
          });
        } catch {}
      }
    }
    W.__tokerWs = true;
    globalThis.WebSocket = W;
    n++;
  }
  log("hook", n ? "voice socket hooks installed (" + n + ")" : "no websocket class found to hook");
}

function patchGateway(client) {
  const ws = client.ws;
  if (!ws || typeof ws.broadcast !== "function" || ws.__tokerPatched) return;
  const orig = ws.broadcast.bind(ws);
  let said = false;
  ws.broadcast = packet => {
    try {
      if (CONFIG.op4Flags && packet && packet.op === 4 && packet.d && packet.d.flags === undefined) {
        packet = { ...packet, d: { ...packet.d, flags: CONFIG.op4Flags } };
        if (!said) { said = true; log("gateway", `voice-state message sent with flags ${CONFIG.op4Flags}`); }
      }
    } catch {}
    return orig(packet);
  };
  ws.__tokerPatched = true;
}

const loadToken = () => {
  try { return JSON.parse(fs.readFileSync(CONFIG.tokenFile, "utf8")).token || null; } catch { return null; }
};
const saveToken = t => {
  fs.writeFileSync(CONFIG.tokenFile, JSON.stringify({ token: t }, null, 2), { mode: 0o600 });
  try { fs.chmodSync(CONFIG.tokenFile, 0o600); } catch {}
};
const loadStats = () => {
  try { return JSON.parse(fs.readFileSync(CONFIG.statsFile, "utf8")); } catch { return { totalHours: 0, sessions: 0 }; }
};
const saveStats = s => { try { fs.writeFileSync(CONFIG.statsFile, JSON.stringify(s, null, 2)); } catch {} };
async function main() {
  if (process.argv.includes("--reset")) { try { fs.unlinkSync(CONFIG.tokenFile); } catch {} }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.on("SIGINT", () => { console.log(); process.exit(0); });
  let muted = false;
  const origWrite = rl._writeToOutput;
  rl._writeToOutput = function (s) { if (!muted) origWrite.call(rl, s); };
  const ask = (q, hidden = false) => new Promise(res => {
    rl.question(q, a => { muted = false; if (hidden) process.stdout.write("\n"); res(a.trim()); });
    muted = hidden;
  });
  const pick = async (label, items, fmt) => {
    items.forEach((it, i) => console.log(`  [${i + 1}] ${fmt(it)}`));
    for (;;) {
      const n = parseInt(await ask(`${label}: `), 10);
      if (n >= 1 && n <= items.length) return items[n - 1];
      console.log("invalid pick");
    }
  };

  const { Client } = require("@lng2004/discord.js-selfbot-v13");
  const { Streamer, prepareStream, playStream, Utils, Encoders } = await import("@dank074/discord-video-stream");

  const client = new Client();
  const streamer = new Streamer(client);
  patchGateway(client);
  const sendGw = payload => { try { client.ws.broadcast(payload); return true; } catch { return false; } };

  let token = loadToken();
  for (;;) {
    while (!token) token = await ask("token: ", true);
    try {
      await client.login(token);
      saveToken(token);
      break;
    } catch (e) {
      console.log("login failed:", e.message || e);
      if (/invalid|unauthor|401/i.test(String(e.message || e))) {
        token = null;
        try { fs.unlinkSync(CONFIG.tokenFile); } catch {}
      } else {
        console.log("not a token problem, keeping saved token, retrying in 5s");
        await sleep(5000);
      }
    }
  }
  console.log(`logged in as ${client.user.username}`);

  const ident = await makeIdentity();
  const science = CONFIG.science ? makeScience(token, ident) : null;
  if (CONFIG.checkConsent) await consentCheck(token, ident, CONFIG.grantConsent);
  if (CONFIG.userPremiumTier === "auto") {
    let pt = 0;
    try {
      const r = await fetch("https://discord.com/api/v9/users/@me", {
        headers: { authorization: token, "user-agent": UA, "x-super-properties": ident.superProps },
        signal: AbortSignal.timeout(10000),
      });
      if (r.ok) pt = Number((await r.json()).premium_type) || 0;
      else log("premium", `lookup failed: HTTP ${r.status}, using 0`);
    } catch (e) { log("premium", "lookup failed: " + causeOf(e) + ", using 0"); }
    CONFIG.userPremiumTier = pt;
    log("premium", `account premium_type ${pt}`);
  }
  const initTs = Date.now();
  if (CONFIG.op41) {
    const sendInit = () => {
      if (sendGw({ op: 41, d: { initialization_timestamp: initTs, session_id: ident.heartbeatSession, client_launch_id: ident.launchId } })) {
        log("gateway", "client-init message (op 41) sent");
      }
    };
    if (client.isReady && client.isReady()) sendInit(); else client.once("ready", sendInit);
  }

  const isVoice = c => c && (c.type === "GUILD_VOICE" || c.type === "GUILD_STAGE_VOICE");
  let channel = null;
  for (const g of client.guilds.cache.values()) {
    const vs = g.voiceStates && g.voiceStates.cache.get(client.user.id);
    const ch = vs && vs.channelId && g.channels.cache.get(vs.channelId);
    if (ch) { channel = ch; break; }
  }
  if (channel) {
    const yn = await ask(`you are in "${channel.name}" (${channel.guild.name}), use it? [Y/n]: `);
    if (/^n/i.test(yn)) channel = null;
  } else {
    log("voice", "no active voice channel detected on the discord client");
  }
  if (!channel) {
    const ref = parseChannelRef(await ask("voice channel id or link (blank = pick from a list): "));
    if (ref) {
      let c = client.channels.cache.get(ref.channelId);
      if (!c) { try { c = await client.channels.fetch(ref.channelId); } catch {} }
      if (isVoice(c) && c.guild) channel = c;
      else console.log("that is not a voice channel I can see, using the list instead");
    }
  }
  if (!channel) {
    const guilds = [...client.guilds.cache.values()];
    if (!guilds.length) { console.log("no servers"); process.exit(1); }
    console.log("\nservers:");
    const g = await pick("server #", guilds, x => x.name);
    const vcs = [...g.channels.cache.values()].filter(isVoice);
    if (!vcs.length) { console.log("no voice channels in that server"); process.exit(1); }
    console.log("\nvoice channels:");
    channel = await pick("channel #", vcs, c => c.name);
  }
  const guild = channel.guild;

  const durIn = await ask(`duration in minutes (0 = until end or Ctrl+C) [${CONFIG.defaultDurationMin}]: `);
  const durationMin = durIn === "" ? CONFIG.defaultDurationMin : Math.max(0, parseFloat(durIn) || 0);
  rl.close();

  const controller = new AbortController();
  let deadline = null;
  if (durationMin > 0) {
    deadline = Date.now() + durationMin * 60000;
    setTimeout(() => controller.abort(), durationMin * 60000);
  }

  const haveFile = !!(CONFIG.videoFile && fs.existsSync(CONFIG.videoFile));
  log("feed", haveFile ? `looping ${CONFIG.videoFile}` : "no video file, using the animated test pattern");
  const stats = loadStats();
  const state = {
    hooked: new WeakSet(), op16Sent: new WeakSet(), msid: {}, pixels: {},
    voiceHost: "", streamHost: "", streamKey: "", viewerIds: new Set(),
    live: false, playing: false, playStart: 0, liveSince: 0, counted: 0, cycleId: 0, ctx: null, lastUnpause: 0, everLive: false,
    streamRegion: "", maxViewers: 0, zeroRecv: 0, sciActive: false, sciEver: false, sciSince: 0, presentSince: 0,
  };
  const viewers = () => countViewers(client, channel, state.viewerIds);
  patchVoiceSockets(state);
  let stopping = false;
  let hookTimer = null, liveTimer = null, tickTimer = null, statusTimer = null, qosTimer = null;

  const markLive = async () => {
    if (state.live) return;
    state.live = true;
    state.everLive = true;
    state.liveSince = Date.now();
    const cycle = ++state.cycleId;
    log("stream", `live: ${guild.name} / ${channel.name} · key ${state.streamKey || "not seen yet"}`);
    state.presentSince = 0;
    if (CONFIG.preview && state.streamKey) {
      previewLoop(token, ident, state.streamKey, haveFile ? CONFIG.videoFile : null,
        () => state.live && state.cycleId === cycle && !stopping).catch(() => {});
    }
  };
  const startScience = async () => {
    if (!science || state.sciActive || !state.live) return;
    state.sciActive = true;
    state.sciEver = true;
    state.sciSince = Date.now();
    state.ctx = {
      guildId: guild.id, channelId: channel.id, userId: client.user.id,
      voiceMsid: state.msid.voice || "", streamMsid: state.msid.stream || "",
      voiceHost: state.voiceHost, streamHost: state.streamHost,
      fps: CONFIG.fps, height: CONFIG.height, bitrate: channel.bitrate,
      voiceStates: channel.members ? channel.members.size : 1,
      streamRegion: state.streamRegion, withAudio: CONFIG.withAudio, width: CONFIG.width,
      bitrateTarget: CONFIG.bitrateKbps * 1000, bitrateMax: CONFIG.maxBitrateKbps * 1000,
      guildTier: GUILD_TIER[String(guild.premiumTier)] || 0,
    };
    state.maxViewers = 0;
    state.zeroRecv = 0;
    try { state.ctx.sfuAddress = (await require("dns").promises.lookup(state.streamHost)).address; } catch {}
    if (!state.ctx.voiceMsid || !state.ctx.streamMsid) log("science", "media session ids not captured (socket hook missed), sending without them");
    const [, info] = await science.post(buildStartedEvents(state.ctx));
    log("science", `stream started events (${state.ctx.voiceStates} in channel) -> ${info}`);
    if (CONFIG.extraEvents) {
      const since = state.sciSince;
      setTimeout(async () => {
        if (stopping || !state.sciActive || state.sciSince !== since || !state.ctx) return;
        const roster = Math.max(2, viewers() + 1);
        const [, i2] = await science.post([buildDaveEvent(state.ctx, roster, Date.now() - since)]);
        log("science", `secure_frames_transition (roster ${roster}) -> ${i2}`);
      }, rnd(8500, 10500));
    }
  };
  const endCycle = () => {
    const wasLive = state.live;
    state.live = false;
    const c = state.ctx;
    state.ctx = null;
    const since = state.sciSince;
    state.sciActive = false;
    state.presentSince = 0;
    if (!wasLive || !science) return Promise.resolve();
    if (!c) { log("science", "no science events were sent for this cycle (nobody else was in the channel)"); return Promise.resolve(); }
    c.maxViewers = state.maxViewers;
    c.zeroRecvSec = Math.round(state.zeroRecv);
    return science.post([buildEndedEvent(c, (Date.now() - since) / 1000)])
      .then(([, info]) => log("science", `stream ended event -> ${info}`));
  };

  const shutdown = async (code = 0) => {
    if (stopping) return;
    stopping = true;
    controller.abort();
    [tickTimer, statusTimer, hookTimer, liveTimer].forEach(t => t && clearInterval(t));
    if (qosTimer) clearTimeout(qosTimer);
    const pending = [endCycle()];
    if (state.streamKey) sendGw({ op: 19, d: { stream_key: state.streamKey } });
    try { streamer.stopStream(); } catch {}
    try { streamer.leaveVoice(); } catch {}
    const hours = state.counted / 3600;
    if (state.counted >= 10) {
      stats.totalHours = (stats.totalHours || 0) + hours;
      stats.sessions = (stats.sessions || 0) + 1;
      saveStats(stats);
      log("stream", `ended · ${fmtTimer(state.counted)} (${hours.toFixed(2)}h) counted streaming hours`);
      log("stream", `total claimed ${stats.totalHours.toFixed(2)}h over ${stats.sessions} sessions · badge progression typically syncs within 24-48 hours`);
    } else if (state.everLive && science && !state.sciEver) {
      log("stream", "ended · science start events were never sent (nobody else joined the channel)");
      log("hint", "run watch.py first or alongside so the alt is in the channel before you go live");
    } else if (state.everLive) {
      log("stream", "ended · 0.00h counted (0 viewers were present, so hours were paused)");
      log("hint", "have an alt or friend sit in the voice channel so hours count");
    } else {
      log("stream", "session ended");
    }
    await Promise.race([Promise.all(pending), sleep(CONFIG.endWaitMs)]);
    try { client.destroy(); } catch {}
    process.exit(code);
  };

  let hits = 0;
  process.on("SIGINT", () => {
    if (++hits > 1) process.kill(process.pid, "SIGKILL");
    console.log("stopping... (Ctrl+C again to force)");
    setTimeout(() => process.kill(process.pid, "SIGKILL"), CONFIG.endWaitMs + 3000).unref();
    shutdown();
  });
  process.on("SIGTERM", () => shutdown());
  process.on("uncaughtException", e => {
    if (/Track is not open/i.test(String(e && e.message))) return console.log("[warn] track not open yet, ignoring frame");
    console.error(e);
    shutdown(1);
  });
  process.on("unhandledRejection", e => log("error", String((e && e.message) || e)));
  const cmd = readline.createInterface({ input: process.stdin });
  cmd.on("line", l => { if (l.trim().toLowerCase() === "end") { log("stream", "end typed, stopping"); shutdown(); } });
  log("stream", "type end and press enter to stop streaming (ctrl+c also works)");

  const mine = k => String(k || "").endsWith(":" + client.user.id);
  client.on("raw", p => {
    if (!p || !p.t) return;
    const d = p.d || {};
    if (p.t === "VOICE_SERVER_UPDATE") state.voiceHost = hostOf(d.endpoint);
    else if (p.t === "STREAM_SERVER_UPDATE" && mine(d.stream_key)) state.streamHost = hostOf(d.endpoint);
    else if ((p.t === "STREAM_CREATE" || p.t === "STREAM_UPDATE") && mine(d.stream_key)) {
      state.streamKey = d.stream_key;
      if (d.region) state.streamRegion = String(d.region);
      state.viewerIds = new Set((d.viewer_ids || []).map(String));
      if (CONFIG.op22 && (p.t === "STREAM_CREATE" || d.paused === true) && Date.now() - state.lastUnpause > 2000) {
        state.lastUnpause = Date.now();
        sendGw({ op: 22, d: { stream_key: d.stream_key, paused: false } });
        log("stream", "stream marked unpaused (op 22 paused=false)");
      }
    }
    if (CONFIG.debug) {
      if (p.t === "VOICE_SERVER_UPDATE") console.log("[raw]", p.t, hostOf(d.endpoint));
      else if (p.t === "VOICE_STATE_UPDATE" && d.user_id === client.user.id) console.log("[raw]", p.t, "channel", d.channel_id);
      if (/^STREAM_/.test(p.t)) console.log("[stream]", p.t, d.stream_key || "", d.endpoint ? hostOf(d.endpoint) : "");
    }
  });
  if (CONFIG.debug) {
    const t0 = Date.now();
    client.on("debug", m => { m = String(m); if (/VOICE|acknowledged|zombie|\[CLOSE\]/.test(m)) console.log("[+" + (Date.now() - t0) + "ms]", m.slice(0, 140)); });
  }

  const __tokerFind = o => {
    if (!o) return null;
    for (const k of ["ws", "_ws", "socket", "_socket", "websocket"]) {
      const w = o[k];
      if (w && typeof w.on === "function") return w;
    }
    for (const k of Object.keys(o)) {
      try {
        const w = o[k];
        if (w && typeof w === "object" && typeof w.on === "function" && "readyState" in w && /discord\.media/.test(String(w.url || w._url || ""))) return w;
      } catch {}
    }
    return null;
  };
  hookTimer = setInterval(() => {
    const vc = streamer.voiceConnection;
    if (!vc) return;
    hookWs("voice", __tokerFind(vc), state);
    if (vc.streamConnection) hookWs("stream", __tokerFind(vc.streamConnection), state);
  }, 20);
  liveTimer = setInterval(() => {
    if (state.live || !state.playing || controller.signal.aborted) return;
    const sc = streamer.voiceConnection && streamer.voiceConnection.streamConnection;
    if (!sc) return;
    if (state.msid.stream || Date.now() - state.playStart > 25000) markLive().catch(() => {});
  }, 500);
  if (CONFIG.qos) {
    const qos = () => {
      const shard = client.ws.shards && client.ws.shards.first && client.ws.shards.first();
      const reasons = ["foregrounded"].concat(streamer.voiceConnection ? ["rtc_connected"] : []);
      sendGw({ op: 40, d: { seq: (shard && shard.sequence) || 0, qos: { active: true, ver: 31, reasons } } });
      qosTimer = setTimeout(qos, CONFIG.qosEveryMs + Math.floor(Math.random() * 1500));
    };
    qosTimer = setTimeout(qos, CONFIG.qosEveryMs);
  }
  let lastTick = Date.now();
  tickTimer = setInterval(() => {
    const now = Date.now();
    const dt = (now - lastTick) / 1000;
    lastTick = now;
    if (state.live && (!CONFIG.onlyCountWithViewers || viewers() > 0)) state.counted += dt;
    if (state.sciActive) {
      const w = state.viewerIds.size;
      if (w > state.maxViewers) state.maxViewers = w;
      if (w === 0) state.zeroRecv += dt;
    }
    if (state.live && science && !state.sciActive) {
      if (!CONFIG.startSciWithViewer || viewers() > 0) {
        if (!state.presentSince) state.presentSince = now;
        if (now - state.presentSince >= (CONFIG.startSciWithViewer ? CONFIG.viewerGraceMs : 0)) startScience().catch(e => log("science", causeOf(e)));
      } else state.presentSince = 0;
    }
  }, 1000);
  statusTimer = setInterval(() => {
    const n = viewers();
    const t = `${fmtTimer(state.counted)} (${(state.counted / 3600).toFixed(2)}h) counted`;
    const sci = science ? ` · science ${state.sciActive ? "on" : "waiting"} · watching ${state.viewerIds.size}` : "";
    if (state.live && n > 0) log("stream", `LIVE (${n} viewer${n === 1 ? "" : "s"}) · ${t}${sci}`);
    else if (state.live) log("stream", `LIVE (0 viewers, hours paused) · ${t} · waiting for a viewer${sci}`);
    else if (streamer.voiceConnection) log("stream", `starting stream · ${t}`);
    else log("stream", `reconnecting · ${t}`);
  }, CONFIG.statusEverySec * 1000);

  log("stream", `settling ${CONFIG.settleMs / 1000}s...`);
  await sleep(CONFIG.settleMs);
  log("voice", "joining...");
  for (let attempt = 1; ; attempt++) {
    try {
      await Promise.race([
        streamer.joinVoice(guild.id, channel.id),
        new Promise((_, rej) => setTimeout(() => rej(new Error(`joinVoice timed out after ${CONFIG.joinTimeoutMs / 1000}s`)), CONFIG.joinTimeoutMs)),
      ]);
      break;
    } catch (e) {
      log("voice", `join attempt ${attempt} failed: ${e.message || e}`);
      try { streamer.leaveVoice(); } catch {}
      if (attempt >= CONFIG.joinTries) { log("voice", `giving up after ${CONFIG.joinTries} attempts`); return shutdown(1); }
      await sleep(10000);
    }
  }
  console.log(`joined ${guild.name} / ${channel.name}, going live${deadline ? ` for ${durationMin} min` : ""}`);

  const spawnFeed = () => {
    const out = ["-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency", "-pix_fmt", "yuv420p"];
    const args = haveFile
      ? ["-re", "-stream_loop", "-1", "-i", CONFIG.videoFile, "-map", "0:v:0", ...(CONFIG.withAudio ? ["-map", "0:a:0?"] : []),
        "-vf", `scale=${CONFIG.width}:${CONFIG.height}`, "-r", String(CONFIG.fps), ...out,
        ...(CONFIG.withAudio ? ["-c:a", "libopus"] : ["-an"]), "-f", "matroska", "pipe:1"]
      : ["-re", "-f", "lavfi", "-i", `testsrc2=size=${CONFIG.width}x${CONFIG.height}:rate=${CONFIG.fps}`,
        ...(CONFIG.withAudio ? ["-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000"] : []), ...out,
        ...(CONFIG.withAudio ? ["-af", "volume=0.001", "-c:a", "libopus"] : ["-an"]), "-f", "matroska", "pipe:1"];
    const ff = spawn(CONFIG.ffmpeg, args, { stdio: ["ignore", "pipe", "pipe"] });
    controller.signal.addEventListener("abort", () => ff.kill("SIGKILL"), { once: true });
    let last = 0;
    ff.stderr.on("data", d => {
      const t = String(d);
      const m = t.match(/frame=\s*(\d+)/);
      if (m && Date.now() - last > 10000) { last = Date.now(); console.log("[ffmpeg] frame", m[1]); }
      else if (/error|invalid/i.test(t)) console.log("[ffmpeg]", t.slice(0, 160));
    });
    return ff;
  };

  await sleep(CONFIG.preFeedMs);
  while (!controller.signal.aborted) {
    state.msid.stream = "";
    const ff = spawnFeed();
    try {
      const { command, output } = prepareStream(ff.stdout, {
        width: CONFIG.width,
        height: CONFIG.height,
        frameRate: CONFIG.fps,
        bitrateVideo: CONFIG.bitrateKbps,
        bitrateVideoMax: CONFIG.maxBitrateKbps,
        videoCodec: Utils.normalizeVideoCodec("H264"),
        encoder: Encoders.software({ x264: { preset: "ultrafast" }, x265: { preset: "ultrafast" } }),
        includeAudio: CONFIG.withAudio,
      }, controller.signal);
      if (command && command.on) command.on("error", e => console.log("ffmpeg:", e.message || e));
      state.playing = true;
      state.playStart = Date.now();
      await playStream(output, streamer, { type: "go-live" }, controller.signal);
    } catch (e) {
      if (!controller.signal.aborted) console.log("stream error:", e.message || e);
    }
    state.playing = false;
    await endCycle();
    ff.kill("SIGKILL");
    if (controller.signal.aborted || !CONFIG.autoRestart) break;
    console.log(`stream ended, restarting in ${CONFIG.restartDelayMs / 1000}s`);
    await sleep(CONFIG.restartDelayMs);
    if (!streamer.voiceConnection) {
      try { await streamer.joinVoice(guild.id, channel.id); } catch (e) { log("voice", `rejoin failed: ${e.message || e}`); }
    }
  }

  console.log("done");
  await shutdown();
}

main().catch(e => { console.error(e); process.exit(1); });
