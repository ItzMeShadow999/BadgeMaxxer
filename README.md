<div align="center">

<p align="center">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<img src="https://github.com/ItzMeShadow999/My-assets/blob/main/Mxx.png?raw=true" alt="BadgeMaxxer" width="240" /></p>

# BadgeMaxxer

**Discord badge leveling: Go Live stream time, game time and game variety.**

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-EDCB40?style=for-the-badge&logo=python&logoColor=white&labelColor=1a1a1a" alt="Python 3.9+" />
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-EDCB40?style=for-the-badge&labelColor=1a1a1a" alt="Windows | Linux" />
  <img src="https://img.shields.io/badge/dependencies-websockets%20%7C%20davey-C9A40E?style=for-the-badge&labelColor=1a1a1a" alt="websockets | davey" />
  <img src="https://img.shields.io/badge/single%20file-BadgeMaxxer.py-C9A40E?style=for-the-badge&logo=files&logoColor=white&labelColor=1a1a1a" alt="Single file" />
  <a href="https://github.com/ItzMeShadow999/BadgeMaxxer/stargazers">
    <img src="https://img.shields.io/github/stars/ItzMeShadow999/BadgeMaxxer?style=for-the-badge&logo=github&logoColor=white&color=EDCB40&labelColor=1a1a1a" alt="GitHub stars" />
  </a>
</p>

<p align="center">
  <img src="https://github.com/mezotv/discord-badges/raw/main/assets/game-time/eternal.svg" alt="Game Time icon" height="20" />
  <img src="https://img.shields.io/badge/Game%20Time-Patched-EDCB40?style=flat-square&labelColor=1a1a1a" alt="Game Time" />
  <img src="https://github.com/mezotv/discord-badges/raw/main/assets/game-variety/universalist.svg" alt="Game Variety icon" height="20" />
  <img src="https://img.shields.io/badge/Game%20Variety-supported-EDCB40?style=flat-square&labelColor=1a1a1a" alt="Game Variety" />
  <img src="https://github.com/mezotv/discord-badges/raw/main/assets/streaming/phenomenon.svg" alt="Streaming icon" height="20" />
  <img src="https://img.shields.io/badge/Go%20Live%20Streaming-supported-EDCB40?style=flat-square&labelColor=1a1a1a" alt="Go Live Streaming" />
<a href="https://discord.gg/DTEBqvv9fb">
  <img src="https://img.shields.io/discord/1573044682051551262?label=BadgeMaxxer%20Inc.&style=flat-square&logo=discord&logoColor=white&color=EDCB40&labelColor=1a1a1a" alt="BadgeMaxxer Inc. Discord" />
</a>
  
</p>

</div>

---

## Features

- **Game Time** (patched by Discord): few titles, long sessions. Defaults to 3 games for 10h each. Discord stopped counting these sessions in November 2026, so progress will most likely not move. The option stays in case that changes.
- **Game Variety**: the whole detectable catalog, short sessions. Defaults to all titles for 1h each.
- **Streaming**: real Go Live with `Streamer/assets/video.mp4` or a generated test video, run by `Streamer/Streamer.js` (Node.js) in its own window. It streams for the minutes you enter there, or until you stop it.
- **Level up all**: asks for all three up front, then runs them in order. Game Time is skipped unless you include it.
- **Inspect Profile**: lists the badges currently on your account.

## Requirements

- Python 3.9 or newer
- Windows or Linux (the fingerprint option is Windows only)
- On Linux: `curl` or `wget`, and Python with `venv` (on Debian and Ubuntu: `python3-venv`). `wl-copy`, `xclip` or `xsel` are optional, for copying the token snippet and the GitHub login code. `secret-tool` is recommended so tokens go to the desktop keyring instead of a plaintext file (Debian and Ubuntu: `libsecret-tools`, Arch and Fedora: `libsecret`).
- `websockets` and `davey` for the Watcher (voice and stream connection with DAVE encryption). The installers and BadgeMaxxer install them for you if missing.
- For Streaming: Node.js 22.18 or newer with `npm`, and `ffmpeg` on PATH. BadgeMaxxer installs the two npm packages from `Streamer/package.json` into `Streamer/` on first use.

## Quick run

PowerShell:

```powershell
irm https://github.com/ItzMeShadow999/BadgeMaxxer/releases/latest/download/install.ps1 | iex
```

This downloads BadgeMaxxer and the Watcher into `%USERPROFILE%\BadgeMaxxer`, installs the Python packages that are missing (packages you already have are skipped), and starts it. Your `session.json` is never overwritten.

Linux:

```sh
curl -fsSL https://github.com/ItzMeShadow999/BadgeMaxxer/releases/latest/download/install.sh | sh
```

This downloads BadgeMaxxer and the Watcher into `~/BadgeMaxxer`, installs the Python packages that are missing into a virtual environment at `~/BadgeMaxxer/.venv` (packages already there are skipped), and starts it. Your `session.json` is never overwritten. The Watcher opens in your desktop's terminal, set `TERMINAL` to use another one.

### Verified installs

The installer pins to a release tag, downloads that release's `SHA256SUMS`, and checks every file against it before saving. A mismatch aborts the install and nothing is written.

To pin an exact version, or to read the installer before running it:

```powershell
$env:BADGEMAXXER_TAG = "v1.3.4"
irm https://github.com/ItzMeShadow999/BadgeMaxxer/releases/download/v1.3.4/install.ps1 -OutFile install.ps1
notepad install.ps1
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

On Linux:

```sh
curl -fsSLO https://github.com/ItzMeShadow999/BadgeMaxxer/releases/download/v1.3.4/install.sh
less install.sh
BADGEMAXXER_TAG=v1.3.4 sh install.sh
```

## Usage

```bash
python BadgeMaxxer.py
```

On Linux, run it with the Python from the installer's virtual environment:

```sh
~/BadgeMaxxer/.venv/bin/python ~/BadgeMaxxer/BadgeMaxxer.py
```

On first run it asks for your account token and a `cf_clearance` cookie, then saves them to `session.json` next to the script. Use **Refresh Credentials & Cookie** in the menu to update them later.

| Menu option | What it does |
|---|---|
| Level up all | Game Variety and Streaming in one run, Game Time only if you include it |
| Game Time (patched by Discord) | Long sessions on a few games, progress will most likely not move |
| Game Variety | Short sessions across many games |
| Streaming | Headless Go Live in a voice channel |
| Start Watcher | Opens the Watcher on an alt account in a new window |
| Inspect Discord Profile & Badges | Shows the badges on your profile |
| Refresh Credentials & Cookie | Updates cookie and analytics token |
| Configure Executable Fingerprint | Optional, Windows only |
| Exit | Quit |

## Streaming requirements

For stream time to count:

1. A second account or a friend must sit in the voice channel. Streaming alone in an empty channel is not counted.
2. **Use data to personalize my Discord experience** must be on (User Settings > Data & Privacy).

## Files

| File | Purpose |
|---|---|
| `BadgeMaxxer.py` | The whole tool |
| `lib/secret_store.py` | Keeps tokens out of plaintext: Windows DPAPI, Linux desktop keyring. The `lib/` folder must sit next to `BadgeMaxxer.py` |
| `Watcher/stream_watcher.py` | Watcher entry point, for an alt account |
| `Watcher/watcher_voice.py` | Watcher voice websocket with UDP discovery and DAVE |
| `Watcher/watcher_common.py` | Watcher constants, redacted debug log, token storage |
| `Streamer/Streamer.js` | The Go Live streamer that Streaming opens in a new window |
| `Streamer/package.json` | Node packages for the streamer, with exact versions |
| `requirements.txt` | Python packages: `websockets`, `davey` |
| `session.json` | Token, cookie, fingerprint and totals (created on first run) |
| `Watcher/watcher_session.json` | Alt account token for the Watcher (created on first Watcher run) |
| `Streamer/streamertoken2.json` | Account token for the streamer (created on first Streaming run) |
| `Streamer/streamer_stats.json` | Hours and sessions streamed, read by the Streaming menu |
| `data/games.json` | Cached games catalog from `cdn.discordapp.com/detectables/games.json`. Delete it to refresh. |

## Notes

- Badge progress usually syncs within 24 to 48 hours.
- `session.json` and `Watcher/watcher_session.json` keep the Discord tokens, cookie, analytics token, GitHub token and fingerprint encrypted with Windows DPAPI (tied to your Windows user) or in the Linux desktop keyring (needs `secret-tool` from libsecret). On Windows the files are also locked to your user with an ACL. Without `secret-tool` on Linux they fall back to plaintext with mode 0600 and a warning. Old plaintext files are migrated on the next start. This does not stop a program already running as you from asking for the secrets. Never share or commit these files.
- The GitHub login is only used to check your star and follow, and requests no scopes (public read only). To revoke it, remove the app under GitHub Settings > Applications.
- `Watcher/watcher_session.json` and `Watcher/watcher_debug.log` are git-ignored. Do not commit them.
- `Streamer/streamertoken2.json` holds the streamer's token in plaintext (mode 0600 on Linux). It is git-ignored, never share or commit it.
- The Watcher needs all three files in `Watcher/`. `Streamer/Streamer.js` and `Streamer/package.json` must also be in the release. A release must contain every installed file in `SHA256SUMS`, or the installers stop with "no checksum listed".

## Disclaimer

This tool uses a user token and sends generated telemetry and streaming activity, which violates Discord's Terms of Service. Accounts using it can be banned. Use a throwaway account, at your own risk. This project is not affiliated with Discord.

## Contributors

<div align="center">
<table>
  <tr>
    <td align="center" width="140">
      <a href="https://discord.com/users/1065604516399026176"><img src="https://cdn.discordapp.com/avatars/1065604516399026176/43d51cebe305c472263d01a60a37b9a6.webp?size=1536" width="100" height="100" alt="literally.shadow"></a><br>
      <sub><b>literally.shadow</b></sub>
    </td>
    <td align="center" width="140">
      <a href="https://discord.com/users/722068753617125466"><img src="https://cdn.discordapp.com/avatars/722068753617125466/8560f8b26a5f59636a9e3d465a865fa1.webp?size=1280" width="100" height="100" alt="rockykln"></a><br>
      <sub><b>rockykln</b></sub>
    </td>
    <td align="center" width="140">
      <a href="https://discord.com/users/1003968507517607976"><img src="https://cdn.discordapp.com/avatars/1003968507517607976/fd40a69b246901bd7b68dc37a8612745.webp?size=1280" width="100" height="100" alt="wept"></a><br>
      <sub><b>wept</b></sub>
    </td>
  </tr>
</table>
</div>

<div align="center">

<sub>Made by <a href="https://github.com/ItzMeShadow999">ItzMeShadow999</a></sub>

</div>

<sub><sub><sub><sub><sub><b>Credits</b></sub></sub></sub></sub></sub>
<br>
<sub><sub><sub><sub><sub>BadgeMaxxer is built on the discord-badge-spoofer by revere-group</sub></sub></sub></sub></sub>
