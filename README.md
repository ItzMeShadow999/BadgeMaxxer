<div align="center">

<p align="center">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<img src="https://github.com/ItzMeShadow999/My-assets/blob/main/Mxx.png?raw=true" alt="BadgeMaxxer" width="240" /></p>

# BadgeMaxxer

**Discord badge leveling: Go Live stream time, game time and game variety.**

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-EDCB40?style=for-the-badge&logo=python&logoColor=white&labelColor=1a1a1a" alt="Python 3.9+" />
  <img src="https://img.shields.io/badge/platform-Windows-EDCB40?style=for-the-badge&logo=windows&logoColor=white&labelColor=1a1a1a" alt="Windows" />
  <img src="https://img.shields.io/badge/dependencies-stdlib%20only-C9A40E?style=for-the-badge&labelColor=1a1a1a" alt="stdlib only" />
  <img src="https://img.shields.io/badge/single%20file-badgemaxxer.py-C9A40E?style=for-the-badge&logo=files&logoColor=white&labelColor=1a1a1a" alt="Single file" />
  <a href="https://github.com/ItzMeShadow999/BadgeMaxxer/stargazers">
    <img src="https://img.shields.io/github/stars/ItzMeShadow999/BadgeMaxxer?style=for-the-badge&logo=github&logoColor=white&color=EDCB40&labelColor=1a1a1a" alt="GitHub stars" />
  </a>
</p>

<p align="center">
  <img src="https://github.com/mezotv/discord-badges/raw/main/assets/game-time/eternal.svg" alt="Game Time icon" height="20" />
  <img src="https://img.shields.io/badge/Game%20Time-supported-EDCB40?style=flat-square&labelColor=1a1a1a" alt="Game Time" />
  <img src="https://github.com/mezotv/discord-badges/raw/main/assets/game-variety/universalist.svg" alt="Game Variety icon" height="20" />
  <img src="https://img.shields.io/badge/Game%20Variety-supported-EDCB40?style=flat-square&labelColor=1a1a1a" alt="Game Variety" />
  <img src="https://github.com/mezotv/discord-badges/raw/main/assets/streaming/phenomenon.svg" alt="Streaming icon" height="20" />
  <img src="https://img.shields.io/badge/Go%20Live%20Streaming-supported-EDCB40?style=flat-square&labelColor=1a1a1a" alt="Go Live Streaming" />
  <img src="https://img.shields.io/badge/discord-badges-5865F2?style=flat-square&logo=discord&logoColor=white&labelColor=1a1a1a" alt="Discord" />
</p>

</div>

---

## Features

- **Game Time**: few titles, long sessions. Defaults to 3 games for 10h each.
- **Game Variety**: the whole detectable catalog, short sessions. Defaults to all titles for 1h each.
- **Streaming**: headless Go Live through the gateway, voice WebSocket and UDP silence frames. Defaults to 1h and auto-stops.
- **Level up all**: asks for all three up front, then runs them in order.
- **Inspect Profile**: lists the badges currently on your account.
- **Smart stream targets**: scans your servers for busy voice channels, skips AFK channels and checks Go Live permissions.

## Requirements

- Python 3.9 or newer
- Windows (fingerprint option and Enter-to-stop use Windows APIs)
- `cryptography` for encrypted silence frames while streaming. It is installed automatically on first run if missing.

## Quick run

PowerShell:

```powershell
irm https://github.com/ItzMeShadow999/BadgeMaxxer/releases/latest/download/install.ps1 | iex
```

This downloads BadgeMaxxer and the Watcher into `%USERPROFILE%\BadgeMaxxer`, installs the Python packages, and starts it. Your `session.json` is never overwritten.

### Verified installs

The installer pins to a release tag, downloads that release's `SHA256SUMS`, and checks every file against it before saving. A mismatch aborts the install and nothing is written.

To pin an exact version, or to read the installer before running it:

```powershell
$env:BADGEMAXXER_TAG = "v1.0.0"
irm https://github.com/ItzMeShadow999/BadgeMaxxer/releases/download/v1.0.0/install.ps1 -OutFile install.ps1
notepad install.ps1
.\install.ps1
```

## Usage

```bash
python badgemaxxer.py
```

On first run it asks for your account token and a `cf_clearance` cookie, then saves them to `session.json` next to the script. Use **Refresh Credentials & Cookie** in the menu to update them later.

| Menu option | What it does |
|---|---|
| Level up all | Game Time, Game Variety and Streaming in one run |
| Game Time | Long sessions on a few games |
| Game Variety | Short sessions across many games |
| Streaming | Headless Go Live in a voice channel |
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
| `badgemaxxer.py` | The whole tool |
| `session.json` | Token, cookie, fingerprint and totals (created on first run) |
| `../data/games.json` | Cached games catalog from `cdn.discordapp.com/detectables/games.json`. Delete it to refresh. |

## Notes

- Badge progress usually syncs within 24 to 48 hours.
- `session.json` holds your token and cookie in plaintext. Never share or commit it.

## Disclaimer

This tool uses a user token and sends generated telemetry and streaming activity, which violates Discord's Terms of Service. Accounts using it can be banned. Use a throwaway account, at your own risk. This project is not affiliated with Discord.


### Credits

BadgeMaxxer is built on the game time and streaming scripts (`games.py` and `stream.py`) from sonujana26's discord-badge-maximizer, MIT licensed, Copyright (c) 2026 Sonu Jana

<div align="center">

<sub>Made by <a href="https://github.com/ItzMeShadow999">ItzMeShadow999</a></sub>

</div>
