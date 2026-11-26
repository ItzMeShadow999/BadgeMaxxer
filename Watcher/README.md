# Watcher

Runs on an ALT account. It joins the voice channel of the main account that is Go Live streaming (the account BadgeMaxxer uses), then opens a viewer connection on that stream.

Files, keep them in one folder:

- `stream_watcher.py` entry point and watcher logic
- `watcher_voice.py` voice websocket with UDP discovery and DAVE
- `watcher_common.py` constants, redacted debug log, token storage, helpers

BadgeMaxxer starts it for you from the Start Watcher menu entry, as long as all three files sit in `Watcher/` next to `BadgeMaxxer.py`.

To run it yourself, start it from the BadgeMaxxer folder with the Python that runs BadgeMaxxer. On Linux that is the installer's virtual environment:

```
.venv/bin/python Watcher/stream_watcher.py <streaming account id> [--guild G --channel C]
```

On Windows the installer uses your normal Python, so run `py -3 Watcher\stream_watcher.py <streaming account id>` (or `python` instead of `py -3`).

Requirements: the Python packages `websockets` and `davey`. The BadgeMaxxer installers (`install.ps1`, `install.sh`) download all three files and install whichever of these packages is missing, and Start Watcher installs them too if they are still missing.

The alt account token is read from `DISCORD_ALT_TOKEN` (`DISCORD_MAIN_TOKEN` still works), else `watcher_session.json`, else a hidden prompt. `watcher_session.json` and `watcher_debug.log` are listed in `.gitignore`, do not commit them. `--reset-token` forgets the saved token. A token that belongs to the account being watched is dropped and asked for again.
