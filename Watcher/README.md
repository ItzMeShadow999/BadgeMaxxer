# Watcher

Runs on an ALT account. It joins the voice channel of the main account that is Go Live streaming (the account BadgeMaxxer uses), then opens a viewer connection on that stream.

Files, keep them in one folder:

- `stream_watcher.py` entry point and watcher logic
- `watcher_voice.py` voice websocket with UDP discovery and DAVE
- `watcher_common.py` constants, redacted debug log, token storage, helpers

```
pip install -r requirements.txt
python stream_watcher.py <streaming account id> [--guild G --channel C]
```

BadgeMaxxer starts it for you from the Streaming and Start Watcher menu entries, as long as all three files sit in `Watcher/` next to `BadgeMaxxer.py`.

Requirements: `websockets` and `davey`. The BadgeMaxxer installers (`install.ps1`, `install.sh`) download all three files and install whichever of these packages is missing. If you run the Watcher from the `Watcher/` folder yourself, use `pip install -r ../requirements.txt` when `requirements.txt` sits in the repo root.

The alt account token is read from `DISCORD_ALT_TOKEN` (`DISCORD_MAIN_TOKEN` still works), else `watcher_session.json`, else a hidden prompt. `watcher_session.json` and `watcher_debug.log` are listed in `.gitignore`, do not commit them. `--reset-token` forgets the saved token. A token that belongs to the account being watched is dropped and asked for again.
