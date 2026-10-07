# Mac timers (herdr-watch LOADED, the rest staged — say the word)

Four launchd agents. `herdr-watch` is loaded; backup, sync, and
balances wait for the owner's word.

| Plist | What | When |
|---|---|---|
| `com.estifie.hub-backup.plist` | Encrypted hub snapshot to `~/.local/share/est/backups` + `backup-age` beat | Twice daily 04:17/16:17 |
| `com.estifie.herdr-watch.plist` | herdr mirror (snapshots + instant done/input/started pushes) | KeepAlive daemon |
| `com.estifie.hub-sync.plist` | iOS + backend check sync | Hourly |
| `com.estifie.balances.plist` | Provider credit poll (OpenRouter/fal → `balances set`) | Every 6h |

Install:

```sh
# Binaries first: launchd cannot read ~/Desktop (TCC), so everything
# a timer runs lives in ~/.local/bin. Re-copy after editing a script.
cp scripts/est-herdr-watch scripts/est-balances scripts/hub-backup.sh ~/.local/bin/
cargo build --release --offline && cp target/release/est-hub ~/.local/bin/
cp scripts/launchd/*.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.estifie.hub-backup.plist
launchctl load ~/Library/LaunchAgents/com.estifie.hub-sync.plist
launchctl load ~/Library/LaunchAgents/com.estifie.herdr-watch.plist
# Balances needs its Keychain keys first (see est-balances setup),
# then:
launchctl load ~/Library/LaunchAgents/com.estifie.balances.plist
```

Notes:

- Backup and herdr ride plain ssh (`vps2`) — no tailnet needed.
- Sync needs Tailscale running on this Mac (it PUTs icons over the
  tailnet URL); it quiet-fails to `/tmp/est-hub-sync.log` when off.
  It also needs a local `~/Desktop/iOS` checkout to sync from.
- Logs live in `/tmp/est-herdr-watch.log`, `/tmp/est-hub-backup.log`,
  `/tmp/est-hub-sync.log`, `/tmp/est-balances.log`.
- Unload: `launchctl unload ~/Library/LaunchAgents/<name>.plist`.
- After editing `est-herdr-watch`, `est-balances`, or `hub-backup.sh`:
  re-copy to `~/.local/bin/` (loaded timers run the copy, not the repo).
