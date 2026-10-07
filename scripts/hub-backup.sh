#!/bin/bash
# hub-backup: pull an encrypted copy of the hub database to this Mac.
#
#   ./scripts/hub-backup.sh            # pull + encrypt + prune to 14 snaps
#   ./scripts/hub-backup.sh --restore FILE.enc OUT.sqlite
#
# The server snapshot comes over the tailnet (ssh vps2), so the only
# new secret is the backup key — generated once into the Mac Keychain
# (service "est-hub-backup") and never written to disk. Encryption is
# stock openssl (aes-256-cbc, pbkdf2, 600k rounds); no new deps.
set -u

cd "$(dirname "$0")/.."

BACKUP_DIR="${EST_HUB_BACKUP_DIR:-$HOME/.local/share/est/backups}"
KEYCHAIN_SERVICE="est-hub-backup"
# Twice-daily snapshots (04:17 + 16:17): 14 files ≈ 7 days. The 12h
# cadence keeps the backup-age heartbeat (miss-after 24h, the hub max)
# from flapping on slightly late runs — a missed full day pages.
KEEP=14
HUB="http://100.120.126.23:18925"

key() {
    security find-generic-password -s "$KEYCHAIN_SERVICE" -w 2>/dev/null
}

ensure_key() {
    if key >/dev/null 2>&1; then
        return 0
    fi
    echo "-- minting a backup key into the Keychain ($KEYCHAIN_SERVICE)"
    PW=$(openssl rand -base64 32)
    security add-generic-password -s "$KEYCHAIN_SERVICE" -a "$USER" -w "$PW" || {
        echo "hub-backup: keychain write failed" >&2
        exit 1
    }
    unset PW
}

encrypt() { # $1 = plain in, $2 = enc out
    openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
        -in "$1" -out "$2" -pass "pass:$(key)" || {
        echo "hub-backup: encrypt failed" >&2
        exit 1
    }
    chmod 600 "$2"
}

decrypt() { # $1 = enc in, $2 = plain out
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -salt \
        -in "$1" -out "$2" -pass "pass:$(key)" || {
        echo "hub-backup: decrypt failed (wrong key or corrupt file?)" >&2
        exit 1
    }
}

if [ "${1:-}" = "--restore" ]; then
    if [ $# -ne 3 ]; then
        echo "usage: hub-backup.sh --restore FILE.enc OUT.sqlite" >&2
        exit 2
    fi
    [ -f "$2" ] || { echo "hub-backup: no such file: $2" >&2; exit 1; }
    decrypt "$2" "$3"
    echo "restored to $3 ($(sqlite3 "$3" 'SELECT COUNT(*) FROM checks;' 2>/dev/null || echo '?') checks)"
    exit 0
fi

if [ $# -ne 0 ]; then
    echo "usage: hub-backup.sh [--restore FILE.enc OUT.sqlite]" >&2
    exit 2
fi

ensure_key
mkdir -p "$BACKUP_DIR"
TMP=$(mktemp -t hub-backup.XXXXXX.sqlite)
trap 'rm -f "$TMP"' EXIT

echo "-- snapshotting on vps2"
ssh -n vps2 "python3 -c \"import sqlite3; s=sqlite3.connect('/var/lib/est-hub/hub.sqlite'); d=sqlite3.connect('/tmp/hub-backup.sqlite'); s.backup(d); d.close(); s.close()\"" || {
    echo "hub-backup: server snapshot failed" >&2
    exit 1
}
scp -q vps2:/tmp/hub-backup.sqlite "$TMP"
ssh -n vps2 'rm -f /tmp/hub-backup.sqlite'

STAMP=$(date +%F-%H%M)
OUT="$BACKUP_DIR/hub-$STAMP.sqlite.enc"
echo "-- encrypting to $OUT"
encrypt "$TMP" "$OUT"

echo "-- pruning to $KEEP snapshots"
ls -1t "$BACKUP_DIR"/hub-*.sqlite.enc 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -f
echo "backup ok: $OUT"

echo "-- reporting backup-age to the hub"
ssh -n vps2 "est-hub checks show backup-age --hub $HUB >/dev/null 2>&1 || est-hub checks add backup-age --type heartbeat --target mac --owner sys --every 43200 --miss-after 86400 --hub $HUB" || {
    echo "hub-backup: backup-age ensure failed (backup itself is fine)" >&2
    exit 1
}
ssh -n vps2 "est-hub results report --check backup-age --ok --reason 'snapshot $STAMP' --hub $HUB && est-hub heartbeats beat --check backup-age --hub $HUB" || {
    echo "hub-backup: backup-age report failed (backup itself is fine)" >&2
    exit 1
}
echo "backup-age reported"
