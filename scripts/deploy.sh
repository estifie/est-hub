#!/bin/bash
# deploy: ship the hub to vps2 in one command.
#
#   ./scripts/deploy.sh
#
# Syncs this checkout (minus target/) to /opt/est-hub-src, builds release
# on the server (the /opt/.target cache makes this incremental), installs
# to /usr/local/bin, restarts est-hub.service, and verifies the hub
# answers on the tailnet with no public ingress.
set -u

cd "$(dirname "$0")/.."
export COPYFILE_DISABLE=1

echo "-- syncing source to vps2"
tar czf - --exclude='./target' --exclude='./.git' . \
    | ssh vps2 'rm -rf /opt/est-hub-src-tmp && mkdir -p /opt/est-hub-src-tmp && tar xzf - -C /opt/est-hub-src-tmp && rm -rf /opt/est-hub-src && mv /opt/est-hub-src-tmp /opt/est-hub-src'

echo "-- building release on vps2"
ssh -n vps2 'cd /opt/est-hub-src && /root/.cargo/bin/cargo build --release --locked' || {
    echo "deploy: build failed" >&2
    exit 1
}

TARGET_DIR=$(ssh -n vps2 'cd /opt/est-hub-src && /root/.cargo/bin/cargo metadata --format-version=1 --no-deps --offline 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)[\"target_directory\"])"')
if [ -z "$TARGET_DIR" ]; then
    echo "deploy: could not resolve the server target dir" >&2
    exit 1
fi

echo "-- installing + restarting"
ssh -n vps2 "install -m 0755 $TARGET_DIR/release/est-hub /usr/local/bin/est-hub && install -m 0755 /opt/est-hub-src/scripts/est-vps-health /opt/est-hub-src/scripts/est-digest /usr/local/bin/ && systemctl restart est-hub.service && sleep 2 && systemctl is-active est-hub.service" || {
    echo "deploy: install/restart failed" >&2
    exit 1
}

echo "-- verifying"
ssh -n vps2 '/usr/local/bin/est-hub ping --hub http://100.120.126.23:18925' || {
    echo "deploy: tailnet /ping failed" >&2
    exit 1
}
ssh -n vps2 'EST_VPS_HOST=vps2 /usr/local/bin/est-vps-health --dry-run && /usr/local/bin/est-digest --dry-run' || {
    echo "deploy: vps reporter dry-runs failed" >&2
    exit 1
}
# The phone reaches the hub over the tailnet via `tailscale serve`
# (https://<hub>.<tailnet>.ts.net). Nothing should answer on the old
# public mTLS port from off-tailnet.
if nc -z -w 3 178.104.45.98 18926 2>/dev/null; then
    echo "deploy: 18926 is still reachable off-tailnet — aborting" >&2
    exit 1
fi
echo "deploy: 18926 closed to the world (tailnet-only)"
echo "deploy: live on vps2"
