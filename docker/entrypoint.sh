#!/bin/sh
# Entrypoint: start warp-svc, bring the tunnel up in proxy mode, then run
# the Go binary. The WARP registration lives on the mounted volume, so the
# registration step is skipped when one already exists.
set -e

# Seed the config from the shipped example on first run.
if [ ! -f /etc/warp-proxy/config.yaml ] && [ -f /etc/warp-proxy/config.example.yaml ]; then
    cp /etc/warp-proxy/config.example.yaml /etc/warp-proxy/config.yaml
fi

warp-svc &
WARP_SVC_PID=$!

# warp-svc needs a moment before it accepts warp-cli calls.
i=0
while [ "$i" -lt 30 ]; do
    if warp-cli status >/dev/null 2>&1; then
        break
    fi
    i=$((i + 1))
    sleep 1
done

if warp-cli registration show >/dev/null 2>&1; then
    echo "warp registration already present, skipping registration"
else
    echo "registering WARP client"
    warp-cli registration new
fi

warp-cli mode proxy
warp-cli connect

# The Go binary takes over the foreground.
exec /usr/local/bin/warp-proxy --config /etc/warp-proxy/config.yaml
