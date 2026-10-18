#!/bin/sh
# Entrypoint: seed the config, then run the Go binary. The MASQUE client
# registers and connects in-process; no warp-svc, no tun device, no
# privileges. The WARP identity lives in the state directory on the mounted
# volume, so the registration step is skipped when one already exists.
set -e

if [ ! -f /etc/warp-proxy/config.yaml ] && [ -f /etc/warp-proxy/config.example.yaml ]; then
    cp /etc/warp-proxy/config.example.yaml /etc/warp-proxy/config.yaml
fi

exec /usr/local/bin/warp-proxy --config /etc/warp-proxy/config.yaml
