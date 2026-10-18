# warp-proxy

warp-proxy routes all client traffic through Cloudflare WARP. It manages the
official `warp-cli` client in proxy mode and exposes two proxy listeners plus
a Turkish admin web panel.

YouTube and many other services block most VPS and cloud IP addresses. A
WARP tunnel gives the machine a Cloudflare exit address instead. When the
health check detects a problem (a configured marker in the response body, a
transport error, or `warp=off` in the trace), warp-proxy reconnects WARP for
a fresh address, rate-limited so it cannot loop.

The proxy is general purpose: HTTP and SOCKS5 clients reach any target, and
the health-check targets and bot markers are fully configurable in the panel
or `config.yaml`.

## How it works

```
client --> :8591 HTTP proxy  --\
client --> :8592 SOCKS5        +--> warp-cli proxy 127.0.0.1:40000 --> WARP
browser --> :8590 panel       --/
```

- `internal/warp` drives `warp-cli` (registration, `mode proxy`,
  connect/disconnect). Two reconnect modes: `reconnect`
  (disconnect + connect) and `reregister` (delete + new registration).
- `internal/health` checks the tunnel periodically, detects flags and
  triggers rate-limited reconnects. Limits: minimum interval between
  reconnects, a burst cap, and a cooldown after the burst.
- `internal/proxy` implements the HTTP CONNECT proxy and the SOCKS5 server;
  both dial every target through the warp-cli upstream proxy.
- `internal/web` serves the panel: status, exit IP, counters, manual
  reconnect, editable settings and a log view. Login is a username plus a
  bcrypt password hash with a cookie session.
- `internal/cleanip` is the Clean-IP scanner: it measures TCP latency from
  the server to candidate Cloudflare edge IPs (official ips-v4 list), ranks
  the fastest, and can pin one as the WARP tunnel endpoint
  (`warp-cli tunnel endpoint set` plus a rate-limited reconnect).

## Run

Set a first-run password and start:

```sh
echo 'WARP_PROXY_PASSWORD=change-me' > .env
docker compose up -d --build
```

The container runs `warp-svc`, registers WARP on first start (the
registration persists in the `warp-registration` volume), switches to proxy
mode, connects, then starts the Go binary.

Open `http://<host>:8590`, log in with `admin` and the password. Use the
proxy ports from any client:

```sh
curl -x http://HOST:8591 https://www.cloudflare.com/cdn-cgi/trace
curl --socks5 HOST:8592 https://www.cloudflare.com/cdn-cgi/trace
```

`warp=on` in the trace confirms the exit goes through WARP.

## Configuration

`config.example.yaml` documents every setting. The panel can edit health
targets, bot markers, reconnect mode and rate limits at runtime; listener
ports and the warp-cli binary need a restart.

## Development

```sh
make vet
make test   # unit tests; proxy and health tests use fake upstreams
```

macOS has no warp-cli service, so end-to-end runs happen in Docker.

## Notes

- The container needs `privileged: true` because the WARP client creates a
  tunnel interface.
- A reconnect does not always change the exit address. If the flag persists,
  switch the reconnect mode to `reregister` in the panel.
