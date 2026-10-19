# warp-proxy

warp-proxy routes all client traffic through Cloudflare WARP and serves the
OpenCode free tier through an OpenAI- and Anthropic-compatible AI bridge. It
implements WARP's MASQUE protocol in-process — there is no `warp-cli`, no
`warp-svc`, no tun device, and the container runs unprivileged. One Go binary
exposes an HTTP proxy, a SOCKS5 proxy, the AI bridge and a Turkish admin web
panel.

YouTube and many other services block most VPS and cloud IP addresses. A WARP
tunnel gives the machine a Cloudflare exit address instead. When the health
check detects a problem (a configured marker in the response body, a transport
error, or `warp=off` in the trace), warp-proxy reconnects for a fresh address,
rate-limited so it cannot loop.

## How it works

```
client --> :8591 HTTP proxy  --\
client --> :8592 SOCKS5        +--> MASQUE tunnel (in-process) --> WARP
AI tool --> :8593 bridge      --/
browser --> :8590 panel
```

- `internal/masque` is the WARP MASQUE client: device registration (P-256 key,
  DoH bypass for poisoned DNS), the CONNECT-IP tunnel over HTTP/3 datagrams
  with a hand-written HTTP/2 fallback, and a gVisor userspace netstack that
  turns tunnel IP packets into TCP dials with remote DNS.
- `internal/warp` owns the tunnel lifecycle and the multi-account pool. Every
  account keeps its identity on disk (`state/`); rotation opens the next
  account's fresh session and closes the old tunnel only after the new one is
  up, so a failed rotation never takes the working tunnel down.
- `internal/health` checks the tunnel periodically and triggers rate-limited
  reconnects (minimum interval, burst cap, cooldown after the burst).
- `internal/proxy` implements the HTTP CONNECT proxy and the SOCKS5 server;
  both dial every target through the tunnel, resolving hostnames remotely so
  client hostnames never leak.
- `internal/bridge` is the AI bridge (see below).
- `internal/publicproxy` scrapes public proxy lists, verifies every candidate
  with a real request and keeps the survivors as a fallback exit pool.
- `internal/cleanip` scans the registration's home edge and pins the fastest
  endpoint; `internal/front` rewrites Cloudflare-fronted targets to the
  fastest scanned edge IPs.
- `internal/web` serves the panel: status, per-account exit IPs, manual
  reconnect, Clean-IP and public-proxy pages, editable settings and a log view.

## Run with Docker

Requirements: Docker with Compose v2. No privileged mode, no kernel modules,
no extra packages.

```sh
git clone <this repo> warp-proxy
cd warp-proxy
echo 'WARP_PROXY_PASSWORD=change-me' > .env
docker compose up -d --build
```

What happens on first start:

1. The image builds (Go is compiled inside a stage; the runtime image is
   `debian:bookworm-slim`).
2. The app registers three things lazily: with `warp.accounts: 1` it
   registers one WARP device on the Cloudflare API and opens the MASQUE
   tunnel. Identities persist in the `warp-state` volume, so restarts reuse
   them.
3. The public proxy pool runs its first scrape (optional, see below).

Then open the panel and log in:

- Panel: `http://<host>:8590` — user `admin`, password from `.env`.

Use the proxies from any client:

```sh
curl -x http://HOST:8591 https://www.cloudflare.com/cdn-cgi/trace
curl --socks5 HOST:8592 https://www.cloudflare.com/cdn-cgi/trace
```

`warp=on` in the trace confirms the exit goes through WARP.

Updating is the same command:

```sh
git pull && docker compose up -d --build
```

Volumes: `warp-state` holds the device identities; `./config` holds
`config.yaml` (mounted as a directory because the app writes the config
atomically via rename). The first-run panel password comes from
`WARP_PROXY_PASSWORD` in `.env`; only the bcrypt hash is stored afterwards.

## Using the AI bridge (no opencode client needed)

The bridge on `:8593` is a standalone free-tier gateway: any OpenAI- or
Anthropic-compatible client works without installing `opencode`. The bridge
reproduces the free tier's client fingerprint itself (User-Agent, canonical
session id, a tool named `read`, forced streaming) and exits through WARP.

```sh
# OpenAI format (JSON in, JSON out; streaming also supported)
curl http://HOST:8593/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"minimax-m3.1-flash-free","messages":[{"role":"user","content":"hi"}]}'

# Anthropic format
curl http://HOST:8593/v1/messages \
  -H "Content-Type: application/json" \
  -d '{"model":"minimax-m3.1-flash-free","max_tokens":256,"messages":[{"role":"user","content":"hi"}]}'

# Model catalogue: free models only, one list for both API flavors
curl http://HOST:8593/v1/models
```

Free-model ids end in `-free`; the catalogue passes the upstream entries
through verbatim and adds the fields Anthropic clients expect
(`type`, `display_name`). Requests without `stream: true` are answered with
one JSON object: the bridge forces streaming upstream and reassembles the
stream.

The genuine `opencode` CLI also works pointed at the bridge: merge
`{"provider":{"opencode":{"options":{"baseURL":"http://HOST:8593/v1"}}}}` into
`~/.config/opencode/opencode.json`. Values the client sends (its own session
id, its User-Agent) are respected and never overwritten on the first attempt.

When the upstream answers 429 with a `FreeUsageLimitError`, the bridge rotates
the WARP exit (next account's fresh session in round-robin mode) and replays
the request byte-for-byte, rate-limited. If the WARP retries run out, the
optional public proxy pool is the last-resort exit.

## Exit-IP multiplication

Measured behaviour: the WARP egress IP keys on the tunnel session, not on the
account or the endpoint. Simultaneous tunnels share one egress; each fresh
session draws from the small pool of the datacenter the machine sits in.
warp-proxy therefore offers four levers:

- **Account pool** (`warp.accounts: N`): N identities; reconnects rotate
  through them. With `warp.distribution: round-robin` every account keeps a
  live tunnel and requests spread across them per request.
- **IPv6 egress** (`warp.ipv6_preference: prefer`): hostnames with an AAAA
  record exit through WARP's separate IPv6 egress space instead of the small
  per-colo IPv4 pool. `off` (default) resolves A records only; `only`
  resolves AAAA only. Applies live.
- **Egress dedupe**: in round-robin mode a bounded pass measures every
  tunnel's real exit IP and refreshes colliding workers through the rate
  limiter (startup, plus the panel button). Collisions it cannot resolve are
  shown on the dashboard instead of breaking the pool.
- **Public proxy fallback** (`public_proxy:` section): scraped and verified
  public proxies used only after the WARP retries are exhausted. Sources,
  interval, cap and the check URL are configurable; the panel page shows the
  pool and triggers scans.

## Configuration

`config.example.yaml` documents every setting. The panel edits reconnect
mode, IPv6 preference, rate limits, health targets, bot markers, front rules,
and the bridge upstream and retry settings at runtime; listener ports,
`warp.state_dir`, `warp.accounts`, `warp.distribution` and the whole
`public_proxy` section need a restart (the panel's Public Proxy page shows
the pool and triggers scans at any time).

Key sections:

```yaml
warp:
  state_dir: "state"
  accounts: 3                    # identity pool
  reconnect_mode: "reconnect"    # or "reregister" (delete + fresh registration)
  distribution: "round-robin"    # or "off" (single active tunnel)
  ipv6_preference: "prefer"      # off | prefer | only

public_proxy:
  enabled: true
  interval: "30m"
  max: 100
```

## Development

```sh
make vet
make test   # unit tests, fully offline
```

Live MASQUE tests are gated behind `MASQUE_LIVE=1` and must run where the
network allows MASQUE traffic (the maintainer's local network drops it): the
unit build is cross-compiled, copied into the deployment container and run
with `MASQUE_STATE` pointing at the identity directory. After a code change
run ripwire `quality_delta` and `test-gate`.

## Notes

- The MASQUE protocol is Cloudflare's undocumented consumer protocol; a
  protocol change breaks this client and detecting it is our job. The health
  check doubles as the alarm.
- A reconnect does not always change the exit address: addresses come from a
  small pool and repeats are normal. The dashboard's per-account readout and
  the dedupe pass exist to make that visible.
- The public proxy pool is third-party infrastructure: treat its exits as
  untrusted and keep it as a fallback, not as the primary path.
