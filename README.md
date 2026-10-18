# warp-proxy

warp-proxy routes all client traffic through Cloudflare WARP. It manages the
official `warp-cli` client in proxy mode and exposes HTTP and SOCKS5 proxy
listeners, an OpenAI-compatible AI bridge and a Turkish admin web panel.

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
AI tool --> :8593 bridge      --/
browser --> :8590 panel
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
- `internal/front` rewrites Cloudflare-fronted targets to those fastest
  edge IPs ("front IPs"). A host qualifies through the panel's domain
  suffix list or automatic detection that it resolves inside Cloudflare's
  ranges; decisions are cached per host. TLS SNI is untouched, so only
  Cloudflare-fronted sites are rewritten and the pool stays empty until a
  Clean-IP scan has run.
- `internal/bridge` is the AI bridge: an OpenAI-compatible reverse proxy on
  :8593 that forwards requests to the configured upstream through WARP.
  When the upstream answers with a retryable status (429 by default), it
  rotates the WARP exit IP and replays the request once, honoring
  `Retry-After`. Requests are forwarded unchanged, except for the OpenCode
  free-tier identity (`bridge.inject_session`, on by default): the bridge
  adds the `X-Opencode-Session` and `X-Opencode-Request` headers, an
  opencode `User-Agent` and stub tool entries when the client did not
  provide them. Values the client sends are never overwritten.

## Using the AI bridge with opencode

Point the free `opencode` provider at the bridge by merging one key into
`~/.config/opencode/opencode.json`:

```json
{
  "provider": {
    "opencode": {
      "options": {
        "baseURL": "http://HOST:8593/v1"
      }
    }
  }
}
```

`HOST` is the machine running warp-proxy. The bridge forwards everything to
`bridge.upstream` (`https://opencode.ai/zen` by default) through WARP; when
the free tier rate-limits the exit IP with a 429, the bridge rotates WARP
and replays automatically (rate-limited, `bridge.retry_attempts`). Any
OpenAI-compatible client works the same way: set its base URL to
`http://HOST:8593/v1`. The upstream, retry statuses and limits are editable
in the panel's settings page.

## Free-tier session headers

OpenCode's free tier keys anonymous traffic on the `X-Opencode-Session`
header; a bare request that lacks it lands in the anonymous quota and can be
rejected with `FreeUsageLimitError`. When `bridge.inject_session` is on (the
default), the bridge adds, on every upstream request that does not already
carry them:

- `X-Opencode-Session` — `ses_` followed by 26 digits
- `X-Opencode-Request` — `msg_` followed by 24 alphanumeric characters
- an opencode `User-Agent` (an empty or non-opencode one is replaced)
- stub entries in the `tools` array of chat bodies (the free gateway
  requires at least two)

Values sent by the client are respected and never overwritten; the ids are
generated once per request so a replay keeps the same session. Toggle the
whole feature off with `inject_session: false` in the config or the panel.

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
