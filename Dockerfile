# Build stage: compile the static Go binary.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /out/warp-proxy ./cmd/warp-proxy

# Runtime: Debian slim plus the official Cloudflare WARP client.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg nftables \
    && curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
        | gpg --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ bookworm main" \
        > /etc/apt/sources.list.d/cloudflare-client.list \
    && apt-get update && apt-get install -y --no-install-recommends cloudflare-warp \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/warp-proxy /usr/local/bin/warp-proxy
COPY docker/entrypoint.sh /entrypoint.sh
COPY config.example.yaml /etc/warp-proxy/config.example.yaml
RUN chmod +x /entrypoint.sh

EXPOSE 8590 8591 8592
ENTRYPOINT ["/entrypoint.sh"]
