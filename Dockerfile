# Build stage: compile the static Go binary.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /out/warp-proxy ./cmd/warp-proxy

# Runtime: the binary is self-contained (MASQUE client + userspace
# netstack), so no Cloudflare package, tun device or privileges are needed.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/warp-proxy /usr/local/bin/warp-proxy
COPY docker/entrypoint.sh /entrypoint.sh
COPY config.example.yaml /etc/warp-proxy/config.example.yaml
RUN chmod +x /entrypoint.sh

EXPOSE 8590 8591 8592 8593
ENTRYPOINT ["/entrypoint.sh"]
