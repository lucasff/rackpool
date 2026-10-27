# One small image with all three binaries: mp-node (default), mp-coord, mp.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/...

FROM alpine:3.24
RUN apk add --no-cache ca-certificates wget \
 && adduser -D -u 10001 mediapool \
 && mkdir -p /data /config && chown mediapool /data
COPY --from=build /out/ /usr/local/bin/
USER mediapool
# Shards and the node key live in /data; the pool file is mounted at /config.
VOLUME ["/data"]
ENV MP_DATA=/data MP_POOL=/config/pool.json MP_LISTEN=:7100
EXPOSE 7100
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- "http://127.0.0.1${MP_LISTEN}/healthz" >/dev/null || exit 1
ENTRYPOINT ["mp-node"]
