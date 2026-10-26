#!/usr/bin/env bash
# Manual end-to-end check against the real Cloudflare network: the
# coordinator sits behind a temporary quick tunnel (random trycloudflare.com
# URL, no account), every node runs relay-only (no STUN, no port mapping,
# nothing listening publicly), and members reach everything through HTTPS.
# Needs Docker and internet access; not run in CI.
set -euo pipefail
cd "$(dirname "$0")/.."
go build -o bin/ ./cmd/...
W=$(mktemp -d)
pids=() cf=""
cleanup() {
  kill "${pids[@]}" 2>/dev/null || true
  [ -n "$cf" ] && docker rm -f "$cf" >/dev/null 2>&1 || true
  wait 2>/dev/null || true
  rm -rf "$W"
}
trap cleanup EXIT
env_of() { (set -a; . "$1"; set +a; shift; "$@"); }

bin/mp pool init --dir "$W/founder" --name alice --coord-url http://placeholder >/dev/null
bin/mp-coord -pool "$W/founder/pool.json" -key "$W/founder/coord/coord.key" -catalog "$W/founder/coord/catalog.log" \
  -scores "$W/founder/coord/scores.json" -fresh -k 2 -max-n 6 -anchored-n 3 -orphan-n 4 -target-loss 0 -tick 1s 2>"$W/coord.log" &
pids+=($!)

echo "== starting a Cloudflare quick tunnel to the coordinator"
docker pull -q cloudflare/cloudflared:2026.9.2 >/dev/null
cf=$(docker run -d --rm cloudflare/cloudflared:2026.9.2 tunnel --no-autoupdate --url http://host.docker.internal:7000)
URL=""
for _ in $(seq 60); do
  URL=$(docker logs "$cf" 2>&1 | grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' | head -1 || true)
  [ -n "$URL" ] && break
  sleep 1
done
[ -n "$URL" ] || { echo "no tunnel URL"; docker logs "$cf" | tail -20; exit 1; }
echo "tunnel: $URL"
for _ in $(seq 60); do curl -sf "$URL/healthz" >/dev/null 2>&1 && break; sleep 2; done
curl -sf "$URL/healthz" >/dev/null || { echo "tunnel never became reachable"; exit 1; }
echo "coordinator reachable through Cloudflare"
sed -i '' "s#^MP_COORD=.*#MP_COORD=$URL#" "$W/founder/mediapool.env" 2>/dev/null || sed -i "s#^MP_COORD=.*#MP_COORD=$URL#" "$W/founder/mediapool.env"

relayonly=(-reach relay -port-map=false -heartbeat 2s)
bin/mp-node -pool "$W/founder/pool.json" -id alice-node -data "$W/founder/node" -listen 127.0.0.1:7101 \
  -coord "$URL" "${relayonly[@]}" 2>>"$W/nodes.log" &
pids+=($!)
port=7102
for who in bob carol dan; do
  env_of "$W/founder/mediapool.env" bin/mp invite create --name "$who" 2>/dev/null >"$W/$who.invite"
  MP_INVITE=$(cat "$W/$who.invite") bin/mp-node -data "$W/$who" -listen "127.0.0.1:$port" "${relayonly[@]}" 2>>"$W/nodes.log" &
  pids+=($!)
  port=$((port + 1))
done
env_of "$W/founder/mediapool.env" bin/mp invite create --name frank 2>/dev/null >"$W/frank.invite"
bin/mp join "$(cat "$W/frank.invite")" --dir "$W/frank" >/dev/null

echo "== waiting for all four nodes to tunnel in through Cloudflare"
for _ in $(seq 60); do
  n=$(grep -c "relay: node .* connected" "$W/coord.log" || true)
  [ "$n" -ge 4 ] && break
  sleep 1
done
sleep 3
env_of "$W/founder/mediapool.env" bin/mp status | sed -n '/^NODE/,/^$/p'

echo "== bob uploads, frank downloads: every shard crosses Cloudflare twice"
head -c 4000000 /dev/urandom >"$W/movie.mkv"
env_of "$W/bob/mediapool.env" bin/mp copyto "$W/movie.mkv" "pool:/movies/Test (2026)/Test (2026).mkv" 2>&1 | tail -1
if cmp <(env_of "$W/frank/mediapool.env" bin/mp cat "pool:/movies/Test (2026)/Test (2026).mkv") "$W/movie.mkv"; then echo "OK: identical through the tunnel"; fi

echo "== what the coordinator saw as client addresses (should be the tunnel, not the nodes)"
grep -oE "connected from [0-9.:]+" "$W/coord.log" | sort | uniq -c
echo "== nodes' advertised addresses"
env_of "$W/founder/mediapool.env" bin/mp status | awk '/^NODE/{f=1;next} /^$/{f=0} f{print $1, "reach=" $4}'
