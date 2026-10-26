#!/usr/bin/env bash
# Runs a whole pool in Docker containers and exercises it from the host:
# per-node quotas and bandwidth caps, dedup, streaming, then draining a node
# by flipping one environment variable.
set -euo pipefail
cd "$(dirname "$0")/../deploy"
export MEDIAPOOL_SECRET=compose-demo-secret
docker compose -f docker-compose.pool.yml down -v --remove-orphans >/dev/null 2>&1 || true
# A new directory per run: Docker Desktop on macOS can keep stale entries for
# bind-mounted paths that were deleted while in use, so paths aren't reused.
export L="local/run-$(date +%s)"
# On Linux, bind mounts keep host ownership, so the services must run as the
# host user to read the keys and write their data. Docker Desktop (macOS)
# maps ownership itself and keeps using the image's default user.
[ "$(uname -s)" = Linux ] && export MP_UID="$(id -u)"
mkdir -p "$L"/{coord,node1,node2,node3,node4,node5,bridge,swarm/abc123,host}
docker build -q -t mediapool:latest .. >/dev/null

run() { docker run --rm -u "$(id -u)" -v "$PWD/$L:/l" --entrypoint "$1" mediapool:latest "${@:2}"; }
COORD=$(run mp-coord -key /l/coord/coord.key -print-pubkey)
members="{\"name\":\"alice\",\"key\":\"$(run mp keygen /l/host/alice.key)\"}"
nodes=''
for n in node1 node2 node3 node4 node5 bridge; do
  members+=",{\"name\":\"op-$n\",\"key\":\"$(run mp keygen /l/host/op-$n.key)\"}"
  pub=$(run mp-node -data /l/$n -print-pubkey)
  bridge=false; [ $n = bridge ] && bridge=true
  nodes+="${nodes:+,}{\"id\":\"$n\",\"key\":\"$pub\",\"owner\":\"op-$n\",\"bridge\":$bridge}"
done
echo "{\"coordinator\":\"$COORD\",\"members\":[$members],\"nodes\":[$nodes]}" >"$L/pool.json"
head -c 20000000 /dev/urandom >"$L/swarm/abc123/Movie.mkv"

docker compose -f docker-compose.pool.yml up -d --quiet-pull 2>&1 | grep -v -E "^ *(Container|Network)" || true
for _ in $(seq 30); do
  [ "$(docker compose -f docker-compose.pool.yml ps --format '{{.Health}}' | grep -c healthy)" -ge 7 ] && break
  sleep 1
done
docker compose -f docker-compose.pool.yml ps --format 'table {{.Service}}\t{{.Status}}'

# Nodes advertise in-network names (node1:7100), so the member CLI runs as a
# one-off container on the same network.
mpc() { docker run --rm --network deploy_default -u "$(id -u)" -v "$PWD/$L:/l" -e MEDIAPOOL_SECRET --entrypoint mp mediapool:latest \
  --coord http://coord:7000 --pool /l/pool.json --key /l/host/alice.key --member alice "$@"; }
echo "== alice adds a movie she got from torrent abc123"
mpc add /l/swarm/abc123/Movie.mkv /movies/Movie.mkv --torrent abc123
sleep 8
mpc status
echo "== read back"
mpc cat /movies/Movie.mkv | cmp - "$L/swarm/abc123/Movie.mkv" && echo "OK: identical"

VICTIM=$(mpc status | awk '$1 ~ /^node/ && $5 > 0 {print $1; exit}')
echo "== operator of $VICTIM (holding a shard) sets MP_DRAIN=true and redeploys"
env "DRAIN_$VICTIM=true" docker compose -f docker-compose.pool.yml up -d "$VICTIM" 2>&1 | grep -v -E "^ *(Container|Network)" || true
sleep 20
mpc status | sed -n '/^NODE/,/^$/p'
mpc cat /movies/Movie.mkv | cmp - "$L/swarm/abc123/Movie.mkv" && echo "OK: identical after drain"
echo "shard files left on $VICTIM: $(find "$L/$VICTIM/shards" -type f ! -name '*.proof' 2>/dev/null | wc -l | tr -d ' ')"
docker compose -f docker-compose.pool.yml logs coord 2>/dev/null | grep -E "moving shard" | sed -E 's/^.*\| [0-9\/: ]+//'
echo
echo "(pool left running; stop with: docker compose -f deploy/docker-compose.pool.yml down)"
