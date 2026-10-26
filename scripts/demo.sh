#!/usr/bin/env bash
# Local pool: 1 coordinator, 13 storage nodes, 1 bridge, all separate processes.
# Shows dedup, streaming, rm + GC, bridge repair after mass node loss, and a
# coordinator recovering its catalog from the nodes after losing its disk.
set -euo pipefail
cd "$(dirname "$0")/.."
go build -o bin/ ./cmd/...

W=$(mktemp -d)
export MEDIAPOOL_SECRET="demo-pool-secret"
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$W"; }
trap cleanup EXIT
mp() { bin/mp -pool "$W/pool.json" -key "$W/$1.key" -member "$1" "${@:2}"; }

# Keys and the pool file (public keys only).
COORD_PUB=$(bin/mp keygen "$W/coord.key")
members='' nodes=''
for m in alice bob; do members+="{\"name\":\"$m\",\"key\":\"$(bin/mp keygen "$W/$m.key")\"},"; done
for i in $(seq 1 14); do
  mkdir -p "$W/n$i"
  pub=$(bin/mp keygen "$W/n$i/node.key")
  members+="{\"name\":\"op$i\",\"key\":\"$(bin/mp keygen "$W/op$i.key")\"},"
  id="node$i" bridge=false
  [ "$i" = 14 ] && id=bridge bridge=true
  nodes+="{\"id\":\"$id\",\"key\":\"$pub\",\"owner\":\"op$i\",\"bridge\":$bridge},"
done
echo "{\"coordinator\":\"$COORD_PUB\",\"members\":[${members%,}],\"nodes\":[${nodes%,}]}" >"$W/pool.json"

COORD_FLAGS=(-pool "$W/pool.json" -key "$W/coord.key" -k 4 -max-n 16 -anchored-n 6 -orphan-n 9
  -repair-slack 0 -offline-after 3s -down-after 8s -swarm-check-every 2s -gc-grace 2s -tick 1s)
bin/mp-coord "${COORD_FLAGS[@]}" -catalog "$W/catalog.log" -fresh 2>"$W/coord.log" & COORD=$!
pids+=($COORD)
sleep 0.5

mkdir -p "$W/swarm/abc123"
head -c 30000000 /dev/urandom >"$W/swarm/abc123/Show.S01E01.mkv"

for i in $(seq 1 13); do
  bin/mp-node -pool "$W/pool.json" -id "node$i" -listen ":$((7100 + i))" -data "$W/n$i" -heartbeat 1s 2>>"$W/nodes.log" &
  pids+=($!)
done
bin/mp-node -pool "$W/pool.json" -id bridge -listen ":7199" -data "$W/n14" -heartbeat 1s -bridge-mirror "$W/swarm" 2>>"$W/nodes.log" &
pids+=($!)
sleep 2

echo "== alice adds an episode she got from torrent abc123"
mp alice add "$W/swarm/abc123/Show.S01E01.mkv" /tv/Show/S01E01.mkv -torrent abc123
echo "== bob adds the same bytes under his own name: nothing uploaded"
mp bob add "$W/swarm/abc123/Show.S01E01.mkv" /bob/show-1x01.mkv
echo "== bob tries to delete alice's file"
mp bob rm /tv/Show/S01E01.mkv 2>&1 | sed 's/^.*: //' || true
mp alice ls

echo "== waiting for the bridge to rebuild the segment from the swarm (anchored, 6 shards)"
sleep 7
mp alice status | sed -n '/SEGMENT/,$p'

echo "== streaming over HTTP with a range request"
bin/mp -pool "$W/pool.json" -key "$W/alice.key" -member alice serve -listen :8080 >/dev/null 2>&1 & pids+=($!)
sleep 1
curl -s -r 1000000-1000015 http://127.0.0.1:8080/tv/Show/S01E01.mkv | xxd | head -1
dd if="$W/swarm/abc123/Show.S01E01.mkv" bs=1 skip=1000000 count=16 2>/dev/null | xxd | head -1

echo "== killing 8 of 13 storage nodes"
for i in $(seq 1 8); do kill "${pids[$i]}" 2>/dev/null; done
sleep 14
mp alice status | sed -n '/SEGMENT/,$p'
echo "== full read back after mass loss"
if cmp <(mp alice cat /tv/Show/S01E01.mkv) "$W/swarm/abc123/Show.S01E01.mkv"; then echo "OK: identical"; fi

echo "== coordinator loses its disk and restarts without -fresh"
kill $COORD; wait $COORD 2>/dev/null || true
bin/mp-coord "${COORD_FLAGS[@]}" -catalog "$W/catalog-new.log" 2>>"$W/coord.log" & pids+=($!)
sleep 4
mp alice status | head -1
if cmp <(mp alice cat /tv/Show/S01E01.mkv) "$W/swarm/abc123/Show.S01E01.mkv"; then echo "OK: identical after coordinator recovery"; fi

echo "== both members remove the file; shards are garbage-collected"
mp alice rm /tv/Show/S01E01.mkv
mp bob rm /bob/show-1x01.mkv
sleep 6
echo "shard files left on disk: $(find "$W"/n* -path '*shards*' -type f ! -name '*.proof' | wc -l | tr -d ' ')"

echo
echo "== coordinator log highlights"
grep -E "rebuilding|swarm (healthy|dead)|shrank|recovered|collected|forked|failed storage" "$W/coord.log" | sed -E 's/^[0-9\/: ]+//; s/ \(t[0-9]+\)$//' | sort | uniq -c | sort -rn
