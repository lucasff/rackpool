#!/usr/bin/env bash
# From nothing to a working pool with real processes: a founder creates the
# pool, invites a second operator (who starts a node with only MP_INVITE)
# and a third member (CLI only), and they share files.
set -euo pipefail
cd "$(dirname "$0")/.."
go build -o bin/ ./cmd/...
W=$(mktemp -d)
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$W"; }
trap cleanup EXIT
env_of() { (set -a; . "$1"; set +a; shift; "$@"); }

echo "== founder: mp pool init"
bin/mp pool init --dir "$W/founder" --name alice --coord-url http://127.0.0.1:7000 | sed -n '1,4p'

# The founder's coordinator and node (what docker-compose.yml runs), with a
# small code so a handful of nodes is enough.
bin/mp-coord -pool "$W/founder/pool.json" -key "$W/founder/coord/coord.key" -catalog "$W/founder/coord/catalog.log" \
  -scores "$W/founder/coord/scores.json" -fresh -k 2 -max-n 6 -anchored-n 3 -orphan-n 4 -target-loss 0 -tick 1s 2>"$W/coord.log" &
pids+=($!)
for _ in $(seq 50); do curl -sf http://127.0.0.1:7000/healthz >/dev/null 2>&1 && break; sleep 0.1; done
curl -sf http://127.0.0.1:7000/healthz >/dev/null || { echo "coordinator didn't start:"; cat "$W/coord.log"; exit 1; }
bin/mp-node -pool "$W/founder/pool.json" -id alice-node -data "$W/founder/node" -listen :7101 -reach off -addr http://127.0.0.1:7101 -heartbeat 1s 2>>"$W/nodes.log" &
pids+=($!)

echo "== founder invites four operators"
for who in bob carol dan erin; do
  env_of "$W/founder/mediapool.env" bin/mp invite create --name "$who" 2>"$W/invite.err" >"$W/$who.invite" || { cat "$W/invite.err"; exit 1; }
done
echo "invite looks like: $(cut -c1-40 "$W/bob.invite")…"

echo "== each starts a node with only MP_INVITE (no pool.json, no coordinator key copied by hand)"
port=7102
for who in bob carol dan erin; do
  MP_INVITE=$(cat "$W/$who.invite") bin/mp-node -data "$W/$who" -listen ":$port" -reach off -addr "http://127.0.0.1:$port" -heartbeat 1s 2>>"$W/nodes.log" &
  pids+=($!)
  port=$((port + 1))
done
sleep 3
grep -h "joined the pool" "$W/nodes.log" | sed -E 's/^[0-9\/ :]+//'

echo "== a fifth person joins with the CLI only"
env_of "$W/founder/mediapool.env" bin/mp invite create --name frank 2>/dev/null >"$W/frank.invite"
bin/mp join "$(cat "$W/frank.invite")" --dir "$W/frank" | head -1

echo "== members"
env_of "$W/founder/mediapool.env" bin/mp member list

echo "== bob adds a file from his node's settings; frank reads it"
head -c 3000000 /dev/urandom >"$W/movie.mkv"
env_of "$W/bob/mediapool.env" bin/mp copyto "$W/movie.mkv" "pool:/movies/Movie (2024)/Movie (2024).mkv" 2>&1 | tail -1
env_of "$W/frank/mediapool.env" bin/mp lsl pool:/movies
if cmp <(env_of "$W/frank/mediapool.env" bin/mp cat "pool:/movies/Movie (2024)/Movie (2024).mkv") "$W/movie.mkv"; then echo "OK: identical"; fi

sleep 2 # let a heartbeat report the new usage
echo "== status (founder's view)"
env_of "$W/founder/mediapool.env" bin/mp status | sed -n '/^NODE/,/^$/p'

echo "== reusing an invite fails"
bin/mp join "$(cat "$W/bob.invite")" --dir "$W/mallory" --name mallory 2>&1 | sed 's/^mp: //' || true
