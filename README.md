# mediapool

A media library that a group of people store together. Each member contributes disk and bandwidth from their own machine (a NAS, a home server, a VPS). Files are encrypted, split into erasure-coded shards and spread across members' nodes. A byte-identical file is stored once for the whole pool, however many people add it.

- **Private.** The coordinator and storage nodes only ever see ciphertext. Names and keys stay encrypted in a catalog that only members can read.
- **Durable.** A file survives many nodes being offline. Redundancy grows for popular files and for members who prove less reliable. Files that come from a torrent can also be rebuilt from the public swarm by bridge nodes.
- **Usable.** There's an rclone-style CLI, an rclone backend (`rclone mount` and `serve`), WebDAV and HTTP streaming, and a web UI.

> Status: a working prototype. The CLI, Docker images and all the flows below run and are tested, but nothing has been audited or run at real scale.

## Concepts

| Term | What it is |
|---|---|
| **Pool** | The group, and everything stored in it. |
| **Coordinator** | One per pool. Tracks where shards are, schedules repairs and keeps the signed catalog. Never sees plaintext. Must be reachable by every member. |
| **Node** | A member's storage daemon (`mp-node`). Holds shards within the limits its operator sets. |
| **Member** | A person, with a key. Members add, read and remove files. A member usually runs one node. |
| **Catalog** | The signed, append-only log of files, segments and members. The coordinator writes it and every node keeps a copy. |
| **Invite** | A one-time string that lets someone join. It holds the coordinator's address and key, the pool secret and a single-use code. |

## Starting a pool (the founder)

```sh
mp pool init --name alice --coord-url http://alice.duckdns.org:7000
cd mediapool && docker compose up -d
```

`pool init` creates the coordinator key, the pool secret, your member and node keys, `pool.json`, `mediapool.env` (your settings, keep it private) and a `docker-compose.yml` that runs the coordinator and your node.

**The coordinator address must be reachable by every member:**
- Forward TCP 7000 on your router, ideally with a dynamic DNS name.
- If your ISP puts you behind carrier-grade NAT, run the coordinator on a small VPS or behind a tunnel (Cloudflare Tunnel, Tailscale Funnel). It needs little CPU or disk and never sees plaintext.

## Inviting people

```sh
set -a; . mediapool/mediapool.env; set +a
mp invite create --name bob            # --admin to let them invite others too
```

Send the printed `mpool1.…` string privately. It works once and expires after 7 days by default.

## Joining

**With a storage node.** Paste the invite into `deploy/docker-compose.node.yml`, set your limits, and run `docker compose -f docker-compose.node.yml up -d`.

```yaml
MP_INVITE: "mpool1.…"
MP_QUOTA: 2T            # most disk to give the pool
MP_UPLOAD_LIMIT: 50M    # Mbit/s you serve to others
```

On first start the node creates your keys, joins, and writes `data/mediapool.env` for the CLI. There's nothing else to configure, and nobody has to restart anything. Every node learns about you from the catalog.

**CLI only (no storage):** `mp join 'mpool1.…'`.

### Being reachable

Nodes work out how to be reachable on their own (`MP_REACH=auto`):
1. Find your public IP with STUN.
2. Try an automatic router port mapping (UPnP/NAT-PMP).
3. Have the coordinator dial back each candidate address.
4. Use the first that works.

If none do (typically carrier-grade NAT), the node tunnels through the coordinator's relay instead. That works everywhere but is slower, and relayed nodes get less popular content. Forwarding TCP 7100 is the better option, and setting `MP_ADDR` to that address skips the guessing.

## Using the pool

```sh
mp lsd pool:/                                   # directories
mp lsl pool:/movies                             # files with sizes and times
mp copy ~/Media/Movies pool:/movies -P          # upload (skips unchanged files)
mp copy pool:/movies/Alien\ \(1979\) ./ -P      # download
mp cat pool:/movies/x.mkv --offset 1000 --count 100
mp about                                        # totals, dedup ratio, redundancy
mp serve webdav --addr 0.0.0.0:8081 --user me --pass …   # Infuse, Kodi, VLC, Finder
mp rcd                                          # web UI on http://127.0.0.1:5572
```

All flags can also be set as `MP_<FLAG>` environment variables. `mp rc` calls the remote-control API that `mp rcd` and `mp-node --rc-addr` serve (rclone-style `POST /<group>/<method>`). `mp rc rc/list` lists every call.

**rclone:** `rclone/` builds `rclone-mediapool`, which is rclone plus a `mediapool` backend. You get `mount`, `nfsmount`, `serve` and `sync` with everything rclone offers.

## Operator controls

| Variable | Meaning |
|---|---|
| `MP_QUOTA` | Most disk to give the pool (`500G`, `2T`). `0` means free space above `MP_RESERVE`. |
| `MP_RESERVE` | Free disk to always leave alone. |
| `MP_UPLOAD_LIMIT` / `MP_DOWNLOAD_LIMIT` | Bandwidth caps in bits/s (`50M` = 50 Mbit/s). |
| `MP_MAX_TRANSFERS` | Concurrent shard transfers. |
| `MP_DRAIN` | `true` moves all your shards elsewhere first. Use it before leaving the pool or freeing the disk. |
| `MP_RC_ADDR` | Serve the node's web UI and rc API, where you can change limits live. |

## Managing members

```sh
mp member list
mp member remove bob          # admins; removes their nodes too
mp node add nas2 ./nas2/node.key
mp node bridge carol-node true
```

## Development

```sh
go test -race ./...             # unit and multi-node integration tests
scripts/demo.sh                 # 15-process pool: dedup, streaming, mass node loss, coordinator recovery
scripts/join-demo.sh            # pool init → invites → nodes joining with only MP_INVITE
scripts/compose-demo.sh         # the same pool in Docker containers
(cd rclone && go test ./...)    # rclone backend, including rclone's standard backend test suite
```
