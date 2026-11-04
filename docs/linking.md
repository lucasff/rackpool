# Linking files instead of uploading them (prototype)

Linking adds a file to the pool without uploading it. The node that holds the
file serves it, and every member sees it in the pool like any other file. The
pool's view becomes the union of every member's library, while each library
stays on its owner's disk.

## How it works

Segments are encrypted with a key derived from their plaintext, and the
erasure code is deterministic. A node that has a segment's plaintext can
therefore regenerate any of its shards, with the same Merkle proof, byte for
byte. A linked segment has no stored shards: when a reader asks the origin
node for a shard, the node reads the file range, seals and encodes it, and
serves the result. Readers can't tell a linked shard from a stored one.

1. The node reads each segment of the file once, to compute its ID and root.
2. It records the segment in `links.json` in its data directory: file path,
   offset and length.
3. The coordinator fetches k shards from the node and checks they rebuild the
   segment, as it does for an upload. Then it adds the segment to the catalog
   with an `origin` (the node's ID).
4. The member's manifest is written as usual, so the file appears in the pool.

## Using it

Run `mp-node` with a link root and member credentials for the rc API:

```sh
MP_LINK_ROOT=/library            # files under here can be linked
MEDIAPOOL_SECRET=...             # needed to regenerate segments
MP_RC_ADDR=127.0.0.1:5572 MP_RC_USER=admin MP_RC_PASS=...
MP_RC_MEMBER=alice MP_RC_MEMBER_KEY=/data/member.key
```

Then link a file or a whole tree (paths are relative to the link root):

```sh
mp rc node/link src=Movies dst=/movies
# a big tree: run it as a job (key=value args are strings; _async must be a JSON bool)
mp rc node/link --json '{"src":"/","dst":"/library","_async":true}'
mp rc job/status jobid=1
```

Linking again is cheap: segments already in the pool are only referenced.
macOS metadata files (`._*`, `.DS_Store`) are skipped.

## Limits of the prototype

- **Availability follows the origin.** A linked file is readable only while its
  origin node is online. The scheduler doesn't repair linked segments or copy
  them into the pool. Status reports them as class `linked`, with target k.
- **Dedup onto a linked segment inherits that.** If another member uploads the
  same bytes later, their upload dedups onto the linked segment and uploads
  nothing, so their copy also depends on the origin.
- **Files must not change.** Each segment is checked against its ID when it's
  regenerated. If the file changed, the node refuses to serve it, and readers
  get an error rather than wrong bytes. Re-link the file to fix it.
- **Reads cost the origin a segment read.** The node regenerates a whole
  segment (16 MiB by default) for a read and keeps the last 4 in memory. On a
  cloud-backed mount such as rclone, that's a download per segment read.
- **No storage proofs.** The coordinator verifies a linked segment once, when
  it's linked, and doesn't challenge it afterwards, so the origin isn't made to
  re-read its files. Linked segments earn no storage credit.

## Next steps

- Replicate popular linked segments into the pool (hot expansion), so heavily
  watched titles survive the origin going offline.
- Let a later upload of the same bytes take over a linked segment and give it
  normal redundancy.
- Watch the link root and link new files automatically.
