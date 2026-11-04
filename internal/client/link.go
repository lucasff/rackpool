package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"mediapool/internal/codec"
	"mediapool/internal/proto"
	"mediapool/internal/transfer"
)

// LinkRegistrar is the node that will serve linked segments: it must accept
// a segment (and be able to regenerate it from the file range) before the
// coordinator is asked to verify it. *node.Node satisfies it.
type LinkRegistrar interface {
	ID() string
	AddLink(seg, root string, cipherSize int, path string, offset, length int64) error
}

// LinkStats reports what LinkFile did. Linked segments are new to the pool
// and served by the origin; Deduped ones were already in the pool (stored or
// linked by someone) and are just referenced. Nothing is uploaded either way.
type LinkStats struct {
	Segments  int
	Linked    int
	Deduped   int
	PlainSize int64
}

// LinkFile adds the file at localPath to the pool under poolPath without
// uploading it. Each segment is sealed and encoded locally to learn its ID
// and root, registered with origin (which serves it from this file from now
// on), then verified and recorded by the coordinator. The file must not
// change afterwards: segments that no longer match their ID can't be served.
func (c *Client) LinkFile(ctx context.Context, origin LinkRegistrar, localPath, poolPath string) (LinkStats, error) {
	var st LinkStats
	f, err := os.Open(localPath)
	if err != nil {
		return st, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return st, err
	}
	if fi.IsDir() {
		return st, fmt.Errorf("%s is a directory", localPath)
	}
	cfg, err := c.PoolConfig(ctx)
	if err != nil {
		return st, err
	}
	params := codec.Params{K: cfg.K, MaxN: cfg.MaxN}
	m := Manifest{Path: cleanPath(poolPath), ModTime: fi.ModTime().UnixNano()}
	buf := make([]byte, cfg.SegmentSize)
	for {
		nr, rerr := io.ReadFull(f, buf)
		if nr > 0 {
			e, deduped, err := c.linkSegment(ctx, params, origin, localPath, m.Size, buf[:nr])
			if err != nil {
				return st, fmt.Errorf("segment %d: %w", len(m.Segments), err)
			}
			m.Segments = append(m.Segments, e)
			m.Size += int64(nr)
			st.Segments++
			if deduped {
				st.Deduped++
			} else {
				st.Linked++
			}
		}
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
			break
		}
		if rerr != nil {
			return st, rerr
		}
	}
	st.PlainSize = m.Size
	if m.ModTime == 0 {
		m.ModTime = time.Now().UnixNano()
	}
	return st, c.putManifest(ctx, m)
}

func (c *Client) linkSegment(ctx context.Context, params codec.Params, origin LinkRegistrar, path string, off int64, plain []byte) (SegmentEntry, bool, error) {
	key, ct, id, err := codec.SealSegment(c.PoolSecret, plain)
	if err != nil {
		return SegmentEntry{}, false, err
	}
	entry := SegmentEntry{ID: id, Key: key, PlainSize: int64(len(plain))}
	shards, err := codec.Encode(params, ct)
	if err != nil {
		return entry, false, err
	}
	root := codec.HashToHex(codec.NewTree(shards).Root)

	// Already in the pool? Then there's nothing to serve: just reference it.
	if s, ok := c.cat.Segment(id); ok && s.Live() {
		return entry, true, nil
	}
	if err := origin.AddLink(id, root, len(ct), path, off, int64(len(plain))); err != nil {
		return entry, false, fmt.Errorf("register with node: %w", err)
	}
	var resp proto.LinkResponse
	req := proto.LinkRequest{Segment: id, CipherSize: len(ct), Root: root, Origin: origin.ID()}
	if err := transfer.PostJSON(ctx, c.HTTP, c.key, c.CoordURL+"/v1/link", req, &resp); err != nil {
		return entry, false, err
	}
	return entry, resp.Exists, nil
}
