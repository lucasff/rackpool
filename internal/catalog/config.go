package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
)

// TypePoolConfig fixes the parameters every member must agree on. It's the
// catalog's first entry and can't change: members cutting files at
// different segment sizes would never dedup against each other, and
// shards made under one erasure code can't be rebuilt under another.
const TypePoolConfig = "pool.config"

type PoolConfig struct {
	SegmentSize int `json:"segment_size"` // plaintext bytes per segment
	K           int `json:"k"`
	MaxN        int `json:"max_n"`
}

func (p PoolConfig) Validate() error {
	switch {
	case p.SegmentSize < 4<<10 || p.SegmentSize > 256<<20:
		return fmt.Errorf("segment size %d out of range (4 KiB to 256 MiB)", p.SegmentSize)
	case p.K < 1 || p.MaxN <= p.K || p.MaxN > 256:
		return fmt.Errorf("bad erasure code k=%d max_n=%d", p.K, p.MaxN)
	}
	return nil
}

func (s *state) applyConfig(e *Entry) (func(), bool, error) {
	if e.Type != TypePoolConfig {
		return nil, false, nil
	}
	if s.config != nil {
		return nil, true, errors.New("the pool configuration can't change")
	}
	var b PoolConfig
	if err := json.Unmarshal(e.Body, &b); err != nil {
		return nil, true, err
	}
	if err := b.Validate(); err != nil {
		return nil, true, err
	}
	return func() { s.config = &b }, true, nil
}

// Config returns the pool configuration, if it has been recorded.
func (c *Catalog) Config() (PoolConfig, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.config == nil {
		return PoolConfig{}, false
	}
	return *c.state.config, true
}
