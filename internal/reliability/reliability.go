// Package reliability scores how much the pool can trust an owner's disks,
// from evidence the coordinator observed itself: heartbeat uptime and
// storage proofs. Self-reported claims never move a score.
//
// A score is a failure probability: the chance a shard on this owner can't
// be served when needed. New owners start from a pessimistic prior, so the
// pool stores more redundancy on them until they've earned trust (that is
// the probation period, with no special case). Trust builds slowly and is
// lost fast: one failed proof outweighs several passes, and evidence decays
// so a long-gone good record doesn't shield a node that has turned bad.
package reliability

import (
	"math"
	"time"
)

type Params struct {
	// Prior for a new owner: assumed uptime and proof pass rate, each held
	// with the weight of PriorWeight of observed time / PriorProofs proofs.
	PriorUptime float64
	PriorWeight time.Duration
	PriorPass   float64
	PriorProofs float64
	// FailWeight is how many passes one failed proof cancels.
	FailWeight float64
	// HalfLife is how fast old evidence fades.
	HalfLife time.Duration
	// OfflineAfter is the heartbeat gap beyond which time counts as down.
	OfflineAfter time.Duration
}

func DefaultParams() Params {
	return Params{
		PriorUptime:  0.8,
		PriorWeight:  24 * time.Hour,
		PriorPass:    0.9,
		PriorProofs:  4,
		FailWeight:   5,
		HalfLife:     30 * 24 * time.Hour,
		OfflineAfter: 2 * time.Minute,
	}
}

// Score is one owner's evidence. The zero value is a brand-new owner.
type Score struct {
	Up, Down       float64 // seconds observed online / offline, decayed
	Passes, Fails  float64 // storage proofs, decayed
	First, LastObs time.Time
}

func (p Params) decay(s *Score, now time.Time) {
	if s.LastObs.IsZero() {
		s.First, s.LastObs = now, now
		return
	}
	dt := now.Sub(s.LastObs).Seconds()
	if dt <= 0 {
		return
	}
	f := math.Exp2(-dt / p.HalfLife.Seconds())
	s.Up, s.Down, s.Passes, s.Fails = s.Up*f, s.Down*f, s.Passes*f, s.Fails*f
}

// Heartbeat records a heartbeat from one of the owner's nodes. The gap since
// the previous observation counts as up time if it was short, down time if
// it exceeded OfflineAfter.
func (p Params) Heartbeat(s *Score, last, now time.Time) {
	if !last.IsZero() {
		gap := now.Sub(last).Seconds()
		if gap < p.OfflineAfter.Seconds() {
			s.Up += gap
		} else {
			s.Down += gap
		}
	}
	p.decay(s, now)
	s.LastObs = now
}

func (p Params) Proof(s *Score, ok bool, now time.Time) {
	p.decay(s, now)
	s.LastObs = now
	if ok {
		s.Passes++
	} else {
		s.Fails++
	}
}

func (p Params) Uptime(s Score) float64 {
	w := p.PriorWeight.Seconds()
	return (s.Up + p.PriorUptime*w) / (s.Up + s.Down + w)
}

func (p Params) PassRate(s Score) float64 {
	bad := s.Fails * p.FailWeight
	return (s.Passes + p.PriorPass*p.PriorProofs) / (s.Passes + bad + p.PriorProofs)
}

// FailProb is the chance a shard on this owner is unavailable when needed.
func (p Params) FailProb(s Score) float64 {
	return 1 - p.Uptime(s)*p.PassRate(s)
}

// LossProb returns the probability that fewer than k of the holders are
// available, given each holder's independent failure probability. Holders
// should be one per owner: shards on the same owner fail together, which is
// why placement never puts two of a segment's shards on one owner.
func LossProb(failProbs []float64, k int) float64 {
	if k <= 0 {
		return 0
	}
	if len(failProbs) < k {
		return 1
	}
	// dist[j] = probability exactly j holders are available so far.
	dist := make([]float64, len(failProbs)+1)
	dist[0] = 1
	for i, q := range failProbs {
		for j := i + 1; j >= 1; j-- {
			dist[j] = dist[j]*q + dist[j-1]*(1-q)
		}
		dist[0] *= q
	}
	loss := 0.0
	for j := range k {
		loss += dist[j]
	}
	return min(1, max(0, loss))
}
