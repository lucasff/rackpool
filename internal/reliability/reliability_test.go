package reliability

import (
	"math"
	"testing"
	"time"
)

func TestLossProbMatchesBinomial(t *testing.T) {
	// 10 holders, each down with p=0.1, need 4: P(available < 4).
	q := make([]float64, 10)
	for i := range q {
		q[i] = 0.1
	}
	want := 0.0
	for j := range 4 {
		want += binom(10, j) * math.Pow(0.9, float64(j)) * math.Pow(0.1, float64(10-j))
	}
	if got := LossProb(q, 4); math.Abs(got-want) > 1e-15 {
		t.Fatalf("got %g want %g", got, want)
	}
	if LossProb(q[:3], 4) != 1 {
		t.Fatal("fewer holders than k must be certain loss")
	}
}

func binom(n, k int) float64 {
	r := 1.0
	for i := range k {
		r = r * float64(n-i) / float64(i+1)
	}
	return r
}

func TestTrustBuildsSlowlyAndDropsFast(t *testing.T) {
	p := DefaultParams()
	var s Score
	start := time.Unix(0, 0)
	newbie := p.FailProb(s)

	// 30 days of steady heartbeats and a proof passed every hour.
	now := start
	for h := range 30 * 24 {
		for range 60 {
			last := now
			now = now.Add(time.Minute)
			p.Heartbeat(&s, last, now)
		}
		_ = h
		p.Proof(&s, true, now)
	}
	veteran := p.FailProb(s)
	if !(veteran < newbie/5) {
		t.Fatalf("a month of good behaviour should earn trust: new %.3f, veteran %.3f", newbie, veteran)
	}

	// Two failed proofs undo a lot of that.
	p.Proof(&s, false, now)
	p.Proof(&s, false, now)
	if burnt := p.FailProb(s); !(burnt > veteran*1.1) {
		t.Fatalf("failed proofs barely moved the score: %.4f → %.4f", veteran, burnt)
	}

	// A week offline shows up as downtime.
	var flaky Score
	p.Heartbeat(&flaky, time.Time{}, start)
	p.Heartbeat(&flaky, start, start.Add(7*24*time.Hour))
	if !(p.Uptime(flaky) < p.PriorUptime) {
		t.Fatalf("a week-long gap should lower uptime below the prior: %.3f", p.Uptime(flaky))
	}
}
