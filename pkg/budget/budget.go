// Package budget enforces three layers of cost protection:
//
//  1. Per-call accounting (CostFor): translate (model, in_tokens, out_tokens)
//     into a USD figure using a Pricing table.
//  2. Per-session token cap (Session.Record): refuse new LLM calls when the
//     cumulative tokens consumed by a single review would exceed the limit.
//     This is the runaway-loop guard.
//  3. Per-day USD cap (Daily.Charge): refuse new spend across the entire
//     daemon when the day's accumulated cost exceeds the user's budget.
//     The day boundary is UTC and resets automatically.
//
// These layers are independent and orthogonal; callers can use any subset.
package budget

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ModelPrice is the per-million-token price for one model.
type ModelPrice struct {
	InputUSDPer1M  float64
	OutputUSDPer1M float64
}

// Pricing maps a model identifier (e.g. "gemini/gemini-2.5-flash") to its price.
type Pricing map[string]ModelPrice

// CostFor returns the USD cost of a single LLM call. Unknown models return 0
// rather than error: pricing tables are user-editable and we'd rather under-
// charge in audit than fail a run because of an unconfigured model.
func CostFor(p Pricing, model string, inputTokens, outputTokens int) float64 {
	mp, ok := p[model]
	if !ok {
		return 0
	}
	return mp.InputUSDPer1M*float64(inputTokens)/1_000_000 +
		mp.OutputUSDPer1M*float64(outputTokens)/1_000_000
}

// ErrSessionCap is returned when a session has consumed too many tokens.
var ErrSessionCap = errors.New("budget: session token cap exceeded")

// SessionLimits configures per-session caps.
type SessionLimits struct {
	MaxTokens int // sum of input + output tokens
}

// Session tracks cumulative token usage for one review run.
type Session struct {
	limits SessionLimits
	mu     sync.Mutex
	total  int
}

// NewSession creates a Session with the given limits.
func NewSession(l SessionLimits) *Session {
	return &Session{limits: l}
}

// Record adds the tokens used by one LLM call. Returns ErrSessionCap if this
// call would push the total past the configured maximum (the call is rejected
// BEFORE being made by the caller; nothing is added to total in that case).
func (s *Session) Record(inputTokens, outputTokens int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.total + inputTokens + outputTokens
	if s.limits.MaxTokens > 0 && next > s.limits.MaxTokens {
		return fmt.Errorf("%w: would reach %d, cap is %d", ErrSessionCap, next, s.limits.MaxTokens)
	}
	s.total = next
	return nil
}

// Total returns the current cumulative token count.
func (s *Session) Total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total
}

// ErrDailyCap is returned when the day's USD budget is exhausted.
var ErrDailyCap = errors.New("budget: daily USD cap exceeded")

// DailyLimits configures per-day USD caps.
type DailyLimits struct {
	MaxUSD float64
}

// Clock abstracts time.Now for deterministic tests.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// SystemClock is the default Clock backed by time.Now.
var SystemClock Clock = realClock{}

// Daily tracks accumulated spend within a UTC calendar day.
type Daily struct {
	limits DailyLimits
	clock  Clock
	mu     sync.Mutex
	day    string  // YYYY-MM-DD
	spend  float64 // USD
}

// NewDaily creates a Daily with the given limits and Clock. Pass SystemClock
// in production.
func NewDaily(l DailyLimits, c Clock) *Daily {
	return &Daily{limits: l, clock: c}
}

// Charge adds usd to today's spend. Returns ErrDailyCap if the cap would be
// exceeded; in that case spend is NOT incremented.
func (d *Daily) Charge(usd float64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	today := d.clock.Now().UTC().Format("2006-01-02")
	if today != d.day {
		d.day = today
		d.spend = 0
	}
	next := d.spend + usd
	if d.limits.MaxUSD > 0 && next > d.limits.MaxUSD {
		return fmt.Errorf("%w: would reach $%.4f, cap is $%.4f", ErrDailyCap, next, d.limits.MaxUSD)
	}
	d.spend = next
	return nil
}

// Spend returns today's accumulated spend (USD).
func (d *Daily) Spend() float64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.spend
}
