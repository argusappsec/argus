package budget_test

import (
	"errors"
	"testing"
	"time"

	"github.com/argusappsec/argus/pkg/budget"
)

// staticClock returns a fixed time, useful for deterministic daily-window tests.
type staticClock struct{ t time.Time }

func (c staticClock) Now() time.Time { return c.t }

func TestCostFor_KnownModel(t *testing.T) {
	pricing := budget.Pricing{
		"gemini/test": {InputUSDPer1M: 1.0, OutputUSDPer1M: 2.0},
	}
	got := budget.CostFor(pricing, "gemini/test", 1_000_000, 500_000)
	want := 1.0 + 2.0*0.5
	if got != want {
		t.Errorf("cost = %v, want %v", got, want)
	}
}

func TestCostFor_UnknownModelIsZero(t *testing.T) {
	got := budget.CostFor(budget.Pricing{}, "unknown/model", 100, 100)
	if got != 0 {
		t.Errorf("unknown model cost = %v, want 0", got)
	}
}

func TestSession_AcceptsUntilTokenCap(t *testing.T) {
	s := budget.NewSession(budget.SessionLimits{MaxTokens: 1000})
	if err := s.Record(400, 100); err != nil {
		t.Fatalf("call 1: %v", err)
	}
	if err := s.Record(400, 99); err != nil {
		t.Fatalf("call 2: %v", err)
	}
	if err := s.Record(1, 1); err == nil || !errors.Is(err, budget.ErrSessionCap) {
		t.Errorf("call 3 should hit cap, got %v", err)
	}
}

func TestDaily_RejectsAfterCapExceeded(t *testing.T) {
	clk := staticClock{t: time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)}
	d := budget.NewDaily(budget.DailyLimits{MaxUSD: 1.0}, clk)
	if err := d.Charge(0.6); err != nil {
		t.Fatalf("charge 1: %v", err)
	}
	if err := d.Charge(0.5); err == nil || !errors.Is(err, budget.ErrDailyCap) {
		t.Errorf("charge 2 should hit cap, got %v", err)
	}
}

func TestDaily_ResetsOnNewDay(t *testing.T) {
	clk := &mutableClock{t: time.Date(2026, 5, 14, 23, 0, 0, 0, time.UTC)}
	d := budget.NewDaily(budget.DailyLimits{MaxUSD: 1.0}, clk)
	if err := d.Charge(0.9); err != nil {
		t.Fatalf("day1 charge: %v", err)
	}
	clk.t = time.Date(2026, 5, 15, 0, 30, 0, 0, time.UTC)
	if err := d.Charge(0.9); err != nil {
		t.Errorf("day2 should accept, got %v", err)
	}
}

type mutableClock struct{ t time.Time }

func (c *mutableClock) Now() time.Time { return c.t }
