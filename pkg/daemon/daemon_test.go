package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/redcarbon-dev/argus/pkg/audit"
	"github.com/redcarbon-dev/argus/pkg/auth"
	"github.com/redcarbon-dev/argus/pkg/budget"
	"github.com/redcarbon-dev/argus/pkg/conversation"
	"github.com/redcarbon-dev/argus/pkg/provider"
	"github.com/redcarbon-dev/argus/pkg/report"
	"github.com/redcarbon-dev/argus/pkg/skill"
	"github.com/redcarbon-dev/argus/pkg/soul"
)

// scriptedProvider returns canned responses in order; the last response is
// repeated if the script runs out. A nil gate makes it synchronous; a non-nil
// gate blocks each Generate until the gate channel is closed.
type scriptedProvider struct {
	mu        sync.Mutex
	responses []provider.Response
	calls     int
	gate      chan struct{}
}

func (f *scriptedProvider) Generate(ctx context.Context, _ provider.Request) (provider.Response, error) {
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return provider.Response{}, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.calls
	if i >= len(f.responses) {
		i = len(f.responses) - 1
	}
	f.calls++
	return f.responses[i], nil
}

func textOnly(text string) provider.Response {
	return provider.Response{Text: text, Usage: provider.Usage{InputTokens: 100, OutputTokens: 50}}
}

// testContext builds a Context wired to a temp home and the given provider.
func testContext(t *testing.T, prov provider.Provider, cap int) *Context {
	t.Helper()
	home := t.TempDir()
	aud, err := audit.NewLogger(filepath.Join(home, "audit.log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { aud.Close() })

	dc := &Context{
		Home:         home,
		DefaultModel: "gemini-2.5-flash",
		Pricing:      budget.Pricing{"gemini-2.5-flash": {InputUSDPer1M: 1, OutputUSDPer1M: 2}},
		Auth:         auth.NewResolver(filepath.Join(home, "users.yaml")),
		Audit:        aud,
		Reports:      report.NewWriter(filepath.Join(home, "reports")),
		Skills:       skill.NewCatalog(skill.Builtin(), filepath.Join(home, "skills")),
		NewProvider: func(_ context.Context, _ string) (provider.Provider, error) {
			return prov, nil
		},
		LoadSoul:   func() (*soul.Soul, error) { return &soul.Soul{}, nil },
		LoadMemory: func() (string, error) { return "", nil },
	}
	dc.Sessions = NewSessionManager(dc, cap)
	return dc
}

func principal() auth.Principal {
	return auth.Principal{ID: "tester", Kind: auth.KindPerson, Role: auth.RoleAdmin, Identity: "local:tester"}
}

func TestGetOrCreate_CapRejectsNeverQueues(t *testing.T) {
	dc := testContext(t, &scriptedProvider{responses: []provider.Response{textOnly("hi")}}, 1)
	ctx := context.Background()

	s1, existing, err := dc.Sessions.GetOrCreate(ctx, "uds", "key-1", principal(), SessionOptions{})
	if err != nil || existing {
		t.Fatalf("first GetOrCreate: existing=%v err=%v", existing, err)
	}

	if _, _, err := dc.Sessions.GetOrCreate(ctx, "uds", "key-2", principal(), SessionOptions{}); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("above cap err = %v, want ErrSessionLimit", err)
	}

	// Same conversation key re-attaches and does not count against the cap.
	again, existing, err := dc.Sessions.GetOrCreate(ctx, "uds", "key-1", principal(), SessionOptions{})
	if err != nil || !existing || again != s1 {
		t.Fatalf("re-attach: existing=%v err=%v same=%v", existing, err, again == s1)
	}

	dc.Sessions.Release(s1)
	if _, _, err := dc.Sessions.GetOrCreate(ctx, "uds", "key-3", principal(), SessionOptions{}); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

func TestHandleMessage_RunsAgentAndPersists(t *testing.T) {
	dc := testContext(t, &scriptedProvider{responses: []provider.Response{textOnly("ciao")}}, 4)
	ctx := context.Background()

	s, _, err := dc.Sessions.GetOrCreate(ctx, "uds", "k", principal(), SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}

	var streamed []provider.Message
	var gotCost float64
	_, err = s.HandleMessage(ctx, "hello agent", RunCallbacks{
		OnMessage: func(m provider.Message) { streamed = append(streamed, m) },
		OnUsage:   func(_ provider.Usage, cost float64) { gotCost += cost },
	})
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}

	// Cost = 100/1M*1 + 50/1M*2 USD.
	want := 100.0/1e6 + 50.0*2/1e6
	if gotCost < want*0.99 || gotCost > want*1.01 {
		t.Errorf("cost = %v, want ~%v", gotCost, want)
	}
	if len(streamed) == 0 {
		t.Errorf("no messages streamed")
	}

	// The user message and the model reply are both on disk.
	recs, err := conversation.ReadAll(s.ConversationPath())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) < 2 || recs[0].Message.Content != "hello agent" {
		t.Errorf("conversation log: %+v", recs)
	}

	// A second message re-seeds the persisted history.
	if _, err := s.HandleMessage(ctx, "follow-up", RunCallbacks{}); err != nil {
		t.Fatalf("second HandleMessage: %v", err)
	}
	recs, _ = conversation.ReadAll(s.ConversationPath())
	if len(recs) < 4 {
		t.Errorf("expected history to accumulate, got %d records", len(recs))
	}
}

func TestHandleMessage_SecondRunInFlightRejected(t *testing.T) {
	gate := make(chan struct{})
	dc := testContext(t, &scriptedProvider{responses: []provider.Response{textOnly("done")}, gate: gate}, 4)
	ctx := context.Background()

	s, _, err := dc.Sessions.GetOrCreate(ctx, "uds", "k", principal(), SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}

	errc := make(chan error, 1)
	go func() {
		_, err := s.HandleMessage(ctx, "first", RunCallbacks{})
		errc <- err
	}()

	// Wait until the first run is actually in flight.
	deadline := time.After(2 * time.Second)
	for {
		s.mu.Lock()
		running := s.running
		s.mu.Unlock()
		if running {
			break
		}
		select {
		case <-deadline:
			t.Fatal("first run never started")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	if _, err := s.HandleMessage(ctx, "second", RunCallbacks{}); !errors.Is(err, ErrRunInProgress) {
		t.Fatalf("err = %v, want ErrRunInProgress", err)
	}

	close(gate)
	if err := <-errc; err != nil {
		t.Fatalf("first run: %v", err)
	}
}

func TestHandleMessage_UnknownSkill(t *testing.T) {
	dc := testContext(t, &scriptedProvider{responses: []provider.Response{textOnly("x")}}, 4)
	ctx := context.Background()

	s, _, err := dc.Sessions.GetOrCreate(ctx, "uds", "k", principal(), SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.HandleMessage(ctx, "/no-such-skill do it", RunCallbacks{}); !errors.Is(err, ErrUnknownSkill) {
		t.Fatalf("err = %v, want ErrUnknownSkill", err)
	}
	// The failed dispatch must not leave the session stuck busy.
	if _, err := s.HandleMessage(ctx, "plain message", RunCallbacks{}); err != nil {
		t.Fatalf("session stuck after skill error: %v", err)
	}
}

func TestRelease_CuratesOnlySessionsWithInteraction(t *testing.T) {
	dc := testContext(t, &scriptedProvider{responses: []provider.Response{textOnly("x")}}, 4)
	ctx := context.Background()

	// No interaction → no curation goroutine → Drain returns immediately.
	idle, _, err := dc.Sessions.GetOrCreate(ctx, "uds", "idle", principal(), SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dc.Sessions.Release(idle)
	dc.Sessions.Drain(time.Second)

	// With interaction → curation runs (the scripted provider answers the
	// curator with a text-only response, which ends its loop cleanly).
	busy, _, err := dc.Sessions.GetOrCreate(ctx, "uds", "busy", principal(), SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := busy.HandleMessage(ctx, "hello", RunCallbacks{}); err != nil {
		t.Fatal(err)
	}
	dc.Sessions.Release(busy)
	dc.Sessions.Drain(5 * time.Second)

	if got := dc.Sessions.Active(); got != 0 {
		t.Errorf("active sessions = %d, want 0", got)
	}
}

func TestRelease_EphemeralSessionSkipsCuration(t *testing.T) {
	// A scripted provider whose only non-text response would be the curator's;
	// we assert the curator never calls Generate by counting calls.
	prov := &scriptedProvider{responses: []provider.Response{textOnly("x")}}
	dc := testContext(t, prov, 4)
	ctx := context.Background()

	s, _, err := dc.Sessions.GetOrCreate(ctx, "mcp", "k", principal(), SessionOptions{Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.HandleMessage(ctx, "hello", RunCallbacks{}); err != nil {
		t.Fatal(err)
	}
	callsAfterRun := prov.calls

	dc.Sessions.Release(s)
	dc.Sessions.Drain(2 * time.Second)

	// No curation goroutine ran, so the provider saw no further calls.
	if prov.calls != callsAfterRun {
		t.Errorf("ephemeral session triggered curation: provider calls went %d → %d", callsAfterRun, prov.calls)
	}
}

func TestSessionID_StableAndChannelScoped(t *testing.T) {
	if SessionID("uds", "a") != SessionID("uds", "a") {
		t.Error("SessionID must be deterministic")
	}
	if SessionID("uds", "a") == SessionID("slack", "a") {
		t.Error("SessionID must differ across channels")
	}
}
