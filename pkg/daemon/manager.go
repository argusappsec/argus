package daemon

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/conversation"
	"github.com/argusappsec/argus/pkg/memory"
	"github.com/argusappsec/argus/pkg/session"
)

// ErrSessionLimit is returned by GetOrCreate above max_concurrent_sessions.
// Channels translate it into their own polite "try again later" — Sessions
// are never queued (ADR 0004).
var ErrSessionLimit = errors.New("daemon: too many concurrent sessions, try again later")

// SessionOptions are the per-Session knobs a channel may carry from its
// client (the UDS hello frame's model / max_turns).
type SessionOptions struct {
	// Model overrides the daemon's default model for this Session. It must
	// map to a provider configured in the daemon's argus.yaml.
	Model string

	// MaxTurns caps each agent run in this Session. Zero = default (50).
	MaxTurns int

	// Ephemeral marks a one-shot, stateless Session whose conversation is not
	// worth distilling into MEMORY.md — e.g. an MCP Snapshot review, whose only
	// "message" is a machine-written seed prompt over throwaway caller code. Such
	// a Session skips the end-of-session memory curation on Release, so the org's
	// memory is shaped only by real conversations and reviews, not by transient
	// one-shot calls (and the daemon avoids a wasted curation agent loop per call).
	Ephemeral bool
}

// SessionManager allocates Sessions, keys them by hash(channel,
// conversation-key), and enforces the concurrent-session cap. It is the
// single point where session identity is decided.
type SessionManager struct {
	dc  *Context
	cap int

	mu     sync.Mutex
	active map[string]*Session

	// curations tracks in-flight memory curations so graceful shutdown can
	// wait for them; curationMu serializes MEMORY.md writers (ADR 0004).
	curations  sync.WaitGroup
	curationMu sync.Mutex
}

// NewSessionManager creates a manager bound to dc with the given cap.
func NewSessionManager(dc *Context, cap int) *SessionManager {
	return &SessionManager{dc: dc, cap: cap, active: map[string]*Session{}}
}

// SessionID derives the stable Session identity from a channel name and its
// conversation key (e.g. a Slack thread ts, a fresh random key for a UDS
// connection).
func SessionID(channel, conversationKey string) string {
	sum := sha256.Sum256([]byte(channel + "\x00" + conversationKey))
	return hex.EncodeToString(sum[:])[:12]
}

// NewConversationKey mints a fresh random conversation key for a channel whose
// shape is "one connection/call = one Session" (the UDS connection, an MCP
// one-shot review). On the practically-impossible rand failure it falls back to
// a timestamp, which is still effectively unique per call.
func NewConversationKey() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// GetOrCreate returns the Session for (channel, conversationKey), creating
// it if absent. The boolean reports whether the Session already existed
// (re-attach, e.g. a later reply in a Slack thread). Above the cap, new
// Sessions are rejected with ErrSessionLimit.
func (m *SessionManager) GetOrCreate(ctx context.Context, channel, conversationKey string, principal auth.Principal, opts SessionOptions) (*Session, bool, error) {
	id := SessionID(channel, conversationKey)

	m.mu.Lock()
	if s, ok := m.active[id]; ok {
		m.mu.Unlock()
		return s, true, nil
	}
	if len(m.active) >= m.cap {
		m.mu.Unlock()
		return nil, false, ErrSessionLimit
	}
	// Reserve the slot before the (slow) construction so two concurrent
	// connects can't both pass the cap check. A nil placeholder is enough:
	// the id is random per connection on the only channel that exists today.
	m.active[id] = nil
	m.mu.Unlock()

	s, err := m.build(ctx, id, channel, principal, opts)

	m.mu.Lock()
	if err != nil {
		delete(m.active, id)
		m.mu.Unlock()
		return nil, false, err
	}
	m.active[id] = s
	m.mu.Unlock()
	return s, false, nil
}

// build constructs the per-Session state: soul/memory snapshots, provider
// (honoring the model override), tool state, conversation log, attributed
// audit logger and tool registry.
func (m *SessionManager) build(ctx context.Context, id, channel string, principal auth.Principal, opts SessionOptions) (*Session, error) {
	dc := m.dc

	modelID := opts.Model
	if modelID == "" {
		modelID = dc.DefaultModel
	}
	prov, err := dc.NewProvider(ctx, modelID)
	if err != nil {
		return nil, fmt.Errorf("daemon: provider for model %q: %w", modelID, err)
	}

	soulSnap, err := dc.LoadSoul()
	if err != nil {
		return nil, fmt.Errorf("daemon: soul: %w", err)
	}
	memSnap, err := dc.LoadMemory()
	if err != nil {
		return nil, fmt.Errorf("daemon: memory: %w", err)
	}

	convoPath := filepath.Join(dc.Home, "conversations", id+".jsonl")
	convo, err := conversation.NewWriter(convoPath, id)
	if err != nil {
		return nil, fmt.Errorf("daemon: conversation: %w", err)
	}

	toolState := session.New()

	s := &Session{
		id:        id,
		channel:   channel,
		principal: principal,
		modelID:   modelID,
		maxTurns:  opts.MaxTurns,
		ephemeral: opts.Ephemeral,
		dc:        dc,
		toolState: toolState,
		convo:     convo,
		convoPath: convoPath,
		provider:  prov,
		registry:  buildRegistry(toolState, dc),
		soul:      soulSnap,
		memory:    memSnap,
		audit: dc.Audit.With(map[string]any{
			"session_id": id,
			"channel":    channel,
			"principal":  principal.ID,
		}),
	}

	_ = s.audit.Log(auditEvent("session_created", map[string]any{
		"model":    modelID,
		"identity": principal.Identity,
		"implicit": principal.Implicit,
	}))
	return s, nil
}

// Release tears a Session down: it leaves the active set immediately, its
// conversation log is closed, and — when the Session saw at least one user
// message — the memory curator runs asynchronously. Curations are serialized
// (one MEMORY.md writer at a time) and tracked for Drain.
func (m *SessionManager) Release(s *Session) {
	if s == nil {
		return
	}
	m.mu.Lock()
	delete(m.active, s.id)
	m.mu.Unlock()

	_ = s.convo.Close()
	_ = s.audit.Log(auditEvent("session_released", map[string]any{
		"user_messages": s.userMessages(),
	}))

	// An ephemeral one-shot Session (e.g. an MCP Snapshot review) carries no
	// conversation worth distilling; skip curation rather than burn an agent loop
	// on a single machine-written seed.
	if s.userMessages() == 0 || s.ephemeral {
		return
	}

	m.curations.Add(1)
	go func() {
		defer m.curations.Done()
		m.curationMu.Lock()
		defer m.curationMu.Unlock()

		err := memory.Curate(context.Background(), memory.Options{
			ConversationPath: s.convoPath,
			MemoryPath:       filepath.Join(m.dc.Home, "MEMORY.md"),
			Provider:         s.provider,
		})
		if err != nil {
			_ = s.audit.Log(auditEvent("memory_curation_failed", map[string]any{"error": err.Error()}))
			return
		}
		_ = s.audit.Log(auditEvent("memory_curated", nil))
	}()
}

// AppendMemory appends one advisory line to MEMORY.md under the same lock that
// serializes the memory curator, so a channel-driven note — e.g. a false
// positive a teammate accepted on a PR (ADR 0008 / slice 6) — cannot be lost to
// a concurrent curator rewrite. The curator owns MEMORY.md's full-file rewrites;
// this is the one sanctioned out-of-band writer, and it shares the curator's
// lock rather than racing it. A trailing newline is ensured.
func (m *SessionManager) AppendMemory(line string) error {
	m.curationMu.Lock()
	defer m.curationMu.Unlock()

	if !strings.HasSuffix(line, "\n") {
		line += "\n"
	}
	path := filepath.Join(m.dc.Home, "MEMORY.md")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("daemon: open MEMORY: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("daemon: append MEMORY: %w", err)
	}
	return nil
}

// Drain blocks until pending curations finish or the timeout elapses.
// Used by graceful shutdown so the process doesn't die mid-MEMORY.md write.
func (m *SessionManager) Drain(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		m.curations.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// Active returns the number of live Sessions.
func (m *SessionManager) Active() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.active)
}
