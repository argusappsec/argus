package mcp

import (
	"sync"

	"github.com/redcarbon-dev/argus/pkg/daemon"
	"github.com/redcarbon-dev/argus/pkg/snapshot"
)

// sessionHeader is the MCP Streamable HTTP session id: the server mints it on
// initialize and returns it; the client echoes it on every later request so the
// server can re-attach the connection's state (here, the Snapshot workspace).
const sessionHeader = "Mcp-Session-Id"

// maxSessions caps the live MCP sessions a daemon will hold. A session's
// scratch workspace is freed on DELETE, but not every client (or a crashed one)
// sends it, so without a cap orphaned sessions and their temp checkouts could
// grow without bound. Past the cap, initialize hands back no session id and the
// client falls back to sessionless one-shot reviews (no accumulation) rather
// than the server leaking — a backstop, set well above any real fan-out.
const maxSessions = 256

// mcpSession is the per-connection state of one MCP session (CONTEXT.md: an MCP
// connection is one Session for its duration). It holds the Snapshot workspace
// so follow-up review calls accumulate onto it, and a stable daemon conversation
// key so the connection's runs share a daemon session id.
type mcpSession struct {
	convoKey string // daemon conversation key, stable for the connection

	mu sync.Mutex          // serializes review calls on this session
	ws *snapshot.Workspace // the Snapshot workspace, created on the first review
}

// openSession mints a new MCP session and registers it, returning its id. The
// workspace is created lazily on the first review so a session that only
// consults or lists never allocates scratch disk. The id doubles as the daemon
// conversation key — it is already an opaque random key, stable for the
// connection — so the session's runs share one daemon session id.
func (s *Server) openSession() string {
	id := daemon.NewConversationKey()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) >= maxSessions {
		return "" // at capacity: the client degrades to sessionless one-shot reviews
	}
	s.sessions[id] = &mcpSession{convoKey: id}
	return id
}

// lookupSession returns the registered session for id, or nil for an empty or
// unknown id (a sessionless one-shot client, or a stale session).
func (s *Server) lookupSession(id string) *mcpSession {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[id]
}

// closeSession removes a session and cleans up its scratch workspace, so
// caller-supplied code does not accumulate on the daemon host. Unknown ids are a
// no-op. Returns whether a session was actually removed.
func (s *Server) closeSession(id string) bool {
	if id == "" {
		return false
	}
	s.mu.Lock()
	sess, ok := s.sessions[id]
	delete(s.sessions, id)
	s.mu.Unlock()
	if !ok {
		return false
	}
	sess.mu.Lock()
	if sess.ws != nil {
		_ = sess.ws.Close()
		sess.ws = nil
	}
	sess.mu.Unlock()
	return true
}

// workspaceFor resolves the Snapshot workspace a review call should use. With a
// session it returns the session's workspace (created on first use), which the
// caller must NOT close — the session owns it. Without a session it returns a
// fresh one-shot workspace the caller closes after the call (oneShot=true).
// The session's mutex is assumed held by the caller for the session path.
func (s *Server) workspaceFor(sess *mcpSession) (ws *snapshot.Workspace, oneShot bool, err error) {
	if sess == nil {
		ws, err = snapshot.New()
		return ws, true, err
	}
	if sess.ws == nil {
		sess.ws, err = snapshot.New()
		if err != nil {
			return nil, false, err
		}
	}
	return sess.ws, false, nil
}
