package uds

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// Client is the TUI-side end of the protocol. One Client = one connection =
// one Session on the daemon.
type Client struct {
	conn net.Conn
	w    *frameWriter
	r    *frameReader

	sessionID string
}

// HelloOptions are the per-Session knobs carried by the hello frame.
type HelloOptions struct {
	Model    string // override the daemon's default model (validated server-side)
	MaxTurns int    // safety-net cap per agent run
}

// ErrRejected wraps a server-side rejection with its polite reason.
type ErrRejected struct{ Reason string }

func (e *ErrRejected) Error() string { return "rejected by daemon: " + e.Reason }

// Dial connects to the daemon socket and performs the hello handshake.
func Dial(socketPath string, opts HelloOptions) (*Client, error) {
	conn, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("uds: dial %s: %w", socketPath, err)
	}
	c := &Client{conn: conn, w: newFrameWriter(conn), r: newFrameReader(conn)}

	if err := c.w.write(Frame{
		Type:     TypeHello,
		Protocol: ProtocolVersion,
		Model:    opts.Model,
		MaxTurns: opts.MaxTurns,
	}); err != nil {
		conn.Close()
		return nil, err
	}

	first, err := c.r.read()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("uds: handshake: %w", err)
	}
	switch first.Type {
	case TypeHelloOK:
		c.sessionID = first.SessionID
		return c, nil
	case TypeRejected:
		conn.Close()
		return nil, &ErrRejected{Reason: first.Reason}
	default:
		conn.Close()
		return nil, fmt.Errorf("uds: unexpected handshake frame %q", first.Type)
	}
}

// SessionID returns the Session id assigned by the daemon at hello.
func (c *Client) SessionID() string { return c.sessionID }

// SendMessage submits one user message (raw — "/<skill>" lines included;
// the daemon resolves them against the organization's catalog).
func (c *Client) SendMessage(text string) error {
	return c.w.write(Frame{Type: TypeMessage, Text: text})
}

// Cancel aborts the in-flight run without closing the Session.
func (c *Client) Cancel() error {
	return c.w.write(Frame{Type: TypeCancel})
}

// Recv blocks for the next server frame (agent_message / usage / done /
// error). Returns ErrConnClosed when the daemon goes away.
func (c *Client) Recv() (Frame, error) {
	f, err := c.r.read()
	if err != nil {
		if errors.Is(err, errClosed) {
			return Frame{}, ErrConnClosed
		}
		return Frame{}, err
	}
	return f, nil
}

// ErrConnClosed reports that the daemon closed the connection.
var ErrConnClosed = errors.New("uds: daemon closed the connection")

// Close tears the connection — and therefore the Session — down.
func (c *Client) Close() error {
	return c.conn.Close()
}
