// Package uds implements the local Unix-domain-socket Channel: the transport
// behind `argus chat` / `argus review` (both against a long-running argusd
// and against the in-process fallback daemon).
//
// Wire format: JSON-lines — one JSON object per \n-terminated line, with a
// `type` discriminator. Internal to this channel only (Slack/MCP/webhook
// have their own transports), human-debuggable with `nc -U`.
//
// Authentication: possession of the socket (ADR 0007). The server derives
// the identity from kernel peer credentials, never from a frame.
package uds

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"sync"

	"github.com/redcarbon-dev/argus/pkg/provider"
)

// ProtocolVersion is bumped on incompatible frame changes. The server
// rejects hellos with a different major version with a polite "update your
// client".
const ProtocolVersion = 1

// Frame types, client → server.
const (
	TypeHello   = "hello"
	TypeMessage = "message"
	TypeReview  = "review"
	TypeCancel  = "cancel"
)

// Frame types, server → client.
const (
	TypeHelloOK      = "hello_ok"
	TypeRejected     = "rejected"
	TypeAgentMessage = "agent_message"
	TypeUsage        = "usage"
	TypeDone         = "done"
	TypeError        = "error"
)

// Frame is the single wire envelope. Fields are populated according to Type;
// the flat shape keeps encode/decode trivial for an internal protocol.
type Frame struct {
	Type string `json:"type"`

	// hello (client → server)
	Protocol int    `json:"protocol,omitempty"`
	Session  string `json:"session,omitempty"` // reserved for resume; rejected when set
	Model    string `json:"model,omitempty"`
	MaxTurns int    `json:"max_turns,omitempty"`

	// message
	Text string `json:"text,omitempty"`

	// review — the structured target; the daemon clones deterministically
	GitHubURL string `json:"github_url,omitempty"`
	Ref       string `json:"ref,omitempty"`

	// hello_ok
	SessionID string `json:"session_id,omitempty"`

	// rejected / error
	Reason string `json:"reason,omitempty"`

	// agent_message
	Message *provider.Message `json:"message,omitempty"`

	// usage — cost is computed by the daemon; clients never see prices
	InputTokens  int     `json:"input_tokens,omitempty"`
	OutputTokens int     `json:"output_tokens,omitempty"`
	CostUSD      float64 `json:"cost_usd,omitempty"`

	// done
	ReportPath string `json:"report_path,omitempty"`
	Findings   int    `json:"findings,omitempty"`
}

// frameWriter serializes frames onto a connection. Safe for concurrent use:
// the streaming callbacks (agent_message, usage) write from the run
// goroutine while the read loop may write errors.
type frameWriter struct {
	mu sync.Mutex
	w  *bufio.Writer
}

func newFrameWriter(conn net.Conn) *frameWriter {
	return &frameWriter{w: bufio.NewWriter(conn)}
}

func (fw *frameWriter) write(f Frame) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	b, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("uds: marshal frame: %w", err)
	}
	if _, err := fw.w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("uds: write frame: %w", err)
	}
	return fw.w.Flush()
}

// frameReader decodes one frame per line.
type frameReader struct {
	sc *bufio.Scanner
}

func newFrameReader(conn net.Conn) *frameReader {
	sc := bufio.NewScanner(conn)
	// Frames carry full agent messages (tool outputs included); allow the
	// same generous line size as the conversation reader.
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	return &frameReader{sc: sc}
}

func (fr *frameReader) read() (Frame, error) {
	if !fr.sc.Scan() {
		if err := fr.sc.Err(); err != nil {
			return Frame{}, err
		}
		return Frame{}, errClosed
	}
	var f Frame
	if err := json.Unmarshal(fr.sc.Bytes(), &f); err != nil {
		return Frame{}, fmt.Errorf("uds: malformed frame: %w", err)
	}
	return f, nil
}

var errClosed = fmt.Errorf("uds: connection closed")
