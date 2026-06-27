package mcp

import "encoding/json"

// protocolVersion is the MCP revision this server speaks. We support exactly one
// revision today, so the handshake always advertises it — which is spec-correct
// both when the client asked for it and when it asked for one we don't speak
// (the MCP version-negotiation rule lets the server answer with a version it
// supports). Echo-if-supported logic arrives only with a second version.
const protocolVersion = "2025-06-18"

// serverName / serverVersion identify Argus to the MCP client in the
// initialize result's serverInfo.
const (
	serverName    = "argus"
	serverVersion = "0.1.0"
)

// JSON-RPC 2.0 error codes (a subset; the ones the MCP surface can emit).
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602

	// codeResourceNotFound is the MCP-defined code for an unknown/unreadable
	// resource URI (resources/read).
	codeResourceNotFound = -32002

	// codeForbidden is a server-defined code (JSON-RPC reserves -32000..-32099
	// for implementation errors) for an authenticated caller whose Role is not
	// permitted the operation — distinct from a malformed request (-32600).
	codeForbidden = -32003
)

// rpcRequest is an inbound JSON-RPC 2.0 message. A message with no id is a
// notification (no response is sent); ID is kept as RawMessage because the spec
// permits a string or a number.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// isNotification reports whether the message omits an id and therefore expects
// no response (JSON-RPC 2.0 §4.1).
func (r rpcRequest) isNotification() bool { return len(r.ID) == 0 }

// rpcResponse is an outbound JSON-RPC 2.0 message. Exactly one of Result / Error
// is set on a well-formed response.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// rpcError is the error object of a JSON-RPC 2.0 failure response.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// result builds a success response for the given id.
func result(id json.RawMessage, payload any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: payload}
}

// errorResponse builds a failure response for the given id. When the id could
// not be determined (a parse or invalid-request error), JSON-RPC 2.0 §5 mandates
// a literal null id, so a nil RawMessage is coerced to "null" rather than being
// dropped by omitempty.
func errorResponse(id json.RawMessage, code int, message string) rpcResponse {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}}
}

// initializeResult is the MCP handshake response. Capabilities advertises the
// coarse surface this server speaks (ADR 0011): tools (review and consult) and
// resources (SOUL, CONTEXT documents, recent reports). The low-level scanners
// are never exposed as tools.
type initializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ServerInfo      serverInfo     `json:"serverInfo"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// toolDecl is one entry in a tools/list result: the tool's name, the
// description the external AI reads to decide when to call it (the boundary is
// the description, not a runtime gate — ADR 0011), and its JSON-Schema inputs.
type toolDecl struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// toolsListResult is the tools/list response.
type toolsListResult struct {
	Tools []toolDecl `json:"tools"`
}

// toolCallResult is the tools/call response (MCP CallToolResult). A tool-layer
// refusal or failure rides a successful JSON-RPC response with IsError set, so
// the calling AI relays it rather than treating it as a transport error.
// StructuredContent carries the machine-readable payload (e.g. the findings)
// alongside the human-readable Content blocks.
type toolCallResult struct {
	Content           []contentBlock `json:"content"`
	StructuredContent any            `json:"structuredContent,omitempty"`
	IsError           bool           `json:"isError,omitempty"`
}

// contentBlock is one piece of a tool result. Only text blocks are produced
// today.
type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// textContent wraps a string as a single text content block.
func textContent(text string) []contentBlock {
	return []contentBlock{{Type: "text", Text: text}}
}
