package openaicompat

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/argusappsec/argus/pkg/provider"
)

// chatRequest is the chat-completions request body.
//
// Only the fields Argus uses are present. max_tokens is a pointer so a zero
// ceiling is omitted rather than sent as a cap of nothing; max_tokens rather
// than max_completion_tokens because every compatible server accepts the
// former, while the latter is understood only by recent OpenAI.
type chatRequest struct {
	Model     string        `json:"model"`
	Messages  []chatMessage `json:"messages"`
	Tools     []chatTool    `json:"tools,omitempty"`
	MaxTokens *int          `json:"max_tokens,omitempty"`
}

// chatMessage is one conversation entry on the wire.
type chatMessage struct {
	Role       string         `json:"role"`
	Content    string         `json:"content"`
	ToolCalls  []chatToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}

// chatToolCall is a function call outbound only, echoing the model's own calls
// back as history. Inbound calls are decoded leniently — see inboundToolCall.
type chatToolCall struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Function chatCallFunction `json:"function"`
}

type chatCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// chatTool is one tool declaration offered to the model.
type chatTool struct {
	Type     string           `json:"type"`
	Function chatToolFunction `json:"function"`
}

type chatToolFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}

// toWireTools maps Argus's tool declarations onto the protocol. The declared
// JSON schema is passed through verbatim: Argus makes no attempt to normalize
// it, so a model that mangles nested objects is the model's problem, not a
// difference introduced here.
func toWireTools(tools []provider.ToolDecl) []chatTool {
	if len(tools) == 0 {
		return nil
	}
	out := make([]chatTool, 0, len(tools))
	for _, t := range tools {
		out = append(out, chatTool{
			Type: "function",
			Function: chatToolFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Schema,
			},
		})
	}
	return out
}

// toWireMessages maps Argus's provider-agnostic conversation onto the protocol.
// The system instruction, when present, leads as a system message.
//
// The role mapping is: user → user, model → assistant (carrying tool_calls),
// tool → one tool message per result. The last one matters: Argus batches every
// result of a turn into a single provider.Message, while this protocol wants one
// message per result, correlated to its call by tool_call_id — where Gemini
// correlates by function name instead.
func toWireMessages(system string, msgs []provider.Message) []chatMessage {
	out := make([]chatMessage, 0, len(msgs)+1)
	if system != "" {
		out = append(out, chatMessage{Role: "system", Content: system})
	}
	for _, m := range msgs {
		switch m.Role {
		case "user":
			out = append(out, chatMessage{Role: "user", Content: m.Content})
		case "model":
			msg := chatMessage{Role: "assistant", Content: m.Content}
			for _, tc := range m.ToolCalls {
				msg.ToolCalls = append(msg.ToolCalls, chatToolCall{
					ID:   tc.ID,
					Type: "function",
					Function: chatCallFunction{
						Name:      tc.Name,
						Arguments: encodeToolArgs(tc.Args),
					},
				})
			}
			out = append(out, msg)
		case "tool":
			for _, tr := range m.ToolResults {
				out = append(out, chatMessage{
					Role:       "tool",
					ToolCallID: tr.CallID,
					Content:    toolResultContent(tr),
				})
			}
		}
	}
	return out
}

// encodeToolArgs renders a tool call's arguments as the JSON string the protocol
// expects. Arguments that cannot be encoded degrade to an empty object rather
// than aborting the turn: the history entry is what is being rebuilt here, and
// the model has already moved past it.
func encodeToolArgs(args map[string]any) string {
	if len(args) == 0 {
		return "{}"
	}
	encoded, err := json.Marshal(args)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

// toolResultContent renders a tool result as the plain string a tool message
// carries. The protocol has no error flag on a tool message, so a failed tool
// is marked in the content itself — dropping the distinction would leave the
// model unable to tell a failure from an unusual success.
func toolResultContent(tr provider.ToolResult) string {
	if tr.IsError {
		return "Error: " + tr.Output
	}
	return tr.Output
}

// chatResponse is the chat-completions response body.
//
// Everything here is optional on purpose: a compatible server may omit usage,
// invent a finish reason, or return fields Argus has never heard of. None of
// that is an error, because none of it is load-bearing.
type chatResponse struct {
	Choices []struct {
		Message struct {
			Content   flexibleText      `json:"content"`
			ToolCalls []inboundToolCall `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
	// Usage is a pointer so an absent block is distinguishable from a zeroed
	// one — though both mean the same thing here, since token counts are a
	// readout and not a control.
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// inboundToolCall is a tool call as a server reports it. It is decoded
// separately from the outbound form because what comes back is far less
// predictable than what Argus sends: arguments arrive as a JSON-encoded string
// per the protocol, but some runtimes send the object directly.
type inboundToolCall struct {
	ID       string `json:"id"`
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

// flexibleText is a message content field. The protocol says string, but null
// and an array of typed content parts both occur in the wild, so all three are
// accepted. Anything else decodes to no text rather than failing the turn: an
// unreadable content field is a degraded answer, not a reason to abandon a
// Review mid-flight.
type flexibleText string

func (f *flexibleText) UnmarshalJSON(raw []byte) error {
	*f = ""

	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		*f = flexibleText(asString)
		return nil
	}

	var parts []struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		var joined strings.Builder
		for _, p := range parts {
			joined.WriteString(p.Text)
		}
		*f = flexibleText(joined.String())
	}
	return nil
}

// toResponse turns a decoded server reply into a provider.Response.
func (r chatResponse) toResponse() (provider.Response, error) {
	if len(r.Choices) == 0 {
		return provider.Response{}, fmt.Errorf("openaicompat: response contained no choices")
	}
	choice := r.Choices[0]

	// Text and tool calls are both kept when both are present: some models
	// narrate their intent in the same message they call a tool from, and
	// discarding either half loses information the agent loop can use.
	out := provider.Response{Text: string(choice.Message.Content)}
	for _, tc := range choice.Message.ToolCalls {
		out.ToolCalls = append(out.ToolCalls, provider.ToolCall{
			ID:   tc.ID,
			Name: tc.Function.Name,
			Args: decodeToolArgs(tc.Function.Arguments),
		})
	}
	normalizeCallIDs(out.ToolCalls)

	if r.Usage != nil {
		out.Usage = provider.Usage{
			InputTokens:  r.Usage.PromptTokens,
			OutputTokens: r.Usage.CompletionTokens,
		}
	}
	return out, nil
}

// normalizeCallIDs gives every tool call a non-empty id that no other call in
// the same turn shares.
//
// Tool-call id correlation is a hard requirement of the agent loop, and it is
// the one nobody documents: results are matched to calls by id, so a server that
// emits empty or repeated ids breaks every turn containing more than one call.
// Rather than fail, Argus fills the gap — keeping whatever the server did supply
// and synthesizing only what it must, deterministically from position, so the
// same response always yields the same ids. The synthesized id is also what
// Argus echoes back in the assistant message it rebuilds, so the pairing the
// server sees stays internally consistent.
func normalizeCallIDs(calls []provider.ToolCall) {
	seen := make(map[string]bool, len(calls))
	for i := range calls {
		id := calls[i].ID
		if id == "" {
			id = fmt.Sprintf("call_%d", i)
		}
		for seen[id] {
			id = fmt.Sprintf("%s_%d", id, i)
		}
		calls[i].ID = id
		seen[id] = true
	}
}

// decodeToolArgs reads a tool call's arguments. The protocol specifies a
// JSON-encoded string; an object sent directly is accepted too, because several
// local runtimes emit one. Arguments that parse as neither yield no arguments
// rather than an error: the tool call then fails and the agent loop can retry,
// which beats aborting the turn.
func decodeToolArgs(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}

	var encoded string
	if err := json.Unmarshal(raw, &encoded); err == nil {
		if strings.TrimSpace(encoded) == "" {
			return nil
		}
		raw = json.RawMessage(encoded)
	}

	var args map[string]any
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil
	}
	return args
}
