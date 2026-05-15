// Package provider defines the LLM provider abstraction.
// Concrete providers (Gemini, OpenAI, ...) live in subpackages and implement Provider.
package provider

import "context"

// Provider is the minimal contract every LLM backend must satisfy.
type Provider interface {
	Generate(ctx context.Context, req Request) (Response, error)
}

// Request is what we send to the LLM on each turn.
type Request struct {
	System   string
	Messages []Message
	Tools    []ToolDecl
}

// Message is one entry in the conversation history.
type Message struct {
	Role        string // "user" | "model" | "tool"
	Content     string
	ToolCalls   []ToolCall   // for role=="model"
	ToolResults []ToolResult // for role=="tool"
}

// ToolDecl is the schema we expose to the model for a tool.
type ToolDecl struct {
	Name        string
	Description string
	Schema      map[string]any // JSON-schema-ish, provider-agnostic
}

// ToolCall is a request from the model to invoke a tool.
type ToolCall struct {
	ID   string
	Name string
	Args map[string]any
}

// ToolResult is the answer we feed back after running a tool.
// Name must match the originating ToolCall.Name: Gemini (and most providers)
// require the function name in the response part to correlate the call.
type ToolResult struct {
	CallID  string
	Name    string
	Output  string
	IsError bool
}

// Response is the structured output of one model turn.
type Response struct {
	Text      string
	ToolCalls []ToolCall
	Usage     Usage
}

// Usage is the token accounting for one call.
type Usage struct {
	InputTokens  int
	OutputTokens int
}
