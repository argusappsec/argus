// Package gemini implements provider.Provider on top of the Google GenAI SDK.
//
// Only the surface we actually use is wired up: text + function-calling
// inputs/outputs and token usage. Streaming, system instructions, and Vertex
// AI backends are intentionally left out of v0.1.
package gemini

import (
	"context"
	"fmt"

	"google.golang.org/genai"

	"github.com/argusappsec/argus/pkg/provider"
)

// Provider talks to Gemini via google.golang.org/genai.
type Provider struct {
	client *genai.Client
	model  string
}

// New creates a Provider authenticated with apiKey and bound to the given
// model id (e.g. "gemini-2.5-flash").
func New(ctx context.Context, apiKey, model string) (*Provider, error) {
	cli, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		return nil, fmt.Errorf("gemini client: %w", err)
	}
	return &Provider{client: cli, model: model}, nil
}

// Generate translates a provider.Request into a genai GenerateContent call.
func (p *Provider) Generate(ctx context.Context, req provider.Request) (provider.Response, error) {
	contents := toGenaiContents(req.Messages)
	config := &genai.GenerateContentConfig{}
	if req.System != "" {
		config.SystemInstruction = genai.NewContentFromText(req.System, genai.RoleUser)
	}
	if len(req.Tools) > 0 {
		config.Tools = []*genai.Tool{{FunctionDeclarations: toFunctionDeclarations(req.Tools)}}
	}

	resp, err := p.client.Models.GenerateContent(ctx, p.model, contents, config)
	if err != nil {
		return provider.Response{}, fmt.Errorf("generate: %w", err)
	}

	out := provider.Response{}
	for _, fc := range resp.FunctionCalls() {
		out.ToolCalls = append(out.ToolCalls, provider.ToolCall{
			ID:   fc.ID,
			Name: fc.Name,
			Args: fc.Args,
		})
	}
	// Only read text when there are no function-call parts — otherwise the
	// SDK logs a noisy warning because resp.Text() concatenates text parts
	// only and would lose the function-call content (which we already read
	// above via FunctionCalls()).
	if len(out.ToolCalls) == 0 {
		out.Text = resp.Text()
	}
	if u := resp.UsageMetadata; u != nil {
		out.Usage = provider.Usage{
			InputTokens:  int(u.PromptTokenCount),
			OutputTokens: int(u.CandidatesTokenCount),
		}
	}
	return out, nil
}

func toGenaiContents(msgs []provider.Message) []*genai.Content {
	out := make([]*genai.Content, 0, len(msgs))
	for _, m := range msgs {
		switch m.Role {
		case "user":
			out = append(out, genai.NewContentFromText(m.Content, genai.RoleUser))
		case "model":
			parts := []*genai.Part{}
			if m.Content != "" {
				parts = append(parts, &genai.Part{Text: m.Content})
			}
			for _, tc := range m.ToolCalls {
				parts = append(parts, &genai.Part{FunctionCall: &genai.FunctionCall{
					ID: tc.ID, Name: tc.Name, Args: tc.Args,
				}})
			}
			out = append(out, &genai.Content{Role: genai.RoleModel, Parts: parts})
		case "tool":
			parts := []*genai.Part{}
			for _, tr := range m.ToolResults {
				parts = append(parts, &genai.Part{FunctionResponse: &genai.FunctionResponse{
					ID:       tr.CallID,
					Name:     tr.Name,
					Response: map[string]any{"output": tr.Output, "is_error": tr.IsError},
				}})
			}
			out = append(out, &genai.Content{Role: genai.RoleUser, Parts: parts})
		}
	}
	return out
}

func toFunctionDeclarations(tools []provider.ToolDecl) []*genai.FunctionDeclaration {
	out := make([]*genai.FunctionDeclaration, 0, len(tools))
	for _, t := range tools {
		out = append(out, &genai.FunctionDeclaration{
			Name:                 t.Name,
			Description:          t.Description,
			ParametersJsonSchema: t.Schema,
		})
	}
	return out
}
