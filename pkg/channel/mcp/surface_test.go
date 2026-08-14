package mcp

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/argusappsec/argus/pkg/auth"
	"github.com/argusappsec/argus/pkg/deployment"
	"github.com/argusappsec/argus/pkg/provider"
)

// The MCP surface has two extents, one per Deployment shape (ADR 0023). These
// tests drive the real protocol in both and assert on what the client receives:
// what tools/list holds, what naming an absent capability returns, what the
// handshake advertises, and that the knowledge Resources are untouched by the
// shape.

// toolboxServer builds a Provider-less MCP channel: the Toolbox shape, which is
// what a daemon started with no `providers:` entry serves.
func toolboxServer(t *testing.T, role auth.Role) (*Server, string) {
	t.Helper()
	return shapedServer(t, deployment.Toolbox, nil, role)
}

// listedTools returns the tool names a client sees in tools/list.
func listedTools(t *testing.T, s *Server) []string {
	t.Helper()
	rec := post(t, s, testToken, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if rec.Code != 200 {
		t.Fatalf("tools/list code = %d, want 200", rec.Code)
	}
	var resp struct {
		Result toolsListResult `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse tools/list: %v\nbody: %s", err, rec.Body.String())
	}
	if resp.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", resp.Error)
	}
	names := make([]string, 0, len(resp.Result.Tools))
	for _, tl := range resp.Result.Tools {
		names = append(names, tl.Name)
	}
	return names
}

// handshakeCapabilities returns the capability set the initialize response
// advertises.
func handshakeCapabilities(t *testing.T, s *Server) map[string]any {
	t.Helper()
	rec := post(t, s, testToken, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if rec.Code != 200 {
		t.Fatalf("initialize code = %d, want 200", rec.Code)
	}
	var resp struct {
		Result initializeResult `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse initialize: %v\nbody: %s", err, rec.Body.String())
	}
	return resp.Result.Capabilities
}

// callTool posts a tools/call for name with empty arguments and returns the raw
// response body.
func callTool(t *testing.T, s *Server, name string) []byte {
	t.Helper()
	return callToolRaw(t, s, name, `{}`)
}

// reasoningCapabilityNames is what a client may name that only exists where
// Argus reasons: the two MCP capabilities and the registry tools that drive its
// review loop.
var reasoningCapabilityNames = []string{toolReview, toolConsult, toolStartReviewLocal, toolStartReviewGitHub}

func TestToolsList_ToolboxServesNoReasoningCapability(t *testing.T) {
	s, _ := toolboxServer(t, auth.RoleAnalyst)
	names := listedTools(t, s)
	for _, name := range reasoningCapabilityNames {
		if slices.Contains(names, name) {
			t.Errorf("a Toolbox must not advertise %q — it has no agent loop to run it; got %v", name, names)
		}
	}
}

func TestToolsList_ColleagueAdvertisesReviewAndConsult(t *testing.T) {
	// A Colleague is the Toolbox plus reasoning: the two coarse capabilities lead
	// the listing, and the deterministic surface follows (ADR 0023).
	s, _ := reviewServer(t, &scriptedProvider{responses: textAnswer("ok")}, auth.RoleAnalyst)
	names := listedTools(t, s)
	if !slices.Equal(names, append([]string{toolReview, toolConsult}, knowledgeTools...)) {
		t.Errorf("a Colleague's tool listing = %v, want review and consult above the deterministic surface", names)
	}
}

func TestToolCall_ToolboxAnswersAReasoningCapabilityWithTheReason(t *testing.T) {
	for _, name := range reasoningCapabilityNames {
		t.Run(name, func(t *testing.T) {
			s, auditPath := toolboxServer(t, auth.RoleAnalyst)

			// A tool error, not a transport error: the calling AI relays the
			// explanation to the developer instead of reporting a broken server.
			// callResult fails the test on a JSON-RPC-level error.
			res := callResult(t, callTool(t, s, name))
			if !res.IsError {
				t.Error("naming an absent capability must be an isError tool result")
			}
			if len(res.Content) == 0 {
				t.Fatal("the refusal must carry a text block the calling AI can relay")
			}
			text := strings.ToLower(res.Content[0].Text)
			if !strings.Contains(text, name) {
				t.Errorf("the refusal must name the tool the client asked for: %q", res.Content[0].Text)
			}
			if !strings.Contains(text, "toolbox") || !strings.Contains(text, "provider") {
				t.Errorf("the refusal must name the reason (no Provider, so no reasoning): %q", res.Content[0].Text)
			}

			// The operator can see why a capability was not served.
			if e := findEvent(t, auditPath, "mcp_tool_withheld"); e == nil {
				t.Error("expected an mcp_tool_withheld audit event")
			} else if e.Data["tool"] != name {
				t.Errorf("audit tool = %v, want %q", e.Data["tool"], name)
			}
		})
	}
}

func TestToolCall_ToolboxStillReportsAnUnknownToolAsUnknown(t *testing.T) {
	// The shape explains the capabilities it withholds; it does not become the
	// answer to every name a client invents.
	s, _ := toolboxServer(t, auth.RoleAnalyst)
	var resp rpcResponse
	if err := json.Unmarshal(callTool(t, s, "definitely_not_a_tool"), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error == nil || resp.Error.Code != codeMethodNotFound {
		t.Fatalf("error = %+v, want method-not-found for a name Argus has never had", resp.Error)
	}
}

func TestInitialize_CapabilitiesFollowTheShape(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T) *Server
	}{
		{"toolbox", func(t *testing.T) *Server {
			s, _ := toolboxServer(t, auth.RoleAnalyst)
			return s
		}},
		{"colleague", func(t *testing.T) *Server {
			s, _ := reviewServer(t, &scriptedProvider{responses: textAnswer("ok")}, auth.RoleAnalyst)
			return s
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.build(t)
			caps := handshakeCapabilities(t, s)

			// The organization's knowledge is served whatever the shape.
			if _, ok := caps["resources"]; !ok {
				t.Errorf("initialize must advertise resources in a %s, got %+v", tc.name, caps)
			}
			// Tools are advertised exactly when this shape serves some: the
			// handshake promises what the next request will actually deliver.
			_, advertised := caps["tools"]
			served := len(listedTools(t, s)) > 0
			if advertised != served {
				t.Errorf("%s advertises tools = %v but serves %d of them", tc.name, advertised, len(listedTools(t, s)))
			}
		})
	}
}

func TestSurface_FollowsTheShapeAtRequestTime(t *testing.T) {
	// A daemon that starts without a Provider and has one configured later must
	// serve the larger surface to the next client that connects — no rebuild.
	prov := &scriptedProvider{responses: textAnswer("Our auth uses short-lived JWTs.")}
	s, _ := shapedServer(t, deployment.Toolbox, prov, auth.RoleAnalyst)

	if names := listedTools(t, s); slices.Contains(names, toolConsult) {
		t.Fatalf("precondition: a Toolbox must not advertise consult, got %v", names)
	}

	// The operator configures a Provider; the same Server, never rebuilt.
	s.dc.Shape = deployment.Colleague

	if names := listedTools(t, s); !slices.Contains(names, toolConsult) {
		t.Errorf("after a Provider is configured the surface must include consult, got %v", names)
	}
	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"consult","arguments":{"question":"what are our auth conventions?"}}}`
	res := callResult(t, post(t, s, testToken, body).Body.Bytes())
	if res.IsError {
		t.Fatalf("consult must work once the shape is a Colleague: %+v", res)
	}
	if got := structuredConsult(t, res).Answer; !strings.Contains(got, "JWT") {
		t.Errorf("answer = %q, want the provider's reply", got)
	}
}

func TestResources_BehaveTheSameInBothShapes(t *testing.T) {
	// The organization's knowledge is deterministic: nothing about it needs a
	// Provider, so a Toolbox serves it exactly as a Colleague does.
	const listBody = `{"jsonrpc":"2.0","id":2,"method":"resources/list"}`
	readBody := `{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"` + contextURIPrefix + `architecture"}}`

	var listings, reads []string
	for _, shape := range []deployment.Shape{deployment.Toolbox, deployment.Colleague} {
		var prov provider.Provider
		if shape == deployment.Colleague {
			prov = &scriptedProvider{responses: textAnswer("ok")}
		}
		s, _ := shapedServer(t, shape, prov, auth.RoleAnalyst)
		seedOrgKnowledge(t, s)

		res := listResult(t, post(t, s, testToken, listBody).Body.Bytes())
		uris := make([]string, 0, len(res.Resources))
		for _, r := range res.Resources {
			uris = append(uris, r.URI)
		}
		listings = append(listings, strings.Join(uris, ","))

		var read struct {
			Result json.RawMessage `json:"result"`
			Error  *rpcError       `json:"error"`
		}
		if err := json.Unmarshal(post(t, s, testToken, readBody).Body.Bytes(), &read); err != nil {
			t.Fatalf("parse resources/read: %v", err)
		}
		if read.Error != nil {
			t.Fatalf("resources/read in a %s: %+v", shape, read.Error)
		}
		reads = append(reads, string(read.Result))
	}

	if listings[0] != listings[1] {
		t.Errorf("resources/list differs by shape:\n toolbox   = %s\n colleague = %s", listings[0], listings[1])
	}
	if reads[0] != reads[1] {
		t.Errorf("resources/read differs by shape:\n toolbox   = %s\n colleague = %s", reads[0], reads[1])
	}
}
