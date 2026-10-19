package bridge

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"warp-proxy/internal/config"
)

// OpenCode free-tier identity.
//
// The free tier keys anonymous traffic on X-Opencode-Session; a request that
// lacks it lands in the anonymous quota and can be rejected with
// FreeUsageLimitError. When session injection is on, the bridge supplies the
// same identity the official client sends. Values the client already provided
// are respected and never overwritten, except a non-opencode User-Agent.
const (
	// opencodeUA is the User-Agent the free-tier gateway expects. An empty
	// or non-opencode User-Agent (curl, a language client, ...) is
	// replaced with it.
	opencodeUA = "opencode/1.18.30 ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.14"

	// The gateway validates X-Opencode-Session beyond its format: the
	// first 12 hex characters decode to a timestamp that must be recent
	// (see newIDs). X-Opencode-Request is "msg_" followed by 24
	// alphanumeric characters.
	sessionPrefix = "ses_"
	requestPrefix = "msg_"
	requestLength = 24

	alnumChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// npmRegistryURL publishes the current opencode release; the User-Agent
	// version is discovered from it so a version bump upstream does not
	// strand the bridge on a stale fingerprint (old versions get 426).
	npmRegistryURL = "https://registry.npmjs.org/opencode-ai/latest"
	// userAgentSuffix pins the SDK and runtime parts that follow the
	// version, which the free tier does not gate on.
	userAgentSuffix = " ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.14"
)

// uaOverride carries the discovered User-Agent; empty until discovery
// succeeds.
var uaOverride atomic.Value

// identity carries the OpenCode values injected into upstream requests. A nil
// identity disables injection.
type identity struct {
	session string
	request string
	ua      string
	// force makes apply overwrite client-provided ids; set by rotate after
	// a WARP rotation when Bridge.RotateSessionOnRetry is on.
	force bool
}

// SetUserAgent overrides the injected User-Agent (used by the npm registry
// discovery). Empty resets to the built-in default.
func SetUserAgent(ua string) {
	uaOverride.Store(ua)
}

// currentUserAgent returns the discovered or default User-Agent.
func currentUserAgent() string {
	if v, ok := uaOverride.Load().(string); ok && v != "" {
		return v
	}
	return opencodeUA
}

// DiscoverUserAgent fetches the current opencode release version from the
// npm registry and installs it as the injected User-Agent. It returns the
// installed value.
func DiscoverUserAgent(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, npmRegistryURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck // read failure surfaces below
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("npm registry status %d", resp.StatusCode)
	}
	var payload struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if payload.Version == "" {
		return "", fmt.Errorf("npm registry answered without a version")
	}
	ua := "opencode/" + payload.Version + userAgentSuffix
	SetUserAgent(ua)
	return ua, nil
}

// newIdentity builds the identity for one client request when injection is
// enabled, or nil when it is off.
func newIdentity(cfg config.BridgeConfig) *identity {
	if !cfg.InjectSession {
		return nil
	}
	session, request := newIDs()
	return &identity{session: session, request: request, ua: currentUserAgent()}
}

// renderInjection applies the free-tier identity to a request: it returns the
// body with tool stubs merged in and the identity to apply to every attempt,
// or a nil identity when injection is off.
func renderInjection(cfg config.BridgeConfig, body []byte) ([]byte, *identity) {
	ids := newIdentity(cfg)
	if ids == nil {
		return body, nil
	}
	return ensureTools(body), ids
}

// rotate regenerates the ids and forces them onto the next attempt. It
// overrides even a client-provided session, so a request replayed after a
// WARP rotation carries a fresh OpenCode identity.
func (id *identity) rotate() {
	if id == nil {
		return
	}
	id.session, id.request = newIDs()
	id.force = true
}

// apply adds the headers the client did not already send, or replaces them
// when the identity was rotated. An empty or non-opencode User-Agent is
// replaced with the opencode one.
func (id *identity) apply(h http.Header) {
	if id == nil {
		return
	}
	if id.force || h.Get("X-Opencode-Session") == "" {
		h.Set("X-Opencode-Session", id.session)
	}
	if id.force || h.Get("X-Opencode-Request") == "" {
		h.Set("X-Opencode-Request", id.request)
	}
	if ua := h.Get("User-Agent"); !strings.HasPrefix(strings.ToLower(ua), "opencode/") {
		h.Set("User-Agent", id.ua)
	}
}

// newIDs returns a fresh session id and request id. The session follows
// OpenCode's canonical descending-identifier layout — "ses_" + the hex of
// the inverted 48-bit ~(unix_ms<<12 | counter) — because the upstream
// decodes the first 12 hex characters back to a timestamp and refuses
// values outside a recent window. Counter 1 puts "ffe" in the low three
// hex digits, matching the genuine client. The request id is "msg_" plus
// 24 alphanumeric characters.
func newIDs() (session, request string) {
	ms := uint64(time.Now().UnixMilli())
	payload := ^(ms<<12 | 1) & 0xFFFFFFFFFFFF
	return sessionPrefix + fmt.Sprintf("%012x", payload) + randomString(alnumChars, 14),
		requestPrefix + randomString(alnumChars, requestLength)
}

// randomString returns n random characters drawn from alphabet.
func randomString(alphabet string, n int) string {
	buf := make([]byte, n)
	// crypto/rand does not fail on supported platforms; a zero-filled
	// buffer would still yield a well-shaped id.
	_, _ = rand.Read(buf)
	for i := range buf {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(buf)
}

// stubTool is one lightweight tool definition injected into a body that does
// not already define it. The free-tier gateway requires a tools array with at
// least two entries and validates the names against real opencode tools.
type stubTool struct {
	name string
	raw  string
}

var stubTools = []stubTool{
	{
		name: "bash",
		raw:  `{"type":"function","function":{"name":"bash","description":"run","parameters":{"type":"object","properties":{"c":{"type":"string"}}}}}`,
	},
	{
		name: "read",
		raw:  `{"type":"function","function":{"name":"read","description":"read","parameters":{"type":"object","properties":{"p":{"type":"string"}}}}}`,
	},
}

// ensureTools appends the stub tools a JSON body is missing. Existing tool
// definitions and a non-JSON body are left untouched, and the bytes are
// preserved when nothing needs to be added.
func ensureTools(body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	tools := addMissingStubs(obj)
	if tools == nil {
		return body
	}
	encoded, err := json.Marshal(tools)
	if err != nil {
		return body
	}
	obj["tools"] = encoded
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

// addMissingStubs appends the stub tools the body lacks and returns the new
// tool list; nil when every stub is already present or the tools field is
// unreadable.
func addMissingStubs(obj map[string]json.RawMessage) []json.RawMessage {
	var tools []json.RawMessage
	if raw, ok := obj["tools"]; ok {
		_ = json.Unmarshal(raw, &tools)
	}
	existing := make(map[string]bool, len(tools))
	for _, tool := range tools {
		if name := toolName(tool); name != "" {
			existing[name] = true
		}
	}
	added := false
	for _, stub := range stubTools {
		if existing[stub.name] {
			continue
		}
		tools = append(tools, json.RawMessage(stub.raw))
		existing[stub.name] = true
		added = true
	}
	if !added {
		return nil
	}
	return tools
}

// toolName reads the function name from one OpenAI tool definition.
func toolName(raw json.RawMessage) string {
	var tool struct {
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if err := json.Unmarshal(raw, &tool); err != nil {
		return ""
	}
	return tool.Function.Name
}
