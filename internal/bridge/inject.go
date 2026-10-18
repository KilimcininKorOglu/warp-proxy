package bridge

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"

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

	// The gateway validates X-Opencode-Session by format only: "ses_"
	// followed by exactly 26 digits (^ses_\d{26}$). X-Opencode-Request is
	// "msg_" followed by 24 alphanumeric characters.
	sessionPrefix = "ses_"
	sessionDigits = 26
	requestPrefix = "msg_"
	requestLength = 24

	digitChars = "0123456789"
	alnumChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// identity carries the OpenCode values injected into upstream requests. A nil
// identity disables injection.
type identity struct {
	session string
	request string
}

// newIdentity builds the identity for one client request when injection is
// enabled, or nil when it is off. The ids are generated once so a replayed
// attempt keeps the same session.
func newIdentity(cfg config.BridgeConfig) *identity {
	if !cfg.InjectSession {
		return nil
	}
	return &identity{
		session: sessionPrefix + randomString(digitChars, sessionDigits),
		request: requestPrefix + randomString(alnumChars, requestLength),
	}
}

// apply adds the headers the client did not already send. An empty or
// non-opencode User-Agent is replaced with the opencode one.
func (id *identity) apply(h http.Header) {
	if id == nil {
		return
	}
	if h.Get("X-Opencode-Session") == "" {
		h.Set("X-Opencode-Session", id.session)
	}
	if h.Get("X-Opencode-Request") == "" {
		h.Set("X-Opencode-Request", id.request)
	}
	if ua := h.Get("User-Agent"); !strings.HasPrefix(strings.ToLower(ua), "opencode/") {
		h.Set("User-Agent", opencodeUA)
	}
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
