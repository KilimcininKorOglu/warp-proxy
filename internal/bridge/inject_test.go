package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"testing"

	"warp-proxy/internal/config"
)

var (
	sessionIDPattern = regexp.MustCompile(`^ses_\d{26}$`)
	requestIDPattern = regexp.MustCompile(`^msg_[0-9A-Za-z]{24}$`)
)

func TestRandomIDShape(t *testing.T) {
	if id := sessionPrefix + randomString(digitChars, sessionDigits); !sessionIDPattern.MatchString(id) {
		t.Errorf("session id %q does not match %s", id, sessionIDPattern)
	}
	for range 50 {
		if id := sessionPrefix + randomString(digitChars, sessionDigits); !sessionIDPattern.MatchString(id) {
			t.Errorf("session id %q does not match %s", id, sessionIDPattern)
		}
		if id := requestPrefix + randomString(alnumChars, requestLength); !requestIDPattern.MatchString(id) {
			t.Errorf("request id %q does not match %s", id, requestIDPattern)
		}
	}
}

func TestIdentityDisabledIsNil(t *testing.T) {
	id := newIdentity(config.BridgeConfig{InjectSession: false})
	if id != nil {
		t.Fatalf("newIdentity(off) = %+v, want nil", id)
	}
	h := http.Header{}
	h.Set("User-Agent", "curl/8.5.0")
	id.apply(h) // must not panic and must not change anything
	if got := h.Get("User-Agent"); got != "curl/8.5.0" {
		t.Errorf("UA = %q, want unchanged", got)
	}
	if h.Get("X-Opencode-Session") != "" {
		t.Error("session header injected while disabled")
	}
}

func TestIdentityApplyRespectsClientValues(t *testing.T) {
	id := newIdentity(config.BridgeConfig{InjectSession: true})

	t.Run("fills missing values and replaces foreign UA", func(t *testing.T) {
		h := http.Header{}
		h.Set("User-Agent", "curl/8.5.0")
		id.apply(h)
		if !sessionIDPattern.MatchString(h.Get("X-Opencode-Session")) {
			t.Errorf("session = %q", h.Get("X-Opencode-Session"))
		}
		if !requestIDPattern.MatchString(h.Get("X-Opencode-Request")) {
			t.Errorf("request = %q", h.Get("X-Opencode-Request"))
		}
		if got := h.Get("User-Agent"); got != opencodeUA {
			t.Errorf("UA = %q, want %q", got, opencodeUA)
		}
	})

	t.Run("keeps client-provided session and opencode UA", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-Opencode-Session", "ses_0123456789012345678901234")
		h.Set("X-Opencode-Request", "msg_Abc123Abc123Abc123Abc123")
		h.Set("User-Agent", "opencode/9.9.9 custom")
		id.apply(h)
		if got := h.Get("X-Opencode-Session"); got != "ses_0123456789012345678901234" {
			t.Errorf("session overwritten: %q", got)
		}
		if got := h.Get("X-Opencode-Request"); got != "msg_Abc123Abc123Abc123Abc123" {
			t.Errorf("request overwritten: %q", got)
		}
		if got := h.Get("User-Agent"); got != "opencode/9.9.9 custom" {
			t.Errorf("opencode UA replaced: %q", got)
		}
	})

	t.Run("keeps a client session but replaces a non-opencode UA", func(t *testing.T) {
		h := http.Header{}
		h.Set("X-Opencode-Session", "ses_99999999999999999999999999")
		h.Set("User-Agent", "python-requests/2.31")
		id.apply(h)
		if got := h.Get("X-Opencode-Session"); got != "ses_99999999999999999999999999" {
			t.Errorf("session overwritten: %q", got)
		}
		if got := h.Get("User-Agent"); got != opencodeUA {
			t.Errorf("UA = %q, want %q", got, opencodeUA)
		}
	})
}

// toolNames decodes the tool function names from a JSON request body.
func toolNames(t *testing.T, body []byte) []string {
	t.Helper()
	var parsed struct {
		Tools []struct {
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	names := make([]string, 0, len(parsed.Tools))
	for _, tool := range parsed.Tools {
		names = append(names, tool.Function.Name)
	}
	return names
}

func TestEnsureTools(t *testing.T) {
	t.Run("adds both stubs when tools is absent", func(t *testing.T) {
		body := []byte(`{"model":"x","messages":[{"role":"user","content":"hi"}]}`)
		got := ensureTools(body)
		names := toolNames(t, got)
		if len(names) != 2 || names[0] != "bash" || names[1] != "read" {
			t.Errorf("tools = %v, want [bash read]", names)
		}
	})

	t.Run("adds only the missing stub", func(t *testing.T) {
		body := []byte(`{"tools":[{"type":"function","function":{"name":"bash","parameters":{}}}],"messages":[]}`)
		got := ensureTools(body)
		if names := toolNames(t, got); len(names) != 2 || names[1] != "read" {
			t.Errorf("tools = %v, want [bash read]", names)
		}
	})

	t.Run("leaves a body with both tools byte-for-byte", func(t *testing.T) {
		body := []byte(`{"tools":[{"function":{"name":"bash"}},{"function":{"name":"read"}}]}`)
		got := ensureTools(body)
		if !bytes.Equal(got, body) {
			t.Errorf("body changed:\n got %s\nwant %s", got, body)
		}
	})

	t.Run("leaves non-JSON untouched", func(t *testing.T) {
		body := []byte(`not json`)
		if got := ensureTools(body); !bytes.Equal(got, body) {
			t.Errorf("body changed to %q", got)
		}
	})

	t.Run("leaves a JSON array untouched", func(t *testing.T) {
		body := []byte(`[1,2,3]`)
		if got := ensureTools(body); !bytes.Equal(got, body) {
			t.Errorf("body changed to %q", got)
		}
	})

	t.Run("leaves an empty body untouched", func(t *testing.T) {
		if got := ensureTools(nil); got != nil {
			t.Errorf("got %q, want nil", got)
		}
	})
}

func TestBridgeInjectsIdentity(t *testing.T) {
	var gotSession, gotRequest, gotUA string
	var gotNames []string

	rotate := func(context.Context) error { return nil }
	bridge := startBridge(t, func(w http.ResponseWriter, r *http.Request) {
		gotSession = r.Header.Get("X-Opencode-Session")
		gotRequest = r.Header.Get("X-Opencode-Request")
		gotUA = r.Header.Get("User-Agent")
		body, _ := io.ReadAll(r.Body)
		gotNames = toolNames(t, body)
		io.WriteString(w, `{}`)
	}, rotate, true, 0)

	req, _ := http.NewRequest("POST", bridge.URL+"/v1/chat/completions",
		bytes.NewBufferString(`{"model":"x","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("User-Agent", "curl/8.5.0")
	req.Header.Set("Authorization", "Bearer k")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()

	if !sessionIDPattern.MatchString(gotSession) {
		t.Errorf("session = %q", gotSession)
	}
	if !requestIDPattern.MatchString(gotRequest) {
		t.Errorf("request = %q", gotRequest)
	}
	if gotUA != opencodeUA {
		t.Errorf("UA = %q, want %q", gotUA, opencodeUA)
	}
	if len(gotNames) != 2 || gotNames[0] != "bash" || gotNames[1] != "read" {
		t.Errorf("tools = %v, want [bash read]", gotNames)
	}
}
