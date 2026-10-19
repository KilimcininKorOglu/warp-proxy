package bridge

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestWantsStream(t *testing.T) {
	if wantsStream([]byte(`{"stream":true}`)) != true {
		t.Error("stream:true not detected")
	}
	if wantsStream([]byte(`{"stream":false}`)) {
		t.Error("stream:false detected as streaming")
	}
	if wantsStream([]byte(`{}`)) {
		t.Error("absent stream detected as streaming")
	}
	if wantsStream([]byte(`not json`)) {
		t.Error("garbage detected as streaming")
	}
}

func TestForceStream(t *testing.T) {
	t.Run("absent flag becomes true", func(t *testing.T) {
		got := forceStream([]byte(`{"model":"x","messages":[]}`))
		if !wantsStream(got) {
			t.Errorf("forced body = %s", got)
		}
	})
	t.Run("false flag becomes true", func(t *testing.T) {
		got := forceStream([]byte(`{"stream":false}`))
		if !wantsStream(got) {
			t.Errorf("forced body = %s", got)
		}
	})
	t.Run("true flag is untouched", func(t *testing.T) {
		body := []byte(`{"stream":true,"other":1}`)
		if got := forceStream(body); !bytes.Equal(got, body) {
			t.Errorf("body changed to %s", got)
		}
	})
	t.Run("non-JSON untouched", func(t *testing.T) {
		body := []byte(`nope`)
		if got := forceStream(body); !bytes.Equal(got, body) {
			t.Errorf("body changed to %s", got)
		}
	})
}

const sampleSSE = "data: {\"id\":\"c1\",\"model\":\"m\",\"choices\":[{\"index\":0," +
	"\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n" +
	"\n" +
	"data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hel" +
	"lo\"},\"finish_reason\":null}]}\n\n" +
	": keep-alive\n\n" +
	"data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" wor" +
	"ld\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion" +
	"_tokens\":5}}\n\n" +
	"data: [DONE]\n\n"

func TestAggregateSSE(t *testing.T) {
	agg := aggregateSSE(strings.NewReader(sampleSSE))
	if agg.ID != "c1" || agg.Model != "m" {
		t.Errorf("id/model = %q/%q", agg.ID, agg.Model)
	}
	if agg.Content != "Hello world" {
		t.Errorf("content = %q", agg.Content)
	}
	if agg.Finish != "stop" {
		t.Errorf("finish = %q", agg.Finish)
	}
	if agg.Prompt != 3 || agg.Output != 5 {
		t.Errorf("usage = %d/%d", agg.Prompt, agg.Output)
	}
	var parsed map[string]any
	if err := json.Unmarshal(agg.openaiCompletion(), &parsed); err != nil {
		t.Fatalf("completion is not JSON: %v", err)
	}
	choices, _ := parsed["choices"].([]any)
	first, _ := choices[0].(map[string]any)
	if first["finish_reason"] != "stop" {
		t.Errorf("finish_reason = %v", first["finish_reason"])
	}
}

func TestIsSSE(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	if isSSE(resp) {
		t.Error("empty content type read as SSE")
	}
	resp.Header.Set("Content-Type", "text/event-stream; charset=utf-8")
	if !isSSE(resp) {
		t.Error("event stream not detected")
	}
}

func TestAnthropicToOpenAI(t *testing.T) {
	body := []byte(`{"model":"big-pickle","system":"be nice",
		"stream":true,
		"messages":[
			{"role":"user","content":"hello"},
			{"role":"assistant","content":[{"type":"text","text":"hi"},{"type":"text","text":"there"}]}
		]}`)
	out, stream, err := anthropicToOpenAI(body)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !stream {
		t.Error("stream flag lost")
	}
	var parsed struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if parsed.Model != "big-pickle" {
		t.Errorf("model = %q", parsed.Model)
	}
	if len(parsed.Messages) != 3 ||
		parsed.Messages[0].Content != "be nice" ||
		parsed.Messages[2].Content != "hi\nthere" {
		t.Errorf("messages = %+v", parsed.Messages)
	}
}

func TestAnthropicToOpenAIRequiresModel(t *testing.T) {
	if _, _, err := anthropicToOpenAI([]byte(`{"messages":[]}`)); err == nil {
		t.Error("model-less body accepted")
	}
}

func TestAnthropicMessageShape(t *testing.T) {
	agg := aggregated{Model: "m", Content: "answer", Finish: "stop", Prompt: 2, Output: 4}
	// writeAnthropicMessage emits the Anthropic envelope; capture it through
	// a recorder by calling the stream writer for shape checks instead.
	rec := &captureWriter{}
	writeAnthropicStream(rec, agg)
	out := rec.buf.String()
	for _, want := range []string{"message_start", "content_block_delta", "text_delta", "message_stop", "answer"} {
		if !strings.Contains(out, want) {
			t.Errorf("stream missing %q:\n%s", want, out)
		}
	}
}

type captureWriter struct{ buf bytes.Buffer }

func (c *captureWriter) Header() http.Header { return http.Header{} }
func (c *captureWriter) Write(p []byte) (int, error) {
	return c.buf.Write(p)
}
func (c *captureWriter) WriteHeader(int) {}
