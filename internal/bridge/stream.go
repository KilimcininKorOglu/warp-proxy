package bridge

import (
	"fmt"

	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// The free tier refuses stream:false (gate 4), so with injection on the
// bridge forces stream:true upstream and reassembles the SSE stream into a
// single chat.completion object for callers that asked for JSON.

// wantsStream reports whether the JSON body asks for streaming; absent
// means false.
func wantsStream(body []byte) bool {
	var obj struct {
		Stream *bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return false
	}
	return obj.Stream != nil && *obj.Stream
}

// forceStream rewrites the body's stream flag to true. It returns the
// original bytes unchanged for non-JSON bodies or when the flag already
// reads true.
func forceStream(body []byte) []byte {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	var flag bool
	if raw, ok := obj["stream"]; ok {
		if err := json.Unmarshal(raw, &flag); err != nil || flag {
			return body
		}
	}
	encoded, err := json.Marshal(true)
	if err != nil {
		return body
	}
	obj["stream"] = encoded
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

// aggregated is the reassembled content of one upstream SSE stream.
type aggregated struct {
	ID      string
	Model   string
	Content string
	Reason  string
	Finish  string
	Prompt  int64
	Output  int64
}

// isSSE reports whether the response carries an event stream.
func isSSE(resp *http.Response) bool {
	return strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream")
}

// aggregateSSE drains an OpenAI-style chat.completion.chunk stream into one
// aggregated completion. Unparsable data lines (keep-alives, comments) are
// skipped; a read error aborts with a partial aggregate and the error.
func aggregateSSE(r io.Reader) (aggregated, error) {
	var agg aggregated
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		applyChunk(&agg, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return agg, fmt.Errorf("read upstream stream: %w", err)
	}
	return agg, nil
}

// applyChunk merges one SSE line into the aggregate; non-data and unparsable
// lines are ignored.
func applyChunk(agg *aggregated, line string) {
	data, ok := chunkData(line)
	if !ok {
		return
	}
	var chunk struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Delta struct {
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"delta"`
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal([]byte(data), &chunk); err != nil {
		return
	}
	mergeChunkMeta(agg, chunk.ID, chunk.Model, chunk.Usage)
	mergeChoices(agg, chunk.Choices)
}

// chunkData extracts the payload of a data: SSE line; ok is false for
// non-data, empty and [DONE] lines.
func chunkData(line string) (string, bool) {
	data, ok := strings.CutPrefix(strings.TrimSpace(line), "data:")
	if !ok {
		return "", false
	}
	data = strings.TrimSpace(data)
	if data == "" || data == "[DONE]" {
		return "", false
	}
	return data, true
}

// mergeChunkMeta carries the chunk's id, model and usage into the aggregate
// when they are still unset or present.
func mergeChunkMeta(agg *aggregated, id, model string,
	usage *struct {
		PromptTokens     int64 `json:"prompt_tokens"`
		CompletionTokens int64 `json:"completion_tokens"`
	}) {
	if agg.ID == "" {
		agg.ID = id
	}
	if agg.Model == "" {
		agg.Model = model
	}
	if usage != nil {
		agg.Prompt = usage.PromptTokens
		agg.Output = usage.CompletionTokens
	}
}

// mergeChoices appends the chunk deltas to the aggregate's text.
func mergeChoices(agg *aggregated, choices []struct {
	Delta struct {
		Content          string `json:"content"`
		ReasoningContent string `json:"reasoning_content"`
	} `json:"delta"`
	FinishReason *string `json:"finish_reason"`
}) {
	for _, c := range choices {
		agg.Content += c.Delta.Content
		agg.Reason += c.Delta.ReasoningContent
		if c.FinishReason != nil && *c.FinishReason != "" {
			agg.Finish = *c.FinishReason
		}
	}
}

// openaiCompletion renders the aggregated stream as a chat.completion
// object.
func (a aggregated) openaiCompletion() []byte {
	finish := a.Finish
	if finish == "" {
		finish = "stop"
	}
	id := a.ID
	if id == "" {
		id = "chatcmpl-bridge"
	}
	out := map[string]any{
		"id":      id,
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   a.Model,
		"choices": []map[string]any{{
			"index": 0,
			"message": map[string]any{
				"role":    "assistant",
				"content": a.Content,
			},
			"finish_reason": finish,
		}},
		"usage": map[string]int64{
			"prompt_tokens":     a.Prompt,
			"completion_tokens": a.Output,
			"total_tokens":      a.Prompt + a.Output,
		},
	}
	if a.Reason != "" {
		out["choices"].([]map[string]any)[0]["message"].(map[string]any)["reasoning_content"] = a.Reason
	}
	b, err := json.Marshal(out)
	if err != nil {
		return []byte(`{"error":{"message":"bridge aggregation failed"}}`)
	}
	return b
}
