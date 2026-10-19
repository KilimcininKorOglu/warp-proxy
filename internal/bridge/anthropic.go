package bridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// The Anthropic-compatible surface: POST /v1/messages speaks the Anthropic
// messages API and runs every request through the same free-tier pipeline
// (fingerprint injection, stream forcing, WARP rotation) as
// /v1/chat/completions, translating both directions. Streaming callers get
// the standard Anthropic event sequence assembled from the upstream stream.

// chatCompletionsPath is the upstream path every request funnels into.
const chatCompletionsPath = "/v1/chat/completions"

// serveMessages handles one /v1/messages request end to end.
func (s *Server) serveMessages(w http.ResponseWriter, r *http.Request) {
	cfg := s.Cfg()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		anthropicError(w, http.StatusBadRequest, "read request body failed")
		return
	}
	if len(body) > maxBody {
		anthropicError(w, http.StatusRequestEntityTooLarge, "request body exceeds bridge limit")
		return
	}
	openaiBody, clientStream, cerr := anthropicToOpenAI(body)
	if cerr != nil {
		anthropicError(w, http.StatusBadRequest, cerr.Error())
		return
	}
	ids := newIdentity(cfg)
	if ids != nil {
		openaiBody = forceStream(ensureTools(openaiBody))
	}

	if err := s.acquire(r.Context(), cfg); err != nil {
		anthropicError(w, http.StatusServiceUnavailable, "bridge busy: "+err.Error())
		return
	}
	defer s.release()

	upstreamReq := r.Clone(r.Context())
	upstreamReq.URL.Path = chatCompletionsPath
	upstreamReq.URL.RawQuery = ""
	resp, replayErr := s.replay(upstreamReq, openaiBody, cfg, ids)
	if errors.Is(replayErr, errClientCanceled) {
		anthropicError(w, http.StatusBadGateway, "client canceled while waiting for retry")
		return
	}
	if replayErr != nil {
		anthropicError(w, http.StatusBadGateway, "bridge upstream failed: "+replayErr.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeAnthropicUpstreamError(w, resp)
		return
	}
	agg, aerr := s.collectCompletion(resp)
	if aerr != nil {
		anthropicError(w, http.StatusBadGateway, "read upstream stream: "+aerr.Error())
		return
	}
	if clientStream {
		writeAnthropicStream(w, agg)
		return
	}
	writeAnthropicMessage(w, agg)
}

// collectCompletion drains an SSE stream into an aggregated completion; a
// non-stream response is passed through by parsing its JSON body.
func (s *Server) collectCompletion(resp *http.Response) (aggregated, error) {
	if isSSE(resp) {
		agg := aggregateSSE(resp.Body)
		resp.Body.Close()
		return agg, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return aggregated{}, err
	}
	var openai struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &openai); err != nil {
		return aggregated{}, fmt.Errorf("unexpected upstream body: %s", truncate(body, 200))
	}
	agg := aggregated{ID: openai.ID, Model: openai.Model,
		Prompt: openai.Usage.PromptTokens, Output: openai.Usage.CompletionTokens}
	if len(openai.Choices) > 0 {
		agg.Content = openai.Choices[0].Message.Content
		agg.Reason = openai.Choices[0].Message.ReasoningContent
		agg.Finish = openai.Choices[0].FinishReason
	}
	return agg, nil
}

// anthropicToOpenAI converts an Anthropic messages request into an
// OpenAI chat completions body and reports whether the caller asked for
// streaming.
func anthropicToOpenAI(body []byte) ([]byte, bool, error) {
	var req struct {
		Model    string          `json:"model"`
		System   json.RawMessage `json:"system"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Stream *bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, false, fmt.Errorf("parse anthropic body: %w", err)
	}
	if req.Model == "" {
		return nil, false, fmt.Errorf("anthropic body has no model")
	}
	msgs := make([]map[string]any, 0, len(req.Messages)+1)
	if sys := blocksText(req.System); sys != "" {
		msgs = append(msgs, map[string]any{"role": "system", "content": sys})
	}
	for _, m := range req.Messages {
		msgs = append(msgs, map[string]any{"role": m.Role, "content": blocksText(m.Content)})
	}
	out := map[string]any{"model": req.Model, "messages": msgs}
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, false, err
	}
	return encoded, req.Stream != nil && *req.Stream, nil
}

// blocksText renders Anthropic content — a plain string or an array of
// {type:"text",text} blocks — as one string.
func blocksText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return ""
	}
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// writeAnthropicMessage renders the aggregated completion as an Anthropic
// message object.
func writeAnthropicMessage(w http.ResponseWriter, agg aggregated) {
	stop := "end_turn"
	if agg.Finish == "length" {
		stop = "max_tokens"
	}
	msg := map[string]any{
		"id":          "msg_bridge_" + randomString(alnumChars, 16),
		"type":        "message",
		"role":        "assistant",
		"model":       agg.Model,
		"content":     []map[string]any{{"type": "text", "text": agg.Content}},
		"stop_reason": stop,
		"usage": map[string]int64{
			"input_tokens":  agg.Prompt,
			"output_tokens": agg.Output,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(msg)
}

// writeAnthropicStream emits the Anthropic event sequence carrying the
// aggregated completion in one content block.
func writeAnthropicStream(w http.ResponseWriter, agg aggregated) {
	stop := "end_turn"
	if agg.Finish == "length" {
		stop = "max_tokens"
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.WriteHeader(http.StatusOK)
	send := func(event string, data map[string]any) {
		b, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
	}
	flusher, _ := w.(http.Flusher)
	send("message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id": "msg_bridge_" + randomString(alnumChars, 16), "type": "message",
			"role": "assistant", "content": []any{}, "model": agg.Model,
			"stop_reason": nil,
			"usage":       map[string]int64{"input_tokens": agg.Prompt, "output_tokens": 0},
		},
	})
	send("content_block_start", map[string]any{
		"type": "content_block_start", "index": 0,
		"content_block": map[string]any{"type": "text", "text": ""},
	})
	if agg.Content != "" {
		send("content_block_delta", map[string]any{
			"type": "content_block_delta", "index": 0,
			"delta": map[string]any{"type": "text_delta", "text": agg.Content},
		})
	}
	send("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
	send("message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": stop},
		"usage": map[string]int64{"output_tokens": agg.Output},
	})
	send("message_stop", map[string]any{"type": "message_stop"})
	if flusher != nil {
		flusher.Flush()
	}
}

// anthropicError answers with the Anthropic error envelope.
func anthropicError(w http.ResponseWriter, status int, message string) {
	errType := "upstream_error"
	if status == http.StatusBadRequest {
		errType = "invalid_request_error"
	} else if status == http.StatusTooManyRequests {
		errType = "rate_limit_error"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":  "error",
		"error": map[string]any{"type": errType, "message": message},
	})
}

// writeAnthropicUpstreamError forwards an upstream refusal in the Anthropic
// error envelope, keeping the upstream status code.
func writeAnthropicUpstreamError(w http.ResponseWriter, resp *http.Response) {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorPeek))
	msg := strings.TrimSpace(string(body))
	var parsed struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil && parsed.Error.Message != "" {
		msg = parsed.Error.Message
	}
	if msg == "" {
		msg = fmt.Sprintf("upstream status %d", resp.StatusCode)
	}
	anthropicError(w, resp.StatusCode, msg)
}

// truncate shortens s for error messages.
func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}
