package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// complete sends one prompt to the configured provider and returns the reply
// text and the model that produced it
func complete(ctx context.Context, cfg LLMConfig, system, prompt string, maxTokens int) (string, string, error) {
	switch cfg.Provider {
	case ProviderClaude:
		return completeClaude(ctx, cfg, system, prompt, maxTokens)
	case ProviderGemini:
		return completeGemini(ctx, cfg, prompt, maxTokens)
	}
	return completeOpenAICompatible(ctx, cfg, prompt, maxTokens)
}

func completeOpenAICompatible(ctx context.Context, cfg LLMConfig, prompt string, maxTokens int) (string, string, error) {
	body := map[string]interface{}{
		"model":       cfg.ModelName(),
		"temperature": 0,
		"max_tokens":  maxTokens,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Model string `json:"model"`
	}
	if err := postJSON(ctx, cfg, nil, body, &result); err != nil {
		return "", "", err
	}
	if len(result.Choices) == 0 {
		return "", "", fmt.Errorf("no response from %s", cfg.Provider)
	}
	return result.Choices[0].Message.Content, result.Model, nil
}

func completeClaude(ctx context.Context, cfg LLMConfig, system, prompt string, maxTokens int) (string, string, error) {
	body := map[string]interface{}{
		"model":       cfg.ModelName(),
		"max_tokens":  maxTokens,
		"temperature": 0,
		"system":      system,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	headers := map[string]string{"anthropic-version": "2023-06-01"}
	if err := postJSON(ctx, cfg, headers, body, &result); err != nil {
		return "", "", err
	}
	if len(result.Content) == 0 {
		return "", "", fmt.Errorf("no response from claude")
	}
	return result.Content[0].Text, cfg.ModelName(), nil
}

func completeGemini(ctx context.Context, cfg LLMConfig, prompt string, maxTokens int) (string, string, error) {
	body := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{"text": prompt},
				},
			},
		},
		"generationConfig": map[string]interface{}{
			"temperature":     0,
			"maxOutputTokens": maxTokens,
		},
	}
	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := postJSON(ctx, cfg, nil, body, &result); err != nil {
		return "", "", err
	}
	if len(result.Candidates) == 0 || len(result.Candidates[0].Content.Parts) == 0 {
		return "", "", fmt.Errorf("no response from gemini")
	}
	return result.Candidates[0].Content.Parts[0].Text, cfg.ModelName(), nil
}

// postJSON sends body to the provider endpoint and decodes the reply into out.
// Non-200 errors include the start of the response body, which usually says why.
func postJSON(ctx context.Context, cfg LLMConfig, headers map[string]string, body, out interface{}) error {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", cfg.Endpoint(), bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set(cfg.AuthHeader(), cfg.AuthValue())
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s request failed: %w", cfg.Provider, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		msg := errorMessage(resp.Body)
		if msg == "" {
			return fmt.Errorf("%s HTTP %d", cfg.Provider, resp.StatusCode)
		}
		return fmt.Errorf("%s HTTP %d: %s", cfg.Provider, resp.StatusCode, msg)
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding %s response: %w", cfg.Provider, err)
	}
	return nil
}

// errorMessage extracts a readable reason from an error response body. All
// supported providers return {"error": {"message": ...}}; anything else is
// returned as a short raw snippet.
func errorMessage(body io.Reader) string {
	data, _ := io.ReadAll(io.LimitReader(body, 4096))
	var parsed struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	msg := string(data)
	if json.Unmarshal(data, &parsed) == nil && parsed.Error.Message != "" {
		msg = parsed.Error.Message
	}
	msg = strings.Join(strings.Fields(msg), " ")
	if r := []rune(msg); len(r) > 200 {
		msg = string(r[:200]) + "…"
	}
	return msg
}
