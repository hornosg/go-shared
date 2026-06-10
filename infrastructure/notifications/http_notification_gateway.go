package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hornosg/go-shared/domain/port"
)

// HTTPNotificationGateway implements NotificationGateway by calling the notifications-service REST API.
type HTTPNotificationGateway struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewHTTPNotificationGateway creates a gateway that forwards notifications to baseURL.
// apiKey is sent as the X-API-Key header.
func NewHTTPNotificationGateway(baseURL, apiKey string, timeout time.Duration) *HTTPNotificationGateway {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &HTTPNotificationGateway{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (g *HTTPNotificationGateway) Send(ctx context.Context, n port.Notification) (*port.NotificationResult, error) {
	results, err := g.SendBatch(ctx, []port.Notification{n})
	if err != nil {
		return nil, err
	}
	return &results[0], nil
}

func (g *HTTPNotificationGateway) SendBatch(ctx context.Context, notifications []port.Notification) ([]port.NotificationResult, error) {
	body, err := json.Marshal(map[string]any{"notifications": notifications})
	if err != nil {
		return nil, fmt.Errorf("notification gateway: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.baseURL+"/v1/send-batch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("notification gateway: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if g.apiKey != "" {
		req.Header.Set("X-API-Key", g.apiKey)
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("notification gateway: http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		return nil, fmt.Errorf("notification gateway: status %d: %v", resp.StatusCode, errBody)
	}

	var out struct {
		Results []port.NotificationResult `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("notification gateway: decode response: %w", err)
	}
	return out.Results, nil
}
