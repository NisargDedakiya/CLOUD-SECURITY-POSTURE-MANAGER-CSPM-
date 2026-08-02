// Package aegis provides the official Go SDK for Aegis CNAPP & CSPM API.
package aegis

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Client struct {
	APIKey   string
	Endpoint string
	HTTP     *http.Client
}

func NewClient(apiKey string, endpoint string) *Client {
	if endpoint == "" {
		endpoint = "http://localhost:8000"
	}
	return &Client{
		APIKey:   apiKey,
		Endpoint: endpoint,
		HTTP:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) GetStatus() (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/cspm/overview", c.Endpoint), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.APIKey))

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}
