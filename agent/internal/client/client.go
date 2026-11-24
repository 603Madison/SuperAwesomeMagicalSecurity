// Package client talks to sams-server over HTTPS.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Client struct {
	BaseURL   string
	AgentID   string
	AgentKey  string
	UserAgent string
	HTTP      *http.Client
	Retries   int
}

type Options struct {
	CAFile             string
	InsecureSkipVerify bool
	Timeout            time.Duration
}

func New(baseURL, version string, opt Options) (*Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if opt.CAFile != "" {
		pem, err := os.ReadFile(opt.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file contains no certificates")
		}
		tlsCfg.RootCAs = pool
	}
	if opt.InsecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true // explicit operator opt-in for lab setups
	}
	if opt.Timeout == 0 {
		opt.Timeout = 60 * time.Second
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &Client{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		UserAgent: "sams-agent/" + version,
		HTTP:      &http.Client{Timeout: opt.Timeout, Transport: tr},
		Retries:   3,
	}, nil
}

// HTTPError is returned for non-2xx responses.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("server returned %d: %s", e.Status, e.Body) }

func retryable(err error) bool {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status == 429 || he.Status >= 500
	}
	return err != nil
}

// Do sends a JSON request (body may be nil) and decodes a JSON response into
// out (may be nil). Returns (status, error). 204 is success with no body.
func (c *Client) Do(ctx context.Context, method, path string, body any, out any) (int, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return 0, err
		}
	}
	var lastErr error
	backoff := time.Second
	for attempt := 0; attempt <= c.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
		status, err := c.once(ctx, method, path, payload, out)
		if err == nil {
			return status, nil
		}
		lastErr = err
		if !retryable(err) || ctx.Err() != nil {
			return status, err
		}
	}
	return 0, lastErr
}

func (c *Client) once(ctx context.Context, method, path string, payload []byte, out any) (int, error) {
	var rdr io.Reader
	if payload != nil {
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.AgentID != "" {
		req.Header.Set("Authorization", "Bearer "+c.AgentID+":"+c.AgentKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := string(data)
		if len(msg) > 512 {
			msg = msg[:512]
		}
		return resp.StatusCode, &HTTPError{Status: resp.StatusCode, Body: msg}
	}
	if out != nil && resp.StatusCode != http.StatusNoContent && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// ---- typed API calls ------------------------------------------------------

type EnrollRequest struct {
	Token    string `json:"token"`
	Kind     string `json:"kind"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	OS       string `json:"os"`
}

type EnrollResponse struct {
	AgentID         string `json:"agent_id"`
	AgentKey        string `json:"agent_key"`
	ServerPublicKey string `json:"server_public_key"`
	KeyID           string `json:"key_id"`
}

func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error) {
	out := &EnrollResponse{}
	if _, err := c.Do(ctx, http.MethodPost, "/api/v1/enroll", req, out); err != nil {
		return nil, err
	}
	if out.AgentID == "" || out.AgentKey == "" || out.ServerPublicKey == "" {
		return nil, errors.New("enroll response missing agent_id/agent_key/server_public_key")
	}
	return out, nil
}

type AgentConfig struct {
	CollectIntervalSeconds int      `json:"collect_interval_seconds"`
	LogSources             []string `json:"log_sources"`
	ServerTime             string   `json:"server_time"`
}

func (c *Client) GetConfig(ctx context.Context) (*AgentConfig, error) {
	out := &AgentConfig{}
	_, err := c.Do(ctx, http.MethodGet, "/api/v1/agent/config", nil, out)
	return out, err
}

func (c *Client) PostInventory(ctx context.Context, inv any) (map[string]any, error) {
	out := map[string]any{}
	_, err := c.Do(ctx, http.MethodPost, "/api/v1/agent/inventory", inv, &out)
	return out, err
}

type LogLine struct {
	Source string `json:"source"`
	Line   string `json:"line"`
	TS     string `json:"ts,omitempty"`
}

func (c *Client) PostLogs(ctx context.Context, lines []LogLine) error {
	_, err := c.Do(ctx, http.MethodPost, "/api/v1/agent/logs", map[string]any{"lines": lines}, nil)
	return err
}

type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	KeyID     string `json:"key_id"`
}

func (c *Client) GetTasks(ctx context.Context) ([]Envelope, error) {
	var out struct {
		Tasks []Envelope `json:"tasks"`
	}
	_, err := c.Do(ctx, http.MethodGet, "/api/v1/agent/tasks", nil, &out)
	return out.Tasks, err
}

type TaskResult struct {
	Status  string         `json:"status"`
	Output  string         `json:"output"`
	Details map[string]any `json:"details,omitempty"`
}

func (c *Client) PostTaskResult(ctx context.Context, id string, res TaskResult) error {
	_, err := c.Do(ctx, http.MethodPost, "/api/v1/agent/tasks/"+url.PathEscape(id)+"/result", res, nil)
	return err
}
