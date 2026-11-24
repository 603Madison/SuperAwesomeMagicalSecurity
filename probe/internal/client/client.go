// Package client talks to sams-server's probe API and persists enrollment state.
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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/603madison/superawesomemagicalsecurity/probe/internal/scope"
)

// Config is persisted after enrollment (mode 0600).
type Config struct {
	Server             string `json:"server"`
	AgentID            string `json:"agent_id"`
	AgentKey           string `json:"agent_key"`
	ServerPublicKey    string `json:"server_public_key"`
	KeyID              string `json:"key_id"`
	CAFile             string `json:"ca_file,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
}

// DefaultConfigPath is ~/.config/sams-probe/config.json (or $SAMS_PROBE_CONFIG).
func DefaultConfigPath() string {
	if p := os.Getenv("SAMS_PROBE_CONFIG"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "sams-probe", "config.json")
}

// Load reads a config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Server == "" || c.AgentID == "" || c.AgentKey == "" || c.ServerPublicKey == "" {
		return nil, fmt.Errorf("%s: incomplete config; run `sams-probe enroll`", path)
	}
	return &c, nil
}

// Save writes the config with 0600 permissions (directory 0700).
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Client is an authenticated API client.
type Client struct {
	cfg  *Config
	http *http.Client
	ua   string
}

// HTTPClient builds an HTTP client honoring a custom CA or insecure flag.
func HTTPClient(caFile string, insecure bool) (*http.Client, error) {
	tcfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure} //nolint:gosec // opt-in for lab setups
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificates found", caFile)
		}
		tcfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tcfg
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}, nil
}

// New creates a client from a saved config.
func New(cfg *Config, version string) (*Client, error) {
	hc, err := HTTPClient(cfg.CAFile, cfg.InsecureSkipVerify)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, http: hc, ua: "sams-probe/" + version}, nil
}

// Config returns the client's config.
func (c *Client) Config() *Config { return c.cfg }

func apiURL(server, path string) string {
	return strings.TrimRight(server, "/") + "/api/v1" + path
}

// EnrollResponse is the server's reply to /enroll.
type EnrollResponse struct {
	AgentID         string `json:"agent_id"`
	AgentKey        string `json:"agent_key"`
	ServerPublicKey string `json:"server_public_key"`
	KeyID           string `json:"key_id"`
}

// Enroll exchanges a one-time token for probe credentials.
func Enroll(ctx context.Context, hc *http.Client, server, token, hostname, version, osName string) (*EnrollResponse, error) {
	body, _ := json.Marshal(map[string]any{
		"token": token, "kind": "probe", "hostname": hostname, "version": version, "os": osName,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL(server, "/enroll"), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "sams-probe/"+version)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("enroll failed: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var er EnrollResponse
	if err := json.Unmarshal(b, &er); err != nil {
		return nil, fmt.Errorf("enroll response: %w", err)
	}
	if er.AgentID == "" || er.AgentKey == "" || er.ServerPublicKey == "" {
		return nil, errors.New("enroll response missing agent_id/agent_key/server_public_key")
	}
	return &er, nil
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, apiURL(c.cfg.Server, path), body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.AgentID+":"+c.cfg.AgentKey)
	req.Header.Set("User-Agent", c.ua)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%s %s: decode: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

// Heartbeat reports liveness; the server replies with the IP it saw us from.
func (c *Client) Heartbeat(ctx context.Context, version string) (seenIP string, err error) {
	var out struct {
		SeenIP     string `json:"seen_ip"`
		ServerTime string `json:"server_time"`
	}
	_, err = c.do(ctx, http.MethodPost, "/probe/heartbeat", map[string]string{"version": version}, &out)
	return out.SeenIP, err
}

// NextJob fetches the next signed job envelope; nil when there is none.
func (c *Client) NextJob(ctx context.Context) (*scope.Envelope, error) {
	var out struct {
		Job *scope.Envelope `json:"job"`
	}
	code, err := c.do(ctx, http.MethodGet, "/probe/jobs/next", nil, &out)
	if err != nil || code == http.StatusNoContent {
		return nil, err
	}
	return out.Job, nil
}

// PostResult uploads an ExternalScanResult for a job.
func (c *Client) PostResult(ctx context.Context, jobID string, result any) error {
	_, err := c.do(ctx, http.MethodPost, "/probe/jobs/"+jobID+"/result", result, nil)
	return err
}
