// Package config holds the agent's local configuration file.
//
// The local file is authoritative for anything security-relevant
// (allow_patching, pinned server key): the server can suggest collection
// intervals and log sources but cannot grant itself new powers.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type Config struct {
	ServerURL          string `json:"server_url"`
	AgentID            string `json:"agent_id"`
	AgentKey           string `json:"agent_key"`
	ServerPublicKey    string `json:"server_public_key"` // base64 Ed25519, pinned at enrollment
	KeyID              string `json:"key_id,omitempty"`
	CAFile             string `json:"ca_file,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`

	// AllowPatching must be set locally by the host owner before the agent
	// will execute patch / patch_all tasks, even validly signed ones.
	AllowPatching bool `json:"allow_patching"`

	// Optional local overrides; zero values mean "use server suggestion".
	CollectIntervalSeconds int      `json:"collect_interval_seconds,omitempty"`
	LogSources             []string `json:"log_sources,omitempty"`
	DisableLogs            bool     `json:"disable_logs,omitempty"`
	// Extra sensitive paths to report as datastores (kind "files").
	SensitivePaths []string `json:"sensitive_paths,omitempty"`

	path string
}

// DefaultPath returns the platform default config location.
func DefaultPath() string {
	if p := os.Getenv("SAMS_AGENT_CONFIG"); p != "" {
		return p
	}
	switch runtime.GOOS {
	case "windows":
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "sams-agent", "config.json")
	case "darwin":
		return "/Library/Application Support/sams-agent/config.json"
	default:
		return "/etc/sams-agent/config.json"
	}
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.path = path
	return c, nil
}

// Save writes the config atomically with mode 0600 (it holds the agent key).
func (c *Config) Save(path string) error {
	if path == "" {
		path = c.path
	}
	if path == "" {
		return errors.New("no config path")
	}
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
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	c.path = path
	return os.Chmod(path, 0o600)
}

func (c *Config) Path() string { return c.path }

// StateDir is where offsets and executed-task records live (next to config).
func (c *Config) StateDir() string { return filepath.Dir(c.path) }

func (c *Config) Enrolled() bool {
	return c.ServerURL != "" && c.AgentID != "" && c.AgentKey != "" && c.ServerPublicKey != ""
}
