// Package scan implements the outside-in checks. Result types mirror
// ExternalScanResult / ExternalTargetResult / ExternalService in
// server/sams/models.py; JSON field names are the wire contract.
package scan

import "time"

// Result == ExternalScanResult.
type Result struct {
	ProbeID       string         `json:"probe_id"`
	JobID         string         `json:"job_id"`
	StartedAt     time.Time      `json:"started_at"`
	FinishedAt    time.Time      `json:"finished_at"`
	ProbePublicIP string         `json:"probe_public_ip"`
	Targets       []TargetResult `json:"targets"`
}

// TargetResult == ExternalTargetResult.
type TargetResult struct {
	Target    string         `json:"target"`
	Resolved  []string       `json:"resolved"`
	Reachable bool           `json:"reachable"`
	Services  []Service      `json:"services"`
	DNS       map[string]any `json:"dns"`
	Issues    []Issue        `json:"issues"`
}

// Service == ExternalService.
type Service struct {
	Port    int            `json:"port"`
	Proto   string         `json:"proto"`
	State   string         `json:"state"`
	Service string         `json:"service"`
	Banner  string         `json:"banner"`
	Product string         `json:"product"`
	Version string         `json:"version"`
	TLS     map[string]any `json:"tls,omitempty"`
	HTTP    map[string]any `json:"http,omitempty"`

	// internal hints, not serialized
	unauthenticated bool
}

// Issue is a probe-side finding (dict in ExternalTargetResult.issues).
type Issue struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // info | low | medium | high | critical
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Port     int    `json:"port,omitempty"`
}

func newTargetResult(target string) TargetResult {
	return TargetResult{
		Target:   target,
		Resolved: []string{},
		Services: []Service{},
		DNS:      map[string]any{},
		Issues:   []Issue{},
	}
}
