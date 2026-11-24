package scope

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Envelope is the server's signed instruction wrapper (see server/sams/crypto.py).
type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	KeyID     string `json:"key_id"`
}

// Job is the signed scan instruction from the server.
type Job struct {
	JobID      string   `json:"job_id"`
	ProbeID    string   `json:"probe_id"`
	Targets    []string `json:"targets"`
	Ports      []int    `json:"ports"`
	Checks     []string `json:"checks"`
	RatePerSec int      `json:"rate_per_sec"`
	ExpiresAt  string   `json:"expires_at"`
}

// VerifyEnvelope checks the Ed25519 signature over the decoded payload bytes
// and returns those bytes. Nothing in the payload is parsed before this succeeds.
func VerifyEnvelope(env Envelope, publicKeyB64 string) ([]byte, error) {
	pk, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(pk) != ed25519.PublicKeySize {
		return nil, errors.New("pinned server public key is invalid")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("payload not base64: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return nil, fmt.Errorf("signature not base64: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pk), payload, sig) {
		return nil, errors.New("signature verification failed")
	}
	return payload, nil
}

// ParseTime accepts RFC3339 and Python's str(datetime) forms.
func ParseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	layouts := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02 15:04:05.999999999",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time %q", s)
}

// OpenJob verifies an envelope and validates the job is for this probe and unexpired.
func OpenJob(env Envelope, publicKeyB64, myProbeID string, now time.Time) (*Job, error) {
	payload, err := VerifyEnvelope(env, publicKeyB64)
	if err != nil {
		return nil, err
	}
	var j Job
	if err := json.Unmarshal(payload, &j); err != nil {
		return nil, fmt.Errorf("job payload: %w", err)
	}
	if j.JobID == "" {
		return nil, errors.New("job has no job_id")
	}
	if j.ProbeID != myProbeID {
		return nil, fmt.Errorf("job is addressed to probe %q, not %q", j.ProbeID, myProbeID)
	}
	if j.ExpiresAt == "" {
		return nil, errors.New("job has no expires_at")
	}
	exp, err := ParseTime(j.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if !now.Before(exp) {
		return nil, fmt.Errorf("job expired at %s", exp.Format(time.RFC3339))
	}
	if len(j.Targets) == 0 {
		return nil, errors.New("job has no targets")
	}
	for _, p := range j.Ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("job has invalid port %d", p)
		}
	}
	return &j, nil
}

// Expiry returns the parsed expiry (zero on error).
func (j *Job) Expiry() time.Time {
	t, _ := ParseTime(j.ExpiresAt)
	return t
}
