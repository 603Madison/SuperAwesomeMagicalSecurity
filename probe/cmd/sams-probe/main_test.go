package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/603madison/superawesomemagicalsecurity/probe/internal/client"
	"github.com/603madison/superawesomemagicalsecurity/probe/internal/scan"
)

type fakeServer struct {
	mu      sync.Mutex
	sk      ed25519.PrivateKey
	pk      ed25519.PublicKey
	job     map[string]any
	tamper  bool
	results map[string]scan.Result
	auth    []string
}

func (f *fakeServer) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["token"] != "tok" || body["kind"] != "probe" {
			http.Error(w, "bad token", 403)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"agent_id": "prb_1", "agent_key": "secret",
			"server_public_key": base64.StdEncoding.EncodeToString(f.pk), "key_id": "k1"})
	})
	mux.HandleFunc("/api/v1/probe/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"seen_ip": "203.0.113.50", "server_time": time.Now().Format(time.RFC3339)})
	})
	mux.HandleFunc("/api/v1/probe/jobs/next", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.job == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		raw, _ := json.Marshal(f.job)
		sig := ed25519.Sign(f.sk, raw)
		if f.tamper {
			raw = []byte(strings.Replace(string(raw), "10.9.9.9", "10.9.9.8", 1))
		}
		f.job = nil
		json.NewEncoder(w).Encode(map[string]any{"job": map[string]string{
			"payload": base64.StdEncoding.EncodeToString(raw), "signature": base64.StdEncoding.EncodeToString(sig), "key_id": "k1"}})
	})
	mux.HandleFunc("/api/v1/probe/jobs/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var res scan.Result
		if err := json.Unmarshal(b, &res); err != nil {
			t.Errorf("bad result json: %v", err)
		}
		f.mu.Lock()
		f.results[r.URL.Path] = res
		f.mu.Unlock()
		w.Write([]byte(`{"ok":true}`))
	})
	return mux
}

func TestEnrollAndRunOnce(t *testing.T) {
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	f := &fakeServer{sk: sk, pk: pk, results: map[string]scan.Result{}}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	cfgPath := filepath.Join(t.TempDir(), "probe", "config.json")
	if err := cmdEnroll(context.Background(), []string{"--server", srv.URL, "--token", "tok", "--config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(cfgPath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config perms: %v %v", st.Mode(), err)
	}
	cfg, err := client.Load(cfgPath)
	if err != nil || cfg.AgentID != "prb_1" {
		t.Fatalf("load: %+v %v", cfg, err)
	}
	c, _ := client.New(cfg, version)

	// No job -> nothing happens.
	did, err := runOnce(context.Background(), c, time.Minute)
	if did || err != nil {
		t.Fatalf("idle: %v %v", did, err)
	}
	if f.auth[0] != "Bearer prb_1:secret" {
		t.Fatalf("auth header %q", f.auth[0])
	}

	// Valid job targeting a private address: the probe must refuse to scan it but still report.
	f.job = map[string]any{"job_id": "job_abc", "probe_id": "prb_1", "targets": []string{"10.9.9.9"},
		"ports": []int{22}, "checks": []string{"tcp"}, "rate_per_sec": 10,
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	did, err = runOnce(context.Background(), c, time.Minute)
	if !did || err != nil {
		t.Fatalf("job: %v %v", did, err)
	}
	res, ok := f.results["/api/v1/probe/jobs/job_abc/result"]
	if !ok {
		t.Fatalf("no result posted: %v", f.results)
	}
	if res.JobID != "job_abc" || res.ProbeID != "prb_1" || res.ProbePublicIP != "203.0.113.50" ||
		len(res.Targets) != 1 || res.Targets[0].Issues[0].ID != "scope_refused" {
		t.Fatalf("result: %+v", res)
	}

	// Tampered job: rejected, nothing posted.
	f.tamper = true
	f.job = map[string]any{"job_id": "job_evil", "probe_id": "prb_1", "targets": []string{"10.9.9.9"},
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	did, err = runOnce(context.Background(), c, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "REJECTED") {
		t.Fatalf("tampered job not rejected: %v %v", did, err)
	}
	if _, ok := f.results["/api/v1/probe/jobs/job_evil/result"]; ok {
		t.Fatal("result posted for tampered job")
	}

	// Job addressed to another probe: rejected.
	f.tamper = false
	f.job = map[string]any{"job_id": "job_other", "probe_id": "prb_2", "targets": []string{"example.org"},
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if _, err := runOnce(context.Background(), c, time.Minute); err == nil {
		t.Fatal("job for another probe accepted")
	}
}
