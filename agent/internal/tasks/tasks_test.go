package tasks

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/603madison/superawesomemagicalsecurity/agent/internal/client"
)

func sign(t *testing.T, sk ed25519.PrivateKey, payload map[string]any) client.Envelope {
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return client.Envelope{
		Payload:   base64.StdEncoding.EncodeToString(raw),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(sk, raw)),
	}
}

func TestVerifyEnvelope(t *testing.T) {
	pub, sk, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	env := sign(t, sk, map[string]any{"id": "t1", "agent_id": "agt_1", "action": "collect"})
	if _, err := VerifyEnvelope(env, pubB64); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	// tampered payload
	raw, _ := base64.StdEncoding.DecodeString(env.Payload)
	tampered := strings.Replace(string(raw), "collect", "patch_all", 1)
	bad := client.Envelope{Payload: base64.StdEncoding.EncodeToString([]byte(tampered)), Signature: env.Signature}
	if _, err := VerifyEnvelope(bad, pubB64); err == nil {
		t.Error("tampered payload accepted")
	}
	// wrong key
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifyEnvelope(env, base64.StdEncoding.EncodeToString(other)); err == nil {
		t.Error("wrong key accepted")
	}
	if _, err := VerifyEnvelope(env, "garbage"); err == nil {
		t.Error("garbage key accepted")
	}
}

func TestValidate(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	future := "2026-01-01 13:00:00.123456+00:00" // Python str(datetime) format
	past := "2026-01-01T11:00:00Z"
	cases := []struct {
		t    Task
		ok   bool
		name string
	}{
		{Task{ID: "1", AgentID: "a", Action: "collect"}, true, "ok"},
		{Task{ID: "1", AgentID: "a", Action: "patch", ExpiresAt: &future}, true, "python time"},
		{Task{ID: "1", AgentID: "b", Action: "collect"}, false, "wrong agent"},
		{Task{ID: "1", AgentID: "a", Action: "shell"}, false, "bad action"},
		{Task{ID: "1", AgentID: "a", Action: "collect", ExpiresAt: &past}, false, "expired"},
		{Task{AgentID: "a", Action: "collect"}, false, "no id"},
	}
	for _, c := range cases {
		err := Validate(&c.t, "a", now)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v", c.name, err)
		}
	}
}

func TestPatchCommands(t *testing.T) {
	c, _ := PatchCommands("apt-get", false, []string{"openssl", "libssl3"}, true)
	if strings.Join(c[1], " ") != "apt-get install -s --only-upgrade -y -q openssl libssl3" {
		t.Errorf("apt dry: %v", c)
	}
	c, _ = PatchCommands("apt-get", true, nil, false)
	if c[1][1] != "upgrade" || !strings.Contains(strings.Join(c[1], " "), "--force-confold") {
		t.Errorf("apt all: %v", c)
	}
	c, _ = PatchCommands("dnf", false, []string{"openssl"}, true)
	if strings.Join(c[0], " ") != "dnf upgrade --assumeno openssl" {
		t.Errorf("dnf dry: %v", c)
	}
	c, _ = PatchCommands("apk", false, []string{"musl"}, true)
	if strings.Join(c[1], " ") != "apk add --simulate -u musl" {
		t.Errorf("apk: %v", c)
	}
	if _, err := PatchCommands("pacman", false, nil, false); err == nil {
		t.Error("unknown manager accepted")
	}
}

// fakeServer records task results.
type fakeServer struct {
	mu      sync.Mutex
	results map[string]client.TaskResult
}

func TestExecutorEndToEnd(t *testing.T) {
	pub, sk, _ := ed25519.GenerateKey(rand.Reader)
	fs := &fakeServer{results: map[string]client.TaskResult{}}
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	envs := []client.Envelope{
		sign(t, sk, map[string]any{"id": "t-patch", "agent_id": "agt_1", "action": "patch", "params": map[string]any{"packages": []string{"openssl"}}, "dry_run": true, "expires_at": exp}),
		sign(t, sk, map[string]any{"id": "t-badname", "agent_id": "agt_1", "action": "collect", "expires_at": exp}),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer agt_1:key" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.URL.Path == "/api/v1/agent/tasks":
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": envs})
		case strings.HasSuffix(r.URL.Path, "/result"):
			var res client.TaskResult
			_ = json.NewDecoder(r.Body).Decode(&res)
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/agent/tasks/"), "/result")
			fs.mu.Lock()
			fs.results[id] = res
			fs.mu.Unlock()
		}
	}))
	defer srv.Close()
	cl, _ := client.New(srv.URL, "test", client.Options{})
	cl.AgentID, cl.AgentKey = "agt_1", "key"
	collected := 0
	ex := &Executor{AgentID: "agt_1", ServerPubKey: base64.StdEncoding.EncodeToString(pub), AllowPatching: false,
		StateDir: t.TempDir(), Client: cl, OnCollect: func(context.Context) error { collected++; return nil }}
	if err := ex.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := fs.results["t-patch"]; r.Status != "rejected" || !strings.Contains(r.Output, "local policy") {
		t.Errorf("patch without local permission should be rejected: %+v", r)
	}
	if r := fs.results["t-badname"]; r.Status != "succeeded" || collected != 1 {
		t.Errorf("collect: %+v collected=%d", r, collected)
	}
	// replay: same envelopes again must not execute twice
	fs.results = map[string]client.TaskResult{}
	_ = ex.Poll(context.Background())
	if len(fs.results) != 0 || collected != 1 {
		t.Errorf("replayed tasks were executed: %v collected=%d", fs.results, collected)
	}
	// invalid package names are rejected even when patching is allowed
	ex2 := &Executor{AgentID: "agt_1", ServerPubKey: base64.StdEncoding.EncodeToString(pub), AllowPatching: true,
		StateDir: t.TempDir(), Client: cl}
	envs = []client.Envelope{sign(t, sk, map[string]any{"id": "t-inject", "agent_id": "agt_1", "action": "patch",
		"params": map[string]any{"packages": []string{"openssl; rm -rf /"}}, "dry_run": true})}
	_ = ex2.Poll(context.Background())
	if r := fs.results["t-inject"]; r.Status != "rejected" || !strings.Contains(r.Output, "invalid package name") {
		t.Errorf("injection attempt: %+v", r)
	}
}
