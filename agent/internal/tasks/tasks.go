// Package tasks verifies and executes server-issued tasks.
//
// Defense in depth:
//  1. Ed25519 signature over the exact payload bytes, checked against the
//     server key pinned at enrollment, BEFORE the payload is parsed.
//  2. agent_id must match, expires_at must be in the future.
//  3. Action allowlist; there is no "run command" action.
//  4. patch / patch_all additionally require allow_patching in the LOCAL config.
//  5. Package names are validated and passed as argv (never via a shell).
//  6. Executed task IDs are recorded to prevent replay.
package tasks

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/603madison/superawesomemagicalsecurity/agent/internal/client"
)

// Task is the signed payload.
type Task struct {
	ID        string          `json:"id"`
	AgentID   string          `json:"agent_id"`
	Action    string          `json:"action"`
	Params    json.RawMessage `json:"params"`
	DryRun    bool            `json:"dry_run"`
	ExpiresAt *string         `json:"expires_at"`
}

var allowedActions = map[string]bool{"collect": true, "patch": true, "patch_all": true, "reboot_required_check": true}

var pkgNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_:~-]{0,127}$`)

// VerifyEnvelope checks the signature and returns the raw payload bytes.
func VerifyEnvelope(env client.Envelope, pubB64 string) ([]byte, error) {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid pinned server public key")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("payload encoding: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return nil, errors.New("signature verification failed")
	}
	return payload, nil
}

// parseTime accepts RFC3339 and Python's str(datetime) ("2026-01-02 15:04:05.123456+00:00").
func parseTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable time %q", s)
}

// Validate checks the decoded task against local policy (not patch permission).
func Validate(t *Task, agentID string, now time.Time) error {
	if t.ID == "" {
		return errors.New("missing task id")
	}
	if t.AgentID != agentID {
		return fmt.Errorf("task for agent %q, not us", t.AgentID)
	}
	if !allowedActions[t.Action] {
		return fmt.Errorf("action %q not allowed", t.Action)
	}
	if t.ExpiresAt != nil && *t.ExpiresAt != "" {
		exp, err := parseTime(*t.ExpiresAt)
		if err != nil {
			return err
		}
		if now.After(exp) {
			return errors.New("task expired")
		}
	}
	return nil
}

// Executor runs tasks.
type Executor struct {
	AgentID       string
	ServerPubKey  string
	AllowPatching bool
	StateDir      string
	Client        *client.Client
	// OnCollect is invoked for the "collect" action.
	OnCollect func(ctx context.Context) error

	mu   sync.Mutex
	done map[string]time.Time
}

func (e *Executor) donePath() string { return filepath.Join(e.StateDir, "tasks_done.json") }

func (e *Executor) loadDone() {
	if e.done != nil {
		return
	}
	e.done = map[string]time.Time{}
	if b, err := os.ReadFile(e.donePath()); err == nil {
		_ = json.Unmarshal(b, &e.done)
	}
}

func (e *Executor) markDone(id string) {
	e.done[id] = time.Now()
	// prune to the newest 2000
	if len(e.done) > 2000 {
		cutoff := time.Now().Add(-90 * 24 * time.Hour)
		for k, v := range e.done {
			if v.Before(cutoff) {
				delete(e.done, k)
			}
		}
	}
	if b, err := json.Marshal(e.done); err == nil {
		_ = os.WriteFile(e.donePath(), b, 0o600)
	}
}

// Poll fetches and handles pending tasks.
func (e *Executor) Poll(ctx context.Context) error {
	envs, err := e.Client.GetTasks(ctx)
	if err != nil {
		return err
	}
	for _, env := range envs {
		e.Handle(ctx, env)
	}
	return nil
}

// Handle verifies and executes a single envelope, reporting the result.
// Unverifiable envelopes are dropped without being reported (we cannot
// trust their task id).
func (e *Executor) Handle(ctx context.Context, env client.Envelope) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.loadDone()
	payload, err := VerifyEnvelope(env, e.ServerPubKey)
	if err != nil {
		logf("task rejected: %v", err)
		return
	}
	var t Task
	if err := json.Unmarshal(payload, &t); err != nil {
		logf("task rejected: bad payload: %v", err)
		return
	}
	if _, seen := e.done[t.ID]; seen {
		logf("task %s already executed; ignoring replay", t.ID)
		return
	}
	res := e.execute(ctx, &t)
	e.markDone(t.ID)
	if len(res.Output) > 64*1024 {
		res.Output = res.Output[len(res.Output)-64*1024:]
	}
	rctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := e.Client.PostTaskResult(rctx, t.ID, res); err != nil {
		logf("task %s: report result: %v", t.ID, err)
	}
}

func (e *Executor) execute(ctx context.Context, t *Task) client.TaskResult {
	if err := Validate(t, e.AgentID, time.Now()); err != nil {
		return client.TaskResult{Status: "rejected", Output: err.Error()}
	}
	switch t.Action {
	case "collect":
		if e.OnCollect == nil {
			return client.TaskResult{Status: "failed", Output: "collect not wired"}
		}
		if err := e.OnCollect(ctx); err != nil {
			return client.TaskResult{Status: "failed", Output: err.Error()}
		}
		return client.TaskResult{Status: "succeeded", Output: "inventory collected and submitted"}
	case "reboot_required_check":
		return rebootCheck()
	case "patch", "patch_all":
		if !e.AllowPatching {
			return client.TaskResult{Status: "rejected",
				Output: "patching disabled by local policy (set allow_patching: true in the agent config to permit)"}
		}
		var p struct {
			Manager  string   `json:"manager"`
			Packages []string `json:"packages"`
		}
		if len(t.Params) > 0 {
			if err := json.Unmarshal(t.Params, &p); err != nil {
				return client.TaskResult{Status: "rejected", Output: "bad params: " + err.Error()}
			}
		}
		if t.Action == "patch" {
			if len(p.Packages) == 0 {
				return client.TaskResult{Status: "rejected", Output: "no packages specified"}
			}
			if len(p.Packages) > 500 {
				return client.TaskResult{Status: "rejected", Output: "too many packages"}
			}
			for _, n := range p.Packages {
				if !pkgNameRe.MatchString(n) {
					return client.TaskResult{Status: "rejected", Output: fmt.Sprintf("invalid package name %q", n)}
				}
			}
		}
		mgr := DetectManager(p.Manager)
		if mgr == "" {
			return client.TaskResult{Status: "failed", Output: "no supported package manager found"}
		}
		cmds, err := PatchCommands(mgr, t.Action == "patch_all", p.Packages, t.DryRun)
		if err != nil {
			return client.TaskResult{Status: "failed", Output: err.Error()}
		}
		return runCommands(ctx, cmds, map[string]any{"manager": mgr, "dry_run": t.DryRun, "packages": p.Packages})
	}
	return client.TaskResult{Status: "rejected", Output: "unknown action"}
}

// managerAliases maps server hints (inventory manager names) to binaries.
var managerAliases = map[string]string{"dpkg": "apt-get", "apt": "apt-get", "rpm": "", "yum": "yum", "dnf": "dnf",
	"apk": "apk", "zypper": "zypper", "brew": "brew", "windows": "winget", "winget": "winget"}

// DetectManager picks the package manager binary, preferring the hint.
func DetectManager(hint string) string {
	if b, ok := managerAliases[strings.ToLower(hint)]; ok && b != "" {
		if _, err := exec.LookPath(b); err == nil {
			return b
		}
	}
	order := []string{"apt-get", "dnf", "yum", "zypper", "apk"}
	switch runtime.GOOS {
	case "darwin":
		order = []string{"brew"}
	case "windows":
		order = []string{"winget"}
	}
	for _, b := range order {
		if _, err := exec.LookPath(b); err == nil {
			return b
		}
	}
	return ""
}

// PatchCommands builds argv lists (never shell strings) for a patch run.
func PatchCommands(mgr string, all bool, pkgs []string, dry bool) ([][]string, error) {
	switch mgr {
	case "apt-get":
		upd := []string{"apt-get", "update", "-q"}
		var run []string
		if all {
			run = []string{"apt-get", "upgrade", "-y", "-q"}
		} else {
			run = append([]string{"apt-get", "install", "--only-upgrade", "-y", "-q"}, pkgs...)
		}
		if dry {
			run = append(run[:2:2], append([]string{"-s"}, run[2:]...)...)
		} else {
			run = append(run[:2:2], append([]string{"-o", "Dpkg::Options::=--force-confold"}, run[2:]...)...)
		}
		return [][]string{upd, run}, nil
	case "dnf", "yum":
		var run []string
		if all {
			run = []string{mgr, "upgrade", "-y", "--security"}
		} else {
			run = append([]string{mgr, "upgrade", "-y"}, pkgs...)
		}
		if dry {
			run[2] = "--assumeno"
		}
		return [][]string{run}, nil
	case "zypper":
		var run []string
		if all {
			run = []string{"zypper", "--non-interactive", "patch"}
		} else {
			run = append([]string{"zypper", "--non-interactive", "update"}, pkgs...)
		}
		if dry {
			run = append(run, "--dry-run")
		}
		return [][]string{run}, nil
	case "apk":
		var run []string
		if all {
			run = []string{"apk", "upgrade"}
		} else {
			run = append([]string{"apk", "add", "-u"}, pkgs...)
		}
		if dry {
			run = append(run[:2:2], append([]string{"--simulate"}, run[2:]...)...)
		}
		return [][]string{{"apk", "update"}, run}, nil
	case "brew":
		if os.Geteuid() == 0 {
			return nil, errors.New("homebrew refuses to run as root; patch manually")
		}
		run := append([]string{"brew", "upgrade"}, pkgs...)
		if dry {
			run = append(run, "--dry-run")
		}
		return [][]string{run}, nil
	case "winget":
		common := []string{"--silent", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity"}
		if dry {
			return [][]string{{"winget", "upgrade", "--include-unknown"}}, nil
		}
		if all {
			return [][]string{append([]string{"winget", "upgrade", "--all"}, common...)}, nil
		}
		var cmds [][]string
		for _, p := range pkgs {
			cmds = append(cmds, append([]string{"winget", "upgrade", "--id", p, "--exact"}, common...))
		}
		return cmds, nil
	}
	return nil, fmt.Errorf("unsupported manager %q", mgr)
}

func runCommands(ctx context.Context, cmds [][]string, details map[string]any) client.TaskResult {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	var out strings.Builder
	var runs []map[string]any
	for _, argv := range cmds {
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a", "LC_ALL=C")
		b, err := cmd.CombinedOutput()
		fmt.Fprintf(&out, "$ %s\n%s\n", strings.Join(argv, " "), b)
		code := 0
		if err != nil {
			code = -1
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			}
		}
		runs = append(runs, map[string]any{"argv": argv, "exit_code": code})
		if err != nil {
			details["runs"] = runs
			return client.TaskResult{Status: "failed", Output: out.String(), Details: details}
		}
	}
	details["runs"] = runs
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		details["reboot_required"] = true
	}
	return client.TaskResult{Status: "succeeded", Output: out.String(), Details: details}
}

func rebootCheck() client.TaskResult {
	d := map[string]any{"reboot_required": false}
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		d["reboot_required"] = true
		if b, err := os.ReadFile("/var/run/reboot-required.pkgs"); err == nil {
			d["packages"] = strings.Fields(string(b))
		}
	} else if p, err := exec.LookPath("needs-restarting"); err == nil {
		if err := exec.Command(p, "-r").Run(); err != nil {
			d["reboot_required"] = true
		}
	}
	return client.TaskResult{Status: "succeeded", Output: fmt.Sprintf("reboot_required=%v", d["reboot_required"]), Details: d}
}

var logf = func(format string, a ...any) { fmt.Fprintf(os.Stderr, "sams-agent: "+format+"\n", a...) }
