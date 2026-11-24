package scope

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	cases := map[string][]int{
		"22":             {22},
		"80,443, 22":     {22, 80, 443},
		"1-3":            {1, 2, 3},
		"8000:8002,8001": {8000, 8001, 8002},
	}
	for in, want := range cases {
		got, err := ParsePorts(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%q: got %v want %v", in, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%q: got %v want %v", in, got, want)
			}
		}
	}
	for _, bad := range []string{"0", "70000", "abc", "10-5", "1-"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
	all, _ := ParsePorts("all")
	if len(all) != 65535 {
		t.Fatalf("all: %d", len(all))
	}
}

func TestTopLists(t *testing.T) {
	n100, n1000 := NmapTopCounts()
	if n100 != 100 {
		t.Errorf("nmap top100 has %d ports", n100)
	}
	if n1000 != 1000 {
		t.Errorf("nmap top1000 has %d ports", n1000)
	}
	for _, p := range []int{22, 443, 445, 3389, 6379, 2375, 9200, 10250, 27017, 11211} {
		found := false
		for _, q := range Top100 {
			if q == p {
				found = true
			}
		}
		if !found {
			t.Errorf("Top100 missing high-risk port %d", p)
		}
	}
	top, _ := ParsePorts("top100")
	if len(top) != len(Top100) {
		t.Errorf("ParsePorts(top100)=%d, Top100=%d", len(top), len(Top100))
	}
}

func TestDisallowed(t *testing.T) {
	bad := []string{"10.1.2.3", "192.168.1.1", "172.20.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1",
		"224.0.0.1", "0.0.0.0", "255.255.255.255", "240.0.0.1", "192.0.2.10", "::1", "fe80::1", "fd00::1",
		"2001:db8::1", "::ffff:10.0.0.1"}
	for _, s := range bad {
		if b, _ := Disallowed(net.ParseIP(s)); !b {
			t.Errorf("%s should be disallowed", s)
		}
	}
	good := []string{"8.8.8.8", "45.33.32.156", "1.1.1.1", "2606:4700:4700::1111"}
	for _, s := range good {
		if b, why := Disallowed(net.ParseIP(s)); b {
			t.Errorf("%s should be allowed: %s", s, why)
		}
	}
}

func fakeLookup(m map[string][]string) LookupFunc {
	return func(_ context.Context, host string) ([]net.IP, error) {
		v, ok := m[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []net.IP
		for _, s := range v {
			out = append(out, net.ParseIP(s))
		}
		return out, nil
	}
}

func TestExpand(t *testing.T) {
	lookup := fakeLookup(map[string][]string{
		"www.example.org":      {"2606:2800:220:1::1", "93.184.216.34"},
		"internal.example.org": {"10.0.0.5"},
		"rebind.example.org":   {"8.8.8.8", "192.168.0.1"},
	})
	targets, refused := Expand(context.Background(), []string{
		"https://www.example.org/path", "8.8.8.8", "45.33.32.0/30", "10.0.0.0/24",
		"internal.example.org", "rebind.example.org", "8.8.0.0/16", "not a host", "8.8.8.8:53",
		"nxdomain.example.org",
	}, false, lookup)
	hosts := map[string]Target{}
	for _, tg := range targets {
		hosts[tg.Host] = tg
	}
	if tg, ok := hosts["www.example.org"]; !ok || !tg.IsName || tg.IPs[0].String() != "93.184.216.34" {
		t.Errorf("www.example.org: %+v (IPv4 should be first)", tg)
	}
	for _, h := range []string{"8.8.8.8", "45.33.32.0", "45.33.32.3", "nxdomain.example.org"} {
		if _, ok := hosts[h]; !ok {
			t.Errorf("missing target %s; have %v", h, hosts)
		}
	}
	if len(targets) != 7 { // www, 8.8.8.8 (dedup), 4 from /30, nxdomain
		t.Errorf("targets=%d %v", len(targets), hosts)
	}
	reasons := map[string]string{}
	for _, r := range refused {
		reasons[r.Input] = r.Reason
	}
	for _, in := range []string{"internal.example.org", "rebind.example.org", "8.8.0.0/16", "not a host"} {
		if _, ok := reasons[in]; !ok {
			t.Errorf("expected refusal for %q; got %v", in, reasons)
		}
	}
	if !strings.Contains(reasons["8.8.0.0/16"], "max 256") {
		t.Errorf("cidr reason: %q", reasons["8.8.0.0/16"])
	}
	// 10.0.0.0/24 expands but every address is refused
	n := 0
	for in := range reasons {
		if strings.HasPrefix(in, "10.0.0.") {
			n++
		}
	}
	if n != 256 {
		t.Errorf("expected 256 refused 10.0.0.x, got %d", n)
	}
	// allowPrivate permits them
	targets, refused = Expand(context.Background(), []string{"127.0.0.1", "internal.example.org"}, true, lookup)
	if len(targets) != 2 || len(refused) != 0 {
		t.Errorf("allowPrivate: %v %v", targets, refused)
	}
}

func signedEnvelope(t *testing.T, sk ed25519.PrivateKey, payload any) Envelope {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return Envelope{
		Payload:   base64.StdEncoding.EncodeToString(raw),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(sk, raw)),
		KeyID:     "test",
	}
}

func TestOpenJob(t *testing.T) {
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	pkB64 := base64.StdEncoding.EncodeToString(pk)
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	job := map[string]any{"job_id": "job_1", "probe_id": "prb_a", "targets": []string{"example.org"},
		"ports": []int{22, 443}, "checks": []string{"tcp"}, "rate_per_sec": 50,
		"expires_at": "2026-11-24 18:00:00+00:00"} // Python str(datetime) form
	env := signedEnvelope(t, sk, job)

	j, err := OpenJob(env, pkB64, "prb_a", now)
	if err != nil {
		t.Fatal(err)
	}
	if j.JobID != "job_1" || j.RatePerSec != 50 || len(j.Ports) != 2 || j.Expiry().Hour() != 18 {
		t.Fatalf("bad job %+v", j)
	}
	if _, err := OpenJob(env, pkB64, "prb_other", now); err == nil {
		t.Error("wrong probe id accepted")
	}
	if _, err := OpenJob(env, pkB64, "prb_a", now.Add(7*time.Hour)); err == nil {
		t.Error("expired job accepted")
	}
	// tampered payload
	tampered := env
	raw, _ := base64.StdEncoding.DecodeString(env.Payload)
	raw = []byte(strings.Replace(string(raw), "example.org", "victim.example", 1))
	tampered.Payload = base64.StdEncoding.EncodeToString(raw)
	if _, err := OpenJob(tampered, pkB64, "prb_a", now); err == nil {
		t.Error("tampered payload accepted")
	}
	// signed by a different key
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := OpenJob(signedEnvelope(t, other, job), pkB64, "prb_a", now); err == nil {
		t.Error("foreign signature accepted")
	}
	// bad port
	job["ports"] = []int{0}
	if _, err := OpenJob(signedEnvelope(t, sk, job), pkB64, "prb_a", now); err == nil {
		t.Error("invalid port accepted")
	}
}

func TestParseTime(t *testing.T) {
	for _, s := range []string{"2026-11-24T18:00:00Z", "2026-11-24T18:00:00.123456+00:00",
		"2026-11-24 18:00:00+00:00", "2026-11-24 18:00:00.5"} {
		if _, err := ParseTime(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
}
