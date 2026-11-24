package logs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatJournalEntry(t *testing.T) {
	m := map[string]any{
		"__REALTIME_TIMESTAMP": "1732456800123456",
		"_HOSTNAME":            "web1",
		"SYSLOG_IDENTIFIER":    "sshd",
		"_PID":                 "4242",
		"MESSAGE":              "Failed password for root from 203.0.113.9 port 51234 ssh2",
	}
	line, ts, ok := FormatJournalEntry(m)
	if !ok {
		t.Fatal("not ok")
	}
	want := "2024-11-24T14:00:00.123456Z web1 sshd[4242]: Failed password for root from 203.0.113.9 port 51234 ssh2"
	if line != want {
		t.Errorf("got  %q\nwant %q", line, want)
	}
	if ts.Unix() != 1732456800 {
		t.Errorf("ts: %v", ts)
	}
	// byte-array MESSAGE and kernel transport without identifier/pid
	k := map[string]any{"__REALTIME_TIMESTAMP": "1732456800000000", "_HOSTNAME": "fw", "_TRANSPORT": "kernel",
		"MESSAGE": []any{float64('h'), float64('i')}}
	line, _, ok = FormatJournalEntry(k)
	if !ok || line != "2024-11-24T14:00:00Z fw kernel: hi" {
		t.Errorf("kernel line: %q", line)
	}
	if _, _, ok := FormatJournalEntry(map[string]any{}); ok {
		t.Errorf("empty message should be skipped")
	}
}

func TestJournalArgs(t *testing.T) {
	a := strings.Join(JournalArgs(JournalSecurity), " ")
	if !strings.Contains(a, "SYSLOG_IDENTIFIER=sshd") || !strings.Contains(a, "+ _TRANSPORT=kernel") {
		t.Errorf("security args: %s", a)
	}
	if strings.Contains(strings.Join(JournalArgs(JournalAll), " "), "SYSLOG_IDENTIFIER") {
		t.Errorf("all mode should not filter")
	}
}

func TestFileTailerRotation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.log")
	st := LoadState(filepath.Join(dir, "state.json"))
	_ = os.WriteFile(p, []byte("old line 1\nold line 2\n"), 0o644)
	tl := &FileTailer{Path: p, Source: SourceName(p), State: st}
	if l, _ := tl.ReadNew(); len(l) != 0 {
		t.Fatalf("first read should start at end, got %v", l)
	}
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("new 1\nnew 2\npartial")
	f.Close()
	l, _ := tl.ReadNew()
	if strings.Join(l, "|") != "new 1|new 2" {
		t.Errorf("append: %v", l)
	}
	f, _ = os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString(" done\n")
	f.Close()
	if l, _ := tl.ReadNew(); strings.Join(l, "|") != "partial done" {
		t.Errorf("partial completion: %v", l)
	}
	// rotate: move away and create new file
	_ = os.Rename(p, p+".1")
	_ = os.WriteFile(p, []byte("rotated 1\n"), 0o644)
	if l, _ := tl.ReadNew(); strings.Join(l, "|") != "rotated 1" {
		t.Errorf("rotation: %v", l)
	}
	// truncate in place
	_ = os.WriteFile(p, []byte("t\n"), 0o644)
	if l, _ := tl.ReadNew(); strings.Join(l, "|") != "t" {
		t.Errorf("truncate: %v", l)
	}
	// state persists
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	st2 := LoadState(filepath.Join(dir, "state.json"))
	if fs, ok := st2.Files[p]; !ok || fs.Offset != 2 {
		t.Errorf("persisted state: %+v", st2.Files)
	}
	if SourceName("/var/log/secure") != "secure" || SourceName("/var/log/syslog") != "syslog" {
		t.Errorf("source names")
	}
}

func TestParseWevtutilXML(t *testing.T) {
	x := `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><TimeCreated SystemTime='2024-11-24T14:00:00.000Z'/><EventRecordID>101</EventRecordID><Channel>Security</Channel><Computer>WS1</Computer></System><EventData><Data Name='TargetUserName'>admin</Data><Data Name='IpAddress'>203.0.113.9</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager'/><EventID Qualifiers='16384'>7045</EventID><TimeCreated SystemTime='2024-11-24T14:01:00.000Z'/><EventRecordID>102</EventRecordID><Channel>System</Channel><Computer>WS1</Computer></System><EventData><Data Name='ServiceName'>evil</Data></EventData></Event>`
	lines, max := ParseWevtutilXML([]byte(x))
	if len(lines) != 2 || max != 102 {
		t.Fatalf("lines=%d max=%d", len(lines), max)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(lines[0].Line), &obj); err != nil {
		t.Fatal(err)
	}
	if obj["EventID"].(float64) != 4625 || obj["Data"].(map[string]any)["IpAddress"] != "203.0.113.9" || lines[0].Source != "windows" {
		t.Errorf("event: %v", obj)
	}
}
