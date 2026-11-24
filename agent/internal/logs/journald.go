package logs

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type JournalMode int

const (
	JournalSecurity   JournalMode = iota // auth-relevant identifiers + kernel
	JournalKernelOnly                    // kernel only (auth file tailed separately)
	JournalAll
)

// securityIdentifiers are the syslog identifiers shipped in security mode.
var securityIdentifiers = []string{
	"sshd", "sshd-session", "sudo", "su", "useradd", "userdel", "usermod", "groupadd", "groupdel", "groupmod",
	"gpasswd", "passwd", "chpasswd", "chage", "login", "systemd-logind", "polkitd", "pkexec", "CRON", "crond",
	"dbus-daemon", "audit", "auditd", "unix_chkpwd", "doas", "fail2ban-server", "sams-agent",
}

// JournalArgs returns the journalctl arguments for a mode.
func JournalArgs(mode JournalMode) []string {
	args := []string{"-f", "-o", "json", "--since", "now", "--no-pager"}
	switch mode {
	case JournalSecurity:
		for _, id := range securityIdentifiers {
			args = append(args, "SYSLOG_IDENTIFIER="+id)
		}
		args = append(args, "+", "_TRANSPORT=kernel")
	case JournalKernelOnly:
		args = append(args, "_TRANSPORT=kernel")
	}
	return args
}

// journalString decodes a journald JSON field that may be a string or an
// array of byte values (non-UTF-8 data).
func journalString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		b := make([]byte, 0, len(t))
		for _, x := range t {
			if f, ok := x.(float64); ok {
				b = append(b, byte(f))
			}
		}
		return string(b)
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

// FormatJournalEntry reconstructs a syslog-style line:
// "<RFC3339 ts> <host> <ident>[<pid>]: <message>".
func FormatJournalEntry(m map[string]any) (string, time.Time, bool) {
	msg := journalString(m["MESSAGE"])
	if msg == "" {
		return "", time.Time{}, false
	}
	ts := time.Now().UTC()
	if us, err := strconv.ParseInt(journalString(m["__REALTIME_TIMESTAMP"]), 10, 64); err == nil {
		ts = time.UnixMicro(us).UTC()
	}
	host := journalString(m["_HOSTNAME"])
	if host == "" {
		host = "localhost"
	}
	ident := journalString(m["SYSLOG_IDENTIFIER"])
	if ident == "" {
		ident = journalString(m["_COMM"])
	}
	if ident == "" && journalString(m["_TRANSPORT"]) == "kernel" {
		ident = "kernel"
	}
	if ident == "" {
		ident = "unknown"
	}
	pid := journalString(m["SYSLOG_PID"])
	if pid == "" {
		pid = journalString(m["_PID"])
	}
	msg = strings.ReplaceAll(msg, "\n", " ")
	var line string
	if pid != "" {
		line = fmt.Sprintf("%s %s %s[%s]: %s", ts.Format(time.RFC3339Nano), host, ident, pid, msg)
	} else {
		line = fmt.Sprintf("%s %s %s: %s", ts.Format(time.RFC3339Nano), host, ident, msg)
	}
	return line, ts, true
}

// RunJournald follows the journal and emits reconstructed lines, restarting
// journalctl with backoff if it exits.
func RunJournald(ctx context.Context, mode JournalMode, emit func(Line)) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return
	}
	backoff := 5 * time.Second
	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, "journalctl", JournalArgs(mode)...)
		out, err := cmd.StdoutPipe()
		if err != nil {
			return
		}
		if err := cmd.Start(); err != nil {
			log.Printf("journald: %v", err)
			return
		}
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 256*1024), 4*1024*1024)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) != nil {
				continue
			}
			if line, ts, ok := FormatJournalEntry(m); ok {
				if len(line) > maxLineLen {
					line = line[:maxLineLen]
				}
				emit(Line{Source: "journald", Line: line, TS: ts.Format(time.RFC3339Nano)})
			}
		}
		_ = cmd.Wait()
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 5*time.Minute {
			backoff *= 2
		}
	}
}
