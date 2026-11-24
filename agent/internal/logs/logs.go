// Package logs tails local security logs and ships them to the server.
//
// Sources (from server config or local override):
//   - absolute file path: tailed (e.g. /var/log/auth.log -> source "auth.log")
//   - "journald": journalctl -f -o json, security identifiers only (or only
//     kernel messages when auth.log/secure files are also tailed, to avoid
//     duplicates); "journald:all" ships everything
//   - "windows": Security + System event logs via wevtutil (Windows only)
//
// Offsets are persisted so restarts neither replay nor skip much. On first
// sight of a file the tailer starts at the end (no historical backfill).
package logs

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/603madison/superawesomemagicalsecurity/agent/internal/client"
)

// Line is one log line to ship.
type Line = client.LogLine

// State is persisted between runs.
type State struct {
	mu        sync.Mutex
	path      string
	Files     map[string]FileState `json:"files"`
	WinRecord map[string]uint64    `json:"win_record"` // channel -> last EventRecordID
}

type FileState struct {
	ID     uint64 `json:"id"` // inode (unix)
	Offset int64  `json:"offset"`
}

func LoadState(path string) *State {
	s := &State{path: path, Files: map[string]FileState{}, WinRecord: map[string]uint64{}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, s)
		if s.Files == nil {
			s.Files = map[string]FileState{}
		}
		if s.WinRecord == nil {
			s.WinRecord = map[string]uint64{}
		}
	}
	return s
}

func (s *State) Save() error {
	s.mu.Lock()
	b, err := json.Marshal(s)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *State) getFile(p string) (FileState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.Files[p]
	return v, ok
}

func (s *State) setFile(p string, fs FileState) {
	s.mu.Lock()
	s.Files[p] = fs
	s.mu.Unlock()
}

// SourceName maps a path to the source name the server's parsers expect.
func SourceName(path string) string {
	switch filepath.Base(path) {
	case "auth.log":
		return "auth.log"
	case "secure":
		return "secure"
	}
	return filepath.Base(path)
}

// Shipper fans in all sources and posts batches.
type Shipper struct {
	Client   *client.Client
	State    *State
	Hostname string
	Interval time.Duration
	MaxBatch int
	MaxBuf   int
}

// Run starts all sources and ships until ctx is cancelled.
func (s *Shipper) Run(ctx context.Context, sources []string) {
	if s.Interval == 0 {
		s.Interval = 10 * time.Second
	}
	if s.MaxBatch == 0 {
		s.MaxBatch = 500
	}
	if s.MaxBuf == 0 {
		s.MaxBuf = 20000
	}
	ch := make(chan Line, 4096)
	emit := func(l Line) {
		select {
		case ch <- l:
		case <-ctx.Done():
		}
	}
	authFilePresent := false
	for _, src := range sources {
		if filepath.IsAbs(src) {
			if _, err := os.Stat(src); err == nil && (SourceName(src) == "auth.log" || SourceName(src) == "secure") {
				authFilePresent = true
			}
		}
	}
	for _, src := range sources {
		src := src
		switch {
		case src == "journald" || src == "journald:all":
			if runtime.GOOS != "linux" {
				continue
			}
			mode := JournalSecurity
			if src == "journald:all" {
				mode = JournalAll
			} else if authFilePresent {
				mode = JournalKernelOnly
			}
			go RunJournald(ctx, mode, emit)
		case src == "windows":
			if runtime.GOOS != "windows" {
				continue
			}
			go RunWindowsEvents(ctx, s.State, emit)
		case filepath.IsAbs(src):
			t := &FileTailer{Path: src, Source: SourceName(src), State: s.State}
			go t.Run(ctx, emit)
		default:
			log.Printf("logs: ignoring unknown source %q", src)
		}
	}

	var buf []Line
	tick := time.NewTicker(s.Interval)
	defer tick.Stop()
	flush := func() {
		for len(buf) > 0 {
			n := len(buf)
			if n > s.MaxBatch {
				n = s.MaxBatch
			}
			pctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := s.Client.PostLogs(pctx, buf[:n])
			cancel()
			if err != nil {
				log.Printf("logs: ship failed (%d buffered): %v", len(buf), err)
				return
			}
			buf = buf[n:]
		}
		if err := s.State.Save(); err != nil {
			log.Printf("logs: save state: %v", err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case l := <-ch:
			buf = append(buf, l)
			if len(buf) > s.MaxBuf {
				buf = buf[len(buf)-s.MaxBuf:] // drop oldest under sustained outage
			}
			if len(buf) >= s.MaxBatch {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}
