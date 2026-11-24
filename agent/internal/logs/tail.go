package logs

import (
	"bytes"
	"context"
	"io"
	"os"
	"time"
)

// FileTailer follows a log file across rotations.
type FileTailer struct {
	Path   string
	Source string
	State  *State
	Poll   time.Duration
}

const maxLineLen = 16 * 1024

func (t *FileTailer) Run(ctx context.Context, emit func(Line)) {
	if t.Poll == 0 {
		t.Poll = 2 * time.Second
	}
	tick := time.NewTicker(t.Poll)
	defer tick.Stop()
	for {
		t.pollOnce(emit)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// pollOnce reads any complete new lines. Exported behaviour is tested via
// ReadNew.
func (t *FileTailer) pollOnce(emit func(Line)) {
	lines, _ := t.ReadNew()
	for _, l := range lines {
		emit(Line{Source: t.Source, Line: l})
	}
}

// ReadNew returns complete lines appended since the last call, handling
// rotation (inode change) and truncation (size < offset).
func (t *FileTailer) ReadNew() ([]string, error) {
	f, err := os.Open(t.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	id := fileID(st)
	prev, known := t.State.getFile(t.Path)
	switch {
	case !known:
		// first sight: start at the end, no historical backfill
		t.State.setFile(t.Path, FileState{ID: id, Offset: st.Size()})
		return nil, nil
	case prev.ID != id || st.Size() < prev.Offset:
		prev = FileState{ID: id, Offset: 0} // rotated or truncated
	}
	if st.Size() == prev.Offset {
		t.State.setFile(t.Path, prev)
		return nil, nil
	}
	if _, err := f.Seek(prev.Offset, io.SeekStart); err != nil {
		return nil, err
	}
	// cap a single read to 8 MiB to bound memory after long outages
	data, err := io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil {
		return nil, err
	}
	last := bytes.LastIndexByte(data, '\n')
	if last < 0 {
		if len(data) >= 8<<20 { // pathological: no newline in 8 MiB
			prev.Offset += int64(len(data))
			t.State.setFile(t.Path, prev)
		}
		return nil, nil
	}
	chunk := data[:last]
	prev.Offset += int64(last + 1)
	t.State.setFile(t.Path, prev)
	var out []string
	for _, l := range bytes.Split(chunk, []byte("\n")) {
		l = bytes.TrimRight(l, "\r")
		if len(l) == 0 {
			continue
		}
		if len(l) > maxLineLen {
			l = l[:maxLineLen]
		}
		out = append(out, string(l))
	}
	return out, nil
}
