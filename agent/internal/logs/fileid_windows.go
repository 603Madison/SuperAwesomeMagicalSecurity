//go:build windows

package logs

import "os"

// Windows has no cheap inode via os.FileInfo; rotation is detected by
// truncation (size < offset) only.
func fileID(st os.FileInfo) uint64 { return 0 }
