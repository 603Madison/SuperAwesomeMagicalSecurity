//go:build !linux && !darwin && !windows

package collect

// Unsupported platforms (e.g. FreeBSD) get the portable collectors only.
func collectPlatform(c *collector) {
	c.errf("platform collectors not implemented for this OS")
}
