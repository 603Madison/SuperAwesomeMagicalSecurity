// Package collect gathers host facts into a model.Inventory.
//
// Each collector runs isolated: a failure (or panic) is recorded in
// Inventory.Errors and collection continues. Platform-specific collectors
// live in linux.go / darwin.go / windows.go.
package collect

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/603madison/superawesomemagicalsecurity/agent/internal/model"
)

type Options struct {
	AgentVersion   string
	SensitivePaths []string
	// Timeout bounds the whole collection.
	Timeout time.Duration
}

type collector struct {
	inv *model.Inventory
	opt Options
	ctx context.Context
}

func (c *collector) errf(format string, a ...any) {
	if len(c.inv.Errors) < 200 {
		c.inv.Errors = append(c.inv.Errors, fmt.Sprintf(format, a...))
	}
}

// step runs fn, converting panics into recorded errors.
func (c *collector) step(name string, fn func() error) {
	defer func() {
		if r := recover(); r != nil {
			c.errf("%s: panic: %v", name, r)
		}
	}()
	if c.ctx.Err() != nil {
		c.errf("%s: skipped: %v", name, c.ctx.Err())
		return
	}
	if err := fn(); err != nil {
		c.errf("%s: %v", name, err)
	}
}

// run executes a command with the collector's context and a per-command timeout.
func (c *collector) run(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(c.ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	return cmd.Output()
}

// Collect gathers a full inventory of the local host.
func Collect(ctx context.Context, opt Options) *model.Inventory {
	if opt.Timeout == 0 {
		opt.Timeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	hn, _ := os.Hostname()
	inv := &model.Inventory{
		SchemaVersion: 1,
		AgentVersion:  opt.AgentVersion,
		CollectedAt:   time.Now().UTC(),
		Host:          model.HostInfo{Hostname: hn, Arch: runtime.GOARCH, OS: model.OSInfo{Family: runtime.GOOS}},
	}
	c := &collector{inv: inv, opt: opt, ctx: ctx}
	c.step("interfaces", c.collectInterfaces)
	c.step("fqdn", c.collectFQDN)
	collectPlatform(c)
	c.step("sensitive_paths", c.collectSensitivePaths)
	c.finalize()
	return inv
}

func (c *collector) collectInterfaces() error {
	ifs, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, i := range ifs {
		iface := model.Interface{Name: i.Name, MAC: i.HardwareAddr.String(), Up: i.Flags&net.FlagUp != 0}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				iface.Addresses = append(iface.Addresses, ipn.String())
			}
		}
		c.inv.Interfaces = append(c.inv.Interfaces, iface)
	}
	return nil
}

func (c *collector) collectFQDN() error {
	h := c.inv.Host.Hostname
	if h == "" {
		return nil
	}
	if strings.Contains(h, ".") {
		c.inv.Host.FQDN = h
		return nil
	}
	ctx, cancel := context.WithTimeout(c.ctx, 2*time.Second)
	defer cancel()
	if cname, err := net.DefaultResolver.LookupCNAME(ctx, h); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if strings.Contains(cname, ".") {
			c.inv.Host.FQDN = cname
		}
	}
	return nil
}

func (c *collector) collectSensitivePaths() error {
	for _, p := range c.opt.SensitivePaths {
		if st, err := os.Stat(p); err == nil {
			c.inv.Datastores = append(c.inv.Datastores, model.Datastore{
				Kind: "files", Name: p, Path: p, Sensitivity: "confidential",
				Details: map[string]any{"configured": true, "is_dir": st.IsDir()},
			})
		}
	}
	return nil
}

// finalize de-duplicates and sorts for stable output.
func (c *collector) finalize() {
	inv := c.inv
	sort.SliceStable(inv.Listeners, func(i, j int) bool {
		if inv.Listeners[i].Port != inv.Listeners[j].Port {
			return inv.Listeners[i].Port < inv.Listeners[j].Port
		}
		return inv.Listeners[i].Proto < inv.Listeners[j].Proto
	})
	seen := map[string]bool{}
	var ls []model.Listener
	for _, l := range inv.Listeners {
		k := fmt.Sprintf("%s|%s|%d", l.Proto, l.Address, l.Port)
		if !seen[k] {
			seen[k] = true
			ls = append(ls, l)
		}
	}
	inv.Listeners = ls
	sort.SliceStable(inv.Packages, func(i, j int) bool {
		if inv.Packages[i].Manager != inv.Packages[j].Manager {
			return inv.Packages[i].Manager < inv.Packages[j].Manager
		}
		return inv.Packages[i].Name < inv.Packages[j].Name
	})
	if len(inv.Connections) > 2000 {
		inv.Connections = inv.Connections[:2000]
	}
}
