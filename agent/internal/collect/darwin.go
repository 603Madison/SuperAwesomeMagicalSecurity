//go:build darwin

package collect

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/603madison/superawesomemagicalsecurity/agent/internal/model"
)

// macOS collectors are best effort.
func collectPlatform(c *collector) {
	c.step("os", c.darwinOS)
	c.step("packages", c.darwinPackages)
	var users []model.User
	c.step("users", func() error { var err error; users, err = c.darwinUsers(); return err })
	c.step("sudoers", func() error { return c.collectSudoers("/etc/sudoers") })
	c.step("user_artifacts", func() error { return c.collectUserArtifacts(users) })
	c.step("listeners", c.darwinListeners)
	c.step("hardening", c.darwinHardening)
}

func (c *collector) darwinOS() error {
	h := &c.inv.Host
	h.OS.Family, h.OS.ID = "darwin", "macos"
	if out, err := c.run(5*time.Second, "sw_vers"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			switch strings.TrimSpace(k) {
			case "ProductName":
				h.OS.Name = v
			case "ProductVersion":
				h.OS.VersionID, h.OS.Version = v, v
			}
		}
		h.OS.Pretty = strings.TrimSpace(h.OS.Name + " " + h.OS.VersionID)
	}
	if out, err := c.run(5*time.Second, "uname", "-r"); err == nil {
		h.Kernel = strings.TrimSpace(string(out))
	}
	if out, err := c.run(5*time.Second, "sysctl", "-n", "kern.boottime"); err == nil {
		if m := regexp.MustCompile(`sec = (\d+)`).FindSubmatch(out); m != nil {
			if sec, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
				h.UptimeSeconds = time.Now().Unix() - sec
			}
		}
	}
	if out, err := c.run(5*time.Second, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice"); err == nil {
		if m := regexp.MustCompile(`"IOPlatformUUID" = "([^"]+)"`).FindSubmatch(out); m != nil {
			h.MachineID = string(m[1])
		}
	}
	h.Virtualization = "none"
	return nil
}

var plistVersionRe = regexp.MustCompile(`<key>CFBundleShortVersionString</key>\s*<string>([^<]+)</string>`)
var plistNameRe = regexp.MustCompile(`<key>CFBundleName</key>\s*<string>([^<]+)</string>`)

func (c *collector) darwinPackages() error {
	// Homebrew cellars: <cellar>/<formula>/<version>
	for _, cellar := range []string{"/opt/homebrew/Cellar", "/usr/local/Cellar"} {
		formulas, err := os.ReadDir(cellar)
		if err != nil {
			continue
		}
		for _, f := range formulas {
			vers, _ := os.ReadDir(filepath.Join(cellar, f.Name()))
			for _, v := range vers {
				if v.IsDir() {
					c.inv.Packages = append(c.inv.Packages, model.Package{Name: f.Name(), Version: v.Name(), Manager: "brew", Location: cellar})
				}
			}
		}
	}
	apps, _ := filepath.Glob("/Applications/*.app/Contents/Info.plist")
	for _, p := range apps {
		b, err := os.ReadFile(p)
		if err != nil {
			continue // binary plists are skipped
		}
		vm := plistVersionRe.FindSubmatch(b)
		if vm == nil {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(filepath.Dir(filepath.Dir(p))), ".app")
		if nm := plistNameRe.FindSubmatch(b); nm != nil {
			name = string(nm[1])
		}
		c.inv.Packages = append(c.inv.Packages, model.Package{Name: name, Version: string(vm[1]), Manager: "macos_app", Location: p})
	}
	c.inv.Packages = append(c.inv.Packages, CollectPythonPackages([]string{
		"/Library/Frameworks/Python.framework/Versions/*/lib/python3*/site-packages",
		"/opt/homebrew/lib/python3*/site-packages", "/usr/local/lib/python3*/site-packages",
	}, 3000)...)
	c.inv.Packages = append(c.inv.Packages, CollectNpmGlobal([]string{"/opt/homebrew/lib/node_modules", "/usr/local/lib/node_modules"}, 1000)...)
	return nil
}

func (c *collector) darwinUsers() ([]model.User, error) {
	out, err := c.run(10*time.Second, "dscl", ".", "-list", "/Users", "UniqueID")
	if err != nil {
		return nil, err
	}
	admins := map[string]bool{}
	if g, err := c.run(5*time.Second, "dscl", ".", "-read", "/Groups/admin", "GroupMembership"); err == nil {
		for _, m := range strings.Fields(strings.TrimPrefix(strings.TrimSpace(string(g)), "GroupMembership:")) {
			admins[m] = true
		}
	}
	var users []model.User
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 || strings.HasPrefix(f[0], "_") {
			continue
		}
		uid, _ := strconv.Atoi(f[1])
		if uid != 0 && uid < 500 {
			continue
		}
		u := model.User{Name: f[0], UID: uid, GID: -1, PasswordState: "unknown", IsAdmin: uid == 0 || admins[f[0]]}
		if r, err := c.run(5*time.Second, "dscl", ".", "-read", "/Users/"+f[0], "NFSHomeDirectory", "UserShell", "PrimaryGroupID"); err == nil {
			for _, line := range strings.Split(string(r), "\n") {
				k, v, ok := strings.Cut(line, ":")
				if !ok {
					continue
				}
				v = strings.TrimSpace(v)
				switch k {
				case "NFSHomeDirectory":
					u.Home = v
				case "UserShell":
					u.Shell = v
				case "PrimaryGroupID":
					u.GID, _ = strconv.Atoi(v)
				}
			}
		}
		u.LoginEnabled = shellAllowsLogin(u.Shell)
		if u.IsAdmin {
			u.Groups = []string{"admin"}
		}
		users = append(users, u)
	}
	c.inv.Users = users
	return users, nil
}

// lsof -nP -iTCP -sTCP:LISTEN output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
func (c *collector) darwinListeners() error {
	out, err := c.run(15*time.Second, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
	if err != nil && len(out) == 0 {
		return err
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 9 {
			continue
		}
		name := f[8]
		i := strings.LastIndex(name, ":")
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(name[i+1:])
		if err != nil {
			continue
		}
		addr := strings.Trim(name[:i], "[]")
		if addr == "*" {
			addr = "0.0.0.0"
			if f[4] == "IPv6" {
				addr = "::"
			}
		}
		k := addr + ":" + name[i+1:]
		if seen[k] {
			continue
		}
		seen[k] = true
		pid, _ := strconv.Atoi(f[1])
		c.inv.Listeners = append(c.inv.Listeners, model.Listener{Proto: "tcp", Address: addr, Port: port, PID: pid, Process: f[0], User: f[2]})
	}
	return nil
}

func (c *collector) darwinHardening() error {
	h := &c.inv.Hardening
	h.SSHD = ParseSSHDConfig("/etc/ssh/sshd_config", "/etc/ssh", nil)
	if out, err := c.run(5*time.Second, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"); err == nil {
		on := strings.Contains(strings.ToLower(string(out)), "enabled")
		h.Firewall = model.HostFirewall{Enabled: model.BoolPtr(on), Backend: "alf"}
	}
	if out, err := c.run(10*time.Second, "fdesetup", "status"); err == nil {
		h.DiskEncryption = model.BoolPtr(strings.Contains(string(out), "FileVault is On"))
	}
	if out, err := c.run(5*time.Second, "defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"); err == nil {
		h.AutoUpdates = model.BoolPtr(strings.TrimSpace(string(out)) == "1")
		h.AutoUpdatesMechanism = "softwareupdate"
	}
	if out, err := c.run(5*time.Second, "csrutil", "status"); err == nil {
		h.Extra = map[string]any{"sip_enabled": strings.Contains(string(out), "enabled")}
	}
	return nil
}
