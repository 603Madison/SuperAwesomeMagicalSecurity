//go:build linux

package collect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/603madison/superawesomemagicalsecurity/agent/internal/model"
)

func collectPlatform(c *collector) {
	c.step("os", c.linuxOS)
	c.step("host", c.linuxHost)
	c.step("packages", c.linuxPackages)
	var users []model.User
	c.step("users", func() error { var err error; users, err = c.linuxUsers(); return err })
	c.step("sudoers", func() error { return c.collectSudoers("/etc/sudoers") })
	c.step("user_artifacts", func() error { return c.collectUserArtifacts(users) })
	c.step("sockets", c.linuxSockets)
	c.step("datastores", c.linuxDatastores)
	c.step("hardening", c.linuxHardening)
	c.step("containers", c.linuxContainers)
}

// ParseOSRelease parses /etc/os-release content.
func ParseOSRelease(b []byte) model.OSInfo {
	kv := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		kv[k] = strings.Trim(v, `"'`)
	}
	o := model.OSInfo{Family: "linux", ID: kv["ID"], Name: kv["NAME"], Version: kv["VERSION"],
		VersionID: kv["VERSION_ID"], Codename: kv["VERSION_CODENAME"], Pretty: kv["PRETTY_NAME"]}
	if o.Codename == "" {
		o.Codename = kv["UBUNTU_CODENAME"]
	}
	if kv["ID_LIKE"] != "" {
		o.IDLike = strings.Fields(kv["ID_LIKE"])
	}
	return o
}

func (c *collector) linuxOS() error {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if b, err := os.ReadFile(p); err == nil {
			c.inv.Host.OS = ParseOSRelease(b)
			// Alpine VERSION_ID is "3.19.1"; keep as-is, server maps ecosystems.
			return nil
		}
	}
	return fmt.Errorf("no os-release")
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (c *collector) linuxHost() error {
	h := &c.inv.Host
	h.Kernel = readTrim("/proc/sys/kernel/osrelease")
	if up := readTrim("/proc/uptime"); up != "" {
		if f, err := strconv.ParseFloat(strings.Fields(up)[0], 64); err == nil {
			h.UptimeSeconds = int64(f)
		}
	}
	h.MachineID = readTrim("/etc/machine-id")
	if h.MachineID == "" {
		h.MachineID = readTrim("/var/lib/dbus/machine-id")
	}
	// container detection
	if _, err := os.Stat("/.dockerenv"); err == nil {
		h.IsContainer, h.Virtualization = true, "docker"
	} else if _, err := os.Stat("/run/.containerenv"); err == nil {
		h.IsContainer, h.Virtualization = true, "podman"
	} else if cg := readTrim("/proc/1/cgroup"); regexp.MustCompile(`docker|kubepods|containerd|lxc|libpod`).MatchString(cg) {
		h.IsContainer, h.Virtualization = true, "container"
	} else if os.Getenv("container") != "" {
		h.IsContainer, h.Virtualization = true, os.Getenv("container")
	}
	if !h.IsContainer {
		if out, err := c.run(3*time.Second, "systemd-detect-virt"); err == nil || len(out) > 0 {
			h.Virtualization = strings.TrimSpace(string(out))
			switch h.Virtualization {
			case "docker", "podman", "lxc", "lxc-libvirt", "systemd-nspawn", "openvz", "rkt", "proot", "pouch", "container-other":
				h.IsContainer = true
			}
		} else {
			prod := strings.ToLower(readTrim("/sys/class/dmi/id/product_name") + " " + readTrim("/sys/class/dmi/id/sys_vendor"))
			for _, v := range []string{"kvm", "qemu", "vmware", "virtualbox", "xen", "hyper-v", "microsoft", "amazon ec2", "google"} {
				if strings.Contains(prod, v) {
					h.Virtualization = v
					break
				}
			}
		}
		if strings.Contains(strings.ToLower(readTrim("/proc/version")), "microsoft") {
			h.Virtualization = "wsl"
		}
	}
	if h.Virtualization == "" {
		h.Virtualization = "none"
	}
	return nil
}

func (c *collector) linuxPackages() error {
	found := false
	if f, err := os.Open("/var/lib/dpkg/status"); err == nil {
		c.inv.Packages = append(c.inv.Packages, ParseDpkgStatus(f)...)
		f.Close()
		found = true
	}
	if f, err := os.Open("/lib/apk/db/installed"); err == nil {
		c.inv.Packages = append(c.inv.Packages, ParseApkInstalled(f)...)
		f.Close()
		found = true
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		if _, serr := os.Stat("/var/lib/rpm"); serr == nil || !found {
			out, err := c.run(60*time.Second, "rpm", "-qa", "--qf", `%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n`)
			if err == nil {
				c.inv.Packages = append(c.inv.Packages, ParseRpmQuery(bytes.NewReader(out))...)
			} else if !found {
				c.errf("rpm: %v", err)
			}
		}
	}
	c.inv.Packages = append(c.inv.Packages, CollectPythonPackages([]string{
		"/usr/lib/python3*/site-packages", "/usr/lib/python3*/dist-packages",
		"/usr/local/lib/python3*/site-packages", "/usr/local/lib/python3*/dist-packages",
		"/usr/lib64/python3*/site-packages", "/opt/*/lib/python3*/site-packages",
		"/opt/*/venv/lib/python3*/site-packages", "/opt/*/.venv/lib/python3*/site-packages",
	}, 3000)...)
	c.inv.Packages = append(c.inv.Packages, CollectNpmGlobal([]string{
		"/usr/lib/node_modules", "/usr/local/lib/node_modules",
	}, 1000)...)
	return nil
}

func (c *collector) linuxUsers() ([]model.User, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	users := ParsePasswd(f)
	f.Close()
	var groups []model.Group
	if g, err := os.Open("/etc/group"); err == nil {
		groups = ParseGroup(g)
		g.Close()
	}
	shadow := map[string]string{}
	if s, err := os.Open("/etc/shadow"); err == nil {
		shadow = ParseShadow(s)
		s.Close()
	}
	MergeIdentity(users, groups, shadow)
	c.inv.Users = users
	c.inv.Groups = groups
	return users, nil
}

// ------------------------------------------------------------------ sockets

type procInfo struct {
	comm, exe string
	uid       int
}

func readProcInfo(pid int) procInfo {
	pi := procInfo{uid: -1}
	base := "/proc/" + strconv.Itoa(pid)
	pi.comm = readTrim(base + "/comm")
	pi.exe, _ = os.Readlink(base + "/exe")
	pi.exe = strings.TrimSuffix(pi.exe, " (deleted)")
	if st, err := os.ReadFile(base + "/status"); err == nil {
		for _, line := range strings.Split(string(st), "\n") {
			if v, ok := strings.CutPrefix(line, "Uid:"); ok {
				if f := strings.Fields(v); len(f) > 0 {
					pi.uid, _ = strconv.Atoi(f[0])
				}
				break
			}
		}
	}
	return pi
}

// inodeToPID maps socket inodes to pids by scanning /proc/*/fd.
func inodeToPID(want map[uint64]bool) map[uint64]int {
	out := map[uint64]int{}
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		fdDir := "/proc/" + p.Name() + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			ino, err := strconv.ParseUint(link[8:len(link)-1], 10, 64)
			if err == nil && want[ino] {
				if _, ok := out[ino]; !ok {
					out[ino] = pid
				}
			}
		}
		if len(out) == len(want) {
			break
		}
	}
	return out
}

func (c *collector) uidName() map[int]string {
	m := map[int]string{}
	for _, u := range c.inv.Users {
		if _, ok := m[u.UID]; !ok {
			m[u.UID] = u.Name
		}
	}
	return m
}

func (c *collector) linuxSockets() error {
	type sock struct {
		proto string
		e     ProcNetEntry
	}
	var socks []sock
	for _, t := range []struct{ file, proto string }{{"tcp", "tcp"}, {"tcp6", "tcp"}, {"udp", "udp"}, {"udp6", "udp"}} {
		f, err := os.Open("/proc/net/" + t.file)
		if err != nil {
			continue
		}
		for _, e := range ParseProcNet(f, t.proto == "udp") {
			if e.State == "LISTEN" || (e.State == "ESTABLISHED" && !IsLoopback(e.RemoteIP)) {
				socks = append(socks, sock{t.proto, e})
			}
		}
		f.Close()
	}
	want := map[uint64]bool{}
	for _, s := range socks {
		if s.e.Inode != 0 {
			want[s.e.Inode] = true
		}
	}
	pids := inodeToPID(want)
	infos := map[int]procInfo{}
	names := c.uidName()
	lookupUser := func(uid int) string {
		if n, ok := names[uid]; ok {
			return n
		}
		if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
			return u.Username
		}
		if uid >= 0 {
			return strconv.Itoa(uid)
		}
		return ""
	}
	for _, s := range socks {
		pid := pids[s.e.Inode]
		var pi procInfo
		if pid > 0 {
			if v, ok := infos[pid]; ok {
				pi = v
			} else {
				pi = readProcInfo(pid)
				infos[pid] = pi
			}
		}
		uid := s.e.UID
		if pi.uid >= 0 && pid > 0 {
			uid = pi.uid
		}
		if s.e.State == "LISTEN" {
			c.inv.Listeners = append(c.inv.Listeners, model.Listener{
				Proto: s.proto, Address: s.e.LocalIP, Port: s.e.LocalPort, PID: pid,
				Process: pi.comm, User: lookupUser(uid), Exe: pi.exe,
			})
		} else {
			c.inv.Connections = append(c.inv.Connections, model.Connection{
				Proto: s.proto, LocalAddress: s.e.LocalIP, LocalPort: s.e.LocalPort,
				RemoteAddress: s.e.RemoteIP, RemotePort: s.e.RemotePort, State: s.e.State,
				Process: pi.comm, User: lookupUser(uid),
			})
		}
	}
	c.resolveListenerPackages()
	return nil
}

// resolveListenerPackages finds the package owning each listener executable.
func (c *collector) resolveListenerPackages() {
	exes := map[string]string{}
	for _, l := range c.inv.Listeners {
		if l.Exe != "" {
			exes[l.Exe] = ""
		}
	}
	if len(exes) == 0 {
		return
	}
	// usrmerge: /usr/sbin/sshd may be listed as /sbin/sshd and vice versa
	alt := func(p string) string {
		if strings.HasPrefix(p, "/usr/") {
			return strings.TrimPrefix(p, "/usr")
		}
		return "/usr" + p
	}
	if lists, _ := filepath.Glob("/var/lib/dpkg/info/*.list"); len(lists) > 0 {
		lookup := map[string]string{}
		for e := range exes {
			lookup[e] = e
			lookup[alt(e)] = e
		}
		remaining := len(exes)
		for _, lf := range lists {
			if remaining == 0 {
				break
			}
			b, err := os.ReadFile(lf)
			if err != nil {
				continue
			}
			pkg := strings.TrimSuffix(filepath.Base(lf), ".list")
			pkg, _, _ = strings.Cut(pkg, ":") // strip :amd64
			for _, line := range bytes.Split(b, []byte("\n")) {
				if orig, ok := lookup[string(line)]; ok && exes[orig] == "" {
					exes[orig] = pkg
					remaining--
				}
			}
		}
	} else if _, err := exec.LookPath("rpm"); err == nil {
		for e := range exes {
			if out, err := c.run(5*time.Second, "rpm", "-qf", "--qf", "%{NAME}", e); err == nil {
				exes[e] = strings.TrimSpace(string(out))
			}
		}
	} else if _, err := exec.LookPath("apk"); err == nil {
		for e := range exes {
			if out, err := c.run(5*time.Second, "apk", "info", "-W", e); err == nil {
				// "/usr/sbin/sshd is owned by openssh-server-9.6_p1-r0"
				if _, v, ok := strings.Cut(strings.TrimSpace(string(out)), " is owned by "); ok {
					exes[e] = v
				}
			}
		}
	}
	for i := range c.inv.Listeners {
		c.inv.Listeners[i].Package = exes[c.inv.Listeners[i].Exe]
	}
}

// -------------------------------------------------------------- datastores

var dbProcesses = map[string]string{
	"postgres": "postgresql", "postmaster": "postgresql", "mysqld": "mysql", "mariadbd": "mysql",
	"mongod": "mongodb", "redis-server": "redis", "sqlservr": "mssql", "influxd": "influxdb",
	"clickhouse-server": "clickhouse", "etcd": "etcd", "vault": "secrets_vault", "minio": "object_storage",
	"couchdb": "couchdb", "cassandra": "cassandra", "neo4j": "neo4j", "valkey-server": "redis",
	"memcached": "memcached", "opensearch": "elasticsearch",
}

func (c *collector) linuxDatastores() error {
	kinds := map[string]bool{}
	for _, l := range c.inv.Listeners {
		kind := dbProcesses[l.Process]
		if kind == "" && (l.Port == 9200 || l.Port == 9300) && (l.Process == "java" || strings.Contains(l.Exe, "elasticsearch")) {
			kind = "elasticsearch"
		}
		if kind == "" || (l.Proto == "udp") {
			continue
		}
		key := fmt.Sprintf("%s:%d", kind, l.Port)
		if kinds[key] {
			continue
		}
		kinds[key], kinds[kind] = true, true
		c.inv.Datastores = append(c.inv.Datastores, model.Datastore{
			Kind: kind, Name: fmt.Sprintf("%s:%d", kind, l.Port), Port: l.Port, Owner: l.User,
			Details: map[string]any{"bind": l.Address, "process": l.Process, "loopback_only": IsLoopback(l.Address)},
		})
	}
	for dir, kind := range map[string]string{
		"/var/lib/postgresql": "postgresql", "/var/lib/pgsql": "postgresql", "/var/lib/mysql": "mysql",
		"/var/lib/mongodb": "mongodb", "/var/lib/redis": "redis", "/var/lib/elasticsearch": "elasticsearch",
	} {
		if kinds[kind] {
			continue
		}
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			kinds[kind] = true
			c.inv.Datastores = append(c.inv.Datastores, model.Datastore{Kind: kind, Name: kind, Path: dir,
				Owner: fileOwner(st), Details: map[string]any{"running": false}})
		}
	}
	if b, err := os.ReadFile("/etc/exports"); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			f := strings.Fields(line)
			c.inv.Datastores = append(c.inv.Datastores, model.Datastore{Kind: "nfs_export", Name: f[0], Path: f[0],
				Port: 2049, Details: map[string]any{"clients": f[1:], "world": strings.Contains(line, "*") || strings.Contains(line, "no_root_squash")}})
		}
	}
	for _, p := range []string{"/etc/samba/smb.conf", "/usr/local/etc/smb4.conf"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		ini := parseINI(b)
		for sec, kv := range ini {
			ls := strings.ToLower(sec)
			if ls == "global" || ls == "printers" || ls == "print$" || ls == "homes" || kv["path"] == "" {
				continue
			}
			guest := strings.EqualFold(kv["guest ok"], "yes") || strings.EqualFold(kv["public"], "yes")
			c.inv.Datastores = append(c.inv.Datastores, model.Datastore{Kind: "smb_share", Name: sec, Path: kv["path"],
				Port: 445, Details: map[string]any{"guest_ok": guest, "writable": strings.EqualFold(kv["writable"], "yes") || strings.EqualFold(kv["read only"], "no")}})
		}
	}
	return nil
}

func fileOwner(st fs.FileInfo) string {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		if u, err := user.LookupId(strconv.Itoa(int(s.Uid))); err == nil {
			return u.Username
		}
		return strconv.Itoa(int(s.Uid))
	}
	return ""
}

// --------------------------------------------------------------- hardening

var sysctlKeys = []string{
	"kernel.randomize_va_space", "net.ipv4.ip_forward", "kernel.kptr_restrict", "kernel.dmesg_restrict",
	"fs.protected_symlinks", "fs.protected_hardlinks", "kernel.unprivileged_bpf_disabled",
	"kernel.yama.ptrace_scope", "net.ipv4.conf.all.accept_redirects", "net.ipv4.tcp_syncookies",
	"kernel.unprivileged_userns_clone", "fs.suid_dumpable",
}

func (c *collector) linuxHardening() error {
	h := &c.inv.Hardening
	c.step("sshd", func() error {
		h.SSHD = ParseSSHDConfig("/etc/ssh/sshd_config", "/etc/ssh", nil)
		return nil
	})
	c.step("host_firewall", func() error { h.Firewall = c.linuxFirewall(); return nil })
	c.step("suid", func() error {
		for _, d := range []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"} {
			entries, _ := os.ReadDir(d)
			for _, e := range entries {
				info, err := e.Info()
				if err != nil || !info.Mode().IsRegular() {
					continue
				}
				if info.Mode()&os.ModeSetuid != 0 {
					p := filepath.Join(d, e.Name())
					if rp, err := filepath.EvalSymlinks(p); err == nil && rp != p && containsStr(h.SUIDBinaries, rp) {
						continue
					}
					h.SUIDBinaries = append(h.SUIDBinaries, p)
				}
			}
		}
		return nil
	})
	c.step("world_writable", func() error {
		walkLimited("/etc", 20000, func(p string, d fs.DirEntry) error {
			info, err := d.Info()
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return nil
			}
			m := info.Mode()
			if m.Perm()&0o002 != 0 && !(m.IsDir() && m&os.ModeSticky != 0) {
				if len(h.WorldWritable) < 200 {
					h.WorldWritable = append(h.WorldWritable, p)
				}
			}
			return nil
		})
		return nil
	})
	c.step("path_dirs", func() error {
		path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
		if b, err := os.ReadFile("/etc/environment"); err == nil {
			if m := regexp.MustCompile(`(?m)^PATH="?([^"\n]+)`).FindSubmatch(b); m != nil {
				path = string(m[1])
			}
		}
		for _, d := range strings.Split(path, ":") {
			if d == "" || d == "." {
				h.WritablePathDirs = append(h.WritablePathDirs, d+" (relative)")
				continue
			}
			if writableByNonRoot(d) {
				h.WritablePathDirs = append(h.WritablePathDirs, d)
			}
		}
		return nil
	})
	c.step("cron", func() error { h.WritableRootCron = linuxWritableRootCron(); return nil })
	c.step("auto_updates", func() error {
		if _, err := os.Stat("/etc/apt"); err == nil {
			b, _ := os.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades")
			on := regexp.MustCompile(`Unattended-Upgrade\s+"1"`).Match(b)
			h.AutoUpdates, h.AutoUpdatesMechanism = model.BoolPtr(on), "unattended-upgrades"
		} else if _, err := os.Stat("/etc/dnf"); err == nil {
			m, _ := filepath.Glob("/etc/systemd/system/timers.target.wants/dnf-automatic*.timer")
			h.AutoUpdates, h.AutoUpdatesMechanism = model.BoolPtr(len(m) > 0), "dnf-automatic"
		} else if _, err := os.Stat("/etc/yum"); err == nil {
			_, err := os.Stat("/etc/yum/yum-cron.conf")
			h.AutoUpdates, h.AutoUpdatesMechanism = model.BoolPtr(err == nil), "yum-cron"
		}
		return nil
	})
	c.step("sysctl", func() error {
		h.Sysctl = map[string]string{}
		for _, k := range sysctlKeys {
			if v := readTrim("/proc/sys/" + strings.ReplaceAll(k, ".", "/")); v != "" {
				h.Sysctl[k] = v
			}
		}
		return nil
	})
	c.step("mac", func() error {
		if v := readTrim("/sys/fs/selinux/enforce"); v != "" {
			if v == "1" {
				h.MACFramework = "selinux:enforcing"
			} else {
				h.MACFramework = "selinux:permissive"
			}
		} else if strings.HasPrefix(readTrim("/sys/module/apparmor/parameters/enabled"), "Y") {
			h.MACFramework = "apparmor"
		} else {
			h.MACFramework = "none"
		}
		return nil
	})
	c.step("docker_socket", func() error {
		for _, p := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
			st, err := os.Stat(p)
			if err != nil {
				continue
			}
			d := map[string]any{"exists": true, "path": p, "mode": fmt.Sprintf("%04o", st.Mode().Perm())}
			if s, ok := st.Sys().(*syscall.Stat_t); ok {
				if g, err := user.LookupGroupId(strconv.Itoa(int(s.Gid))); err == nil {
					d["group"] = g.Name
				} else {
					d["group"] = strconv.Itoa(int(s.Gid))
				}
			}
			d["world_writable"] = st.Mode().Perm()&0o002 != 0
			h.DockerSocket = d
			return nil
		}
		h.DockerSocket = map[string]any{"exists": false}
		return nil
	})
	c.step("reboot", func() error {
		_, err := os.Stat("/var/run/reboot-required")
		h.PendingReboot = model.BoolPtr(err == nil)
		return nil
	})
	c.step("secure_boot", func() error {
		m, _ := filepath.Glob("/sys/firmware/efi/efivars/SecureBoot-*")
		if len(m) > 0 {
			if b, err := os.ReadFile(m[0]); err == nil && len(b) > 0 {
				h.SecureBoot = model.BoolPtr(b[len(b)-1] == 1)
			}
		}
		return nil
	})
	c.step("disk_encryption", func() error {
		// heuristic: any device-mapper target backed by dm-crypt
		uuids, _ := filepath.Glob("/sys/block/dm-*/dm/uuid")
		if _, err := os.Stat("/sys/block"); err != nil {
			return nil
		}
		enc := false
		for _, u := range uuids {
			if strings.HasPrefix(readTrim(u), "CRYPT-") {
				enc = true
			}
		}
		if !c.inv.Host.IsContainer {
			h.DiskEncryption = model.BoolPtr(enc)
		}
		return nil
	})
	return nil
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// writableByNonRoot reports whether a path can be modified by a non-root user.
func writableByNonRoot(p string) bool {
	st, err := os.Stat(p)
	if err != nil {
		return false
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	perm := st.Mode().Perm()
	if s.Uid != 0 {
		return true
	}
	if perm&0o002 != 0 {
		return true
	}
	if perm&0o020 != 0 && s.Gid != 0 {
		return true
	}
	return false
}

var cronLineRe = regexp.MustCompile(`^\s*(@\w+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(\S+)\s+(.*)$`)

func linuxWritableRootCron() []string {
	var out []string
	check := func(p string) {
		if p != "" && filepath.IsAbs(p) && writableByNonRoot(p) && !containsStr(out, p) {
			out = append(out, p)
		}
	}
	// system crontabs have a user field
	files := []string{"/etc/crontab"}
	cd, _ := filepath.Glob("/etc/cron.d/*")
	files = append(files, cd...)
	for _, f := range files {
		check(f)
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.Contains(strings.SplitN(line, " ", 2)[0], "=") {
				continue
			}
			m := cronLineRe.FindStringSubmatch(line)
			if m == nil || m[2] != "root" {
				continue
			}
			check(firstAbsPath(m[3]))
		}
	}
	// root's personal crontab has no user field
	for _, rc := range []string{"/var/spool/cron/crontabs/root", "/var/spool/cron/root"} {
		b, err := os.ReadFile(rc)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 || strings.HasPrefix(f[0], "#") {
				continue
			}
			if strings.HasPrefix(f[0], "@") && len(f) > 1 {
				check(firstAbsPath(strings.Join(f[1:], " ")))
			} else if len(f) > 5 {
				check(firstAbsPath(strings.Join(f[5:], " ")))
			}
		}
	}
	for _, d := range []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
		check(d)
		entries, _ := os.ReadDir(d)
		for _, e := range entries {
			check(filepath.Join(d, e.Name()))
		}
	}
	return out
}

func firstAbsPath(cmd string) string {
	for _, tok := range strings.Fields(cmd) {
		tok = strings.Trim(tok, `"';`)
		if strings.HasPrefix(tok, "/") && !strings.HasPrefix(tok, "/dev/") {
			if tok == "/bin/sh" || tok == "/bin/bash" || strings.HasSuffix(tok, "/run-parts") || strings.HasSuffix(tok, "/test") {
				continue
			}
			return tok
		}
	}
	return ""
}

func (c *collector) linuxFirewall() model.HostFirewall {
	fw := model.HostFirewall{}
	if b, err := os.ReadFile("/etc/ufw/ufw.conf"); err == nil {
		fw.Backend = "ufw"
		on := regexp.MustCompile(`(?m)^ENABLED=yes`).Match(b)
		fw.Enabled = model.BoolPtr(on)
		if d, err := os.ReadFile("/etc/default/ufw"); err == nil {
			if m := regexp.MustCompile(`(?m)^DEFAULT_INPUT_POLICY="?(\w+)`).FindSubmatch(d); m != nil {
				fw.DefaultInbound = strings.ToLower(string(m[1]))
			}
		}
		if !on {
			fw.DefaultInbound = "accept"
		}
	}
	if out, err := c.run(10*time.Second, "nft", "list", "ruleset"); err == nil {
		n := 0
		policyDrop := false
		for _, line := range strings.Split(string(out), "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "type filter hook input") && (strings.Contains(t, "policy drop") || strings.Contains(t, "policy reject")) {
				policyDrop = true
			}
			if t == "" || strings.HasPrefix(t, "table ") || strings.HasPrefix(t, "chain ") || strings.HasPrefix(t, "type ") ||
				t == "}" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "set ") || strings.HasPrefix(t, "elements") ||
				strings.HasPrefix(t, "flags ") {
				continue
			}
			n++
		}
		if fw.Backend == "" {
			fw.Backend = "nftables"
		}
		fw.RuleCount += n
		if fw.DefaultInbound == "" && policyDrop {
			fw.DefaultInbound = "drop"
		}
	}
	if out, err := c.run(10*time.Second, "iptables", "-S"); err == nil {
		n := 0
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "-A ") {
				n++
			}
			if strings.HasPrefix(line, "-P INPUT ") && fw.DefaultInbound == "" {
				fw.DefaultInbound = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "-P INPUT ")))
			}
		}
		if fw.Backend == "" {
			fw.Backend = "iptables"
		}
		if n > fw.RuleCount {
			fw.RuleCount = n
		}
	}
	if fw.Enabled == nil && fw.Backend != "" {
		fw.Enabled = model.BoolPtr(fw.RuleCount > 0 || fw.DefaultInbound == "drop" || fw.DefaultInbound == "reject")
	}
	return fw
}

// --------------------------------------------------------------- containers

func (c *collector) linuxContainers() error {
	sock := ""
	for _, p := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
		if _, err := os.Stat(p); err == nil {
			sock = p
			break
		}
	}
	if sock == "" {
		return nil
	}
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
	get := func(path string, out any) error {
		req, _ := http.NewRequestWithContext(c.ctx, http.MethodGet, "http://docker"+path, nil)
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("docker api %s: %d", path, resp.StatusCode)
		}
		return json.NewDecoder(resp.Body).Decode(out)
	}
	var list []struct {
		ID    string   `json:"Id"`
		Names []string `json:"Names"`
		Image string   `json:"Image"`
		Ports []struct {
			IP          string `json:"IP"`
			PrivatePort int    `json:"PrivatePort"`
			PublicPort  int    `json:"PublicPort"`
			Type        string `json:"Type"`
		} `json:"Ports"`
	}
	if err := get("/containers/json", &list); err != nil {
		return nil // daemon not running is not an error worth reporting
	}
	for i, ct := range list {
		if i >= 200 {
			break
		}
		co := model.Container{ID: ct.ID, Image: ct.Image}
		if len(ct.Names) > 0 {
			co.Name = strings.TrimPrefix(ct.Names[0], "/")
		}
		for _, p := range ct.Ports {
			if p.PublicPort > 0 {
				co.Ports = append(co.Ports, fmt.Sprintf("%s:%d->%d/%s", p.IP, p.PublicPort, p.PrivatePort, p.Type))
			}
		}
		var insp struct {
			HostConfig struct {
				Privileged  bool   `json:"Privileged"`
				NetworkMode string `json:"NetworkMode"`
				PidMode     string `json:"PidMode"`
			} `json:"HostConfig"`
			Mounts []struct {
				Source      string `json:"Source"`
				Destination string `json:"Destination"`
				RW          bool   `json:"RW"`
			} `json:"Mounts"`
		}
		if err := get("/containers/"+ct.ID+"/json", &insp); err == nil {
			co.Privileged = insp.HostConfig.Privileged
			for _, m := range insp.Mounts {
				mode := "ro"
				if m.RW {
					mode = "rw"
				}
				co.Mounts = append(co.Mounts, m.Source+":"+m.Destination+":"+mode)
			}
		}
		c.inv.Containers = append(c.inv.Containers, co)
	}
	return nil
}
