//go:build windows

package collect

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/603madison/superawesomemagicalsecurity/agent/internal/model"
)

// Windows collectors are best effort and rely on reg.exe / PowerShell.
func collectPlatform(c *collector) {
	c.step("os", c.winOS)
	c.step("packages", c.winPackages)
	var users []model.User
	c.step("users", func() error { var err error; users, err = c.winUsers(); return err })
	c.step("user_artifacts", func() error { return c.collectUserArtifacts(users) })
	c.step("listeners", c.winListeners)
	c.step("hardening", c.winHardening)
}

func (c *collector) ps(script string) ([]byte, error) {
	return c.run(60*time.Second, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

// psJSON decodes ConvertTo-Json output that may be a single object or an array.
func psJSON(b []byte) []map[string]any {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil
	}
	var arr []map[string]any
	if json.Unmarshal(b, &arr) == nil {
		return arr
	}
	var one map[string]any
	if json.Unmarshal(b, &one) == nil {
		return []map[string]any{one}
	}
	return nil
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

// parseRegQuery parses `reg query <key> /s` output into key -> value map.
func parseRegQuery(b []byte) map[string]map[string]string {
	out := map[string]map[string]string{}
	cur := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.HasPrefix(line, "HKEY_") {
			cur = line
			out[cur] = map[string]string{}
			continue
		}
		t := strings.TrimSpace(line)
		if cur == "" || t == "" {
			continue
		}
		for _, typ := range []string{"REG_SZ", "REG_EXPAND_SZ", "REG_DWORD", "REG_QWORD", "REG_MULTI_SZ"} {
			if i := strings.Index(t, "    "+typ); i > 0 {
				name := strings.TrimSpace(t[:i])
				val := strings.TrimSpace(t[i+len(typ)+4:])
				out[cur][name] = val
				break
			}
		}
	}
	return out
}

func (c *collector) winOS() error {
	h := &c.inv.Host
	h.OS.Family, h.OS.ID = "windows", "windows"
	out, err := c.run(10*time.Second, "reg", "query", `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
	if err != nil {
		return err
	}
	for _, kv := range parseRegQuery(out) {
		h.OS.Name = kv["ProductName"]
		h.OS.Version = kv["DisplayVersion"]
		build := kv["CurrentBuild"]
		if ubr := kv["UBR"]; ubr != "" {
			if n, err := strconv.ParseInt(strings.TrimPrefix(ubr, "0x"), 16, 64); err == nil {
				build += "." + strconv.FormatInt(n, 10)
			}
		}
		h.OS.VersionID = build
		h.Kernel = build
	}
	h.OS.Pretty = strings.TrimSpace(h.OS.Name + " " + h.OS.Version)
	if d := os.Getenv("USERDNSDOMAIN"); d != "" {
		h.Domain = d
	}
	if mg, err := c.run(5*time.Second, "reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid"); err == nil {
		for _, kv := range parseRegQuery(mg) {
			h.MachineID = kv["MachineGuid"]
		}
	}
	return nil
}

func (c *collector) winPackages() error {
	seen := map[string]bool{}
	for _, key := range []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	} {
		out, err := c.run(60*time.Second, "reg", "query", key, "/s")
		if err != nil {
			continue
		}
		for _, kv := range parseRegQuery(out) {
			name, ver := kv["DisplayName"], kv["DisplayVersion"]
			if name == "" || ver == "" || seen[name+ver] {
				continue
			}
			seen[name+ver] = true
			c.inv.Packages = append(c.inv.Packages, model.Package{Name: name, Version: ver, Manager: "windows"})
		}
	}
	return nil
}

func (c *collector) winUsers() ([]model.User, error) {
	out, err := c.ps(`Get-LocalUser | Select-Object Name,Enabled,@{n='Sid';e={$_.SID.Value}},PasswordRequired | ConvertTo-Json -Compress`)
	if err != nil {
		return nil, err
	}
	admins := map[string]bool{}
	if a, err := c.ps(`Get-LocalGroupMember -SID S-1-5-32-544 | Select-Object Name | ConvertTo-Json -Compress`); err == nil {
		for _, m := range psJSON(a) {
			n := str(m["Name"])
			if i := strings.LastIndex(n, `\`); i >= 0 {
				n = n[i+1:]
			}
			admins[strings.ToLower(n)] = true
		}
	}
	sysDrive := os.Getenv("SystemDrive")
	if sysDrive == "" {
		sysDrive = "C:"
	}
	var users []model.User
	for _, m := range psJSON(out) {
		name := str(m["Name"])
		enabled, _ := m["Enabled"].(bool)
		rid := -1
		if sid := str(m["Sid"]); sid != "" {
			if i := strings.LastIndex(sid, "-"); i >= 0 {
				rid, _ = strconv.Atoi(sid[i+1:])
			}
		}
		u := model.User{Name: name, UID: rid, GID: -1, LoginEnabled: enabled, PasswordState: "unknown",
			IsAdmin: admins[strings.ToLower(name)], Home: filepath.Join(sysDrive+`\`, "Users", name)}
		if pr, ok := m["PasswordRequired"].(bool); ok && !pr {
			u.PasswordState = "empty"
		}
		if u.IsAdmin {
			u.Groups = []string{"Administrators"}
		}
		users = append(users, u)
	}
	c.inv.Users = users
	return users, nil
}

func (c *collector) winListeners() error {
	out, err := c.ps(`$p=@{}; Get-Process | ForEach-Object { $p[$_.Id]=$_ }; ` +
		`Get-NetTCPConnection -State Listen | ForEach-Object { [pscustomobject]@{a=$_.LocalAddress;port=$_.LocalPort;pid=$_.OwningProcess;proc=$p[[int]$_.OwningProcess].ProcessName;exe=$p[[int]$_.OwningProcess].Path} } | ConvertTo-Json -Compress`)
	if err == nil {
		for _, m := range psJSON(out) {
			port, _ := m["port"].(float64)
			pid, _ := m["pid"].(float64)
			c.inv.Listeners = append(c.inv.Listeners, model.Listener{Proto: "tcp", Address: str(m["a"]), Port: int(port),
				PID: int(pid), Process: str(m["proc"]), Exe: str(m["exe"])})
		}
		return nil
	}
	// fallback: netstat -ano
	ns, nerr := c.run(20*time.Second, "netstat", "-ano", "-p", "TCP")
	if nerr != nil {
		return err
	}
	for _, line := range strings.Split(string(ns), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[3] != "LISTENING" {
			continue
		}
		i := strings.LastIndex(f[1], ":")
		port, _ := strconv.Atoi(f[1][i+1:])
		pid, _ := strconv.Atoi(f[4])
		c.inv.Listeners = append(c.inv.Listeners, model.Listener{Proto: "tcp", Address: strings.Trim(f[1][:i], "[]"), Port: port, PID: pid})
	}
	return nil
}

func (c *collector) winHardening() error {
	h := &c.inv.Hardening
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	h.SSHD = ParseSSHDConfig(filepath.Join(pd, "ssh", "sshd_config"), filepath.Join(pd, "ssh"), nil)
	if f, err := os.Open(filepath.Join(pd, "ssh", "administrators_authorized_keys")); err == nil {
		c.inv.AuthorizedKeys = append(c.inv.AuthorizedKeys, ParseAuthorizedKeys(f, "Administrators", f.Name())...)
		f.Close()
	}
	if out, err := c.ps(`Get-NetFirewallProfile | Select-Object Name,Enabled,@{n='In';e={"$($_.DefaultInboundAction)"}} | ConvertTo-Json -Compress`); err == nil {
		all := true
		in := ""
		for _, m := range psJSON(out) {
			if e, ok := m["Enabled"].(bool); ok && !e {
				all = false
			}
			if s := strings.ToLower(str(m["In"])); s != "" && s != "notconfigured" {
				in = s
			}
		}
		if in == "" {
			in = "block"
		}
		h.Firewall = model.HostFirewall{Enabled: model.BoolPtr(all), Backend: "windows", DefaultInbound: map[string]string{"block": "drop", "allow": "accept"}[in]}
	}
	if out, err := c.ps(`Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json -Compress`); err == nil {
		for _, m := range psJSON(out) {
			av, _ := m["AntivirusEnabled"].(bool)
			rt, _ := m["RealTimeProtectionEnabled"].(bool)
			h.AVEnabled = model.BoolPtr(av && rt)
		}
	}
	if out, err := c.ps(`(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus`); err == nil {
		h.DiskEncryption = model.BoolPtr(strings.TrimSpace(string(out)) == "On")
	}
	if out, err := c.ps(`Confirm-SecureBootUEFI`); err == nil {
		h.SecureBoot = model.BoolPtr(strings.TrimSpace(string(out)) == "True")
	}
	if out, err := c.run(10*time.Second, "reg", "query", `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, "/v", "NoAutoUpdate"); err == nil {
		for _, kv := range parseRegQuery(out) {
			h.AutoUpdates = model.BoolPtr(kv["NoAutoUpdate"] != "0x1")
		}
	} else {
		h.AutoUpdates = model.BoolPtr(true) // Windows default
	}
	h.AutoUpdatesMechanism = "windows-update"
	extra := map[string]any{}
	if out, err := c.ps(`Get-HotFix | Select-Object -ExpandProperty HotFixID`); err == nil {
		var ids []string
		for _, l := range strings.Fields(string(out)) {
			ids = append(ids, l)
		}
		extra["hotfixes"] = ids
	}
	if out, err := c.run(10*time.Second, "reg", "query", `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, "/v", "fDenyTSConnections"); err == nil {
		for _, kv := range parseRegQuery(out) {
			extra["rdp_enabled"] = kv["fDenyTSConnections"] == "0x0"
		}
	}
	if out, err := c.run(10*time.Second, "reg", "query", `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, "/v", "SMB1"); err == nil {
		for _, kv := range parseRegQuery(out) {
			extra["smb1_enabled"] = kv["SMB1"] != "0x0"
		}
	}
	h.Extra = extra
	return nil
}
