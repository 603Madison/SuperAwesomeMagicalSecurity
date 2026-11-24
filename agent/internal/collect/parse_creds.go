package collect

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/603madison/superawesomemagicalsecurity/agent/internal/model"
)

// Credential discovery. IMPORTANT: nothing in this file may place secret
// material (passwords, private keys, tokens) into the returned structs. Only
// metadata, masked identifiers, targets and fingerprints of public halves.

const maxCredFileSize = 4 << 20

func idFingerprint(kind, id string) string {
	sum := sha256.Sum256([]byte(kind + ":" + id))
	return "sha256:" + hex.EncodeToString(sum[:])[:32]
}

// MaskIdentifier keeps the first 4 and last 4 characters.
func MaskIdentifier(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 4) + s[len(s)-4:]
}

func fileDetails(path string) map[string]any {
	d := map[string]any{}
	if st, err := os.Stat(path); err == nil {
		mode := st.Mode().Perm()
		d["mode"] = fmt.Sprintf("%04o", mode)
		d["world_readable"] = mode&0o004 != 0
		d["group_readable"] = mode&0o040 != 0
	}
	return d
}

func readSmall(path string) ([]byte, bool) {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxCredFileSize {
		return nil, false
	}
	b, err := os.ReadFile(path)
	return b, err == nil
}

// DiscoverCredentials inspects a user's home directory.
func DiscoverCredentials(home, owner string) ([]model.Credential, []model.KnownHost) {
	var creds []model.Credential
	var known []model.KnownHost
	if home == "" || home == "/" || home == "/nonexistent" {
		return nil, nil
	}
	if st, err := os.Stat(home); err != nil || !st.IsDir() {
		return nil, nil
	}
	creds = append(creds, discoverSSHKeys(filepath.Join(home, ".ssh"), owner)...)
	for _, kh := range []string{".ssh/known_hosts", ".ssh/known_hosts2"} {
		if b, ok := readSmall(filepath.Join(home, kh)); ok {
			known = append(known, ParseKnownHosts(bytes.NewReader(b), owner)...)
		}
	}
	creds = append(creds, awsCreds(filepath.Join(home, ".aws", "credentials"), owner)...)
	creds = append(creds, kubeCreds(filepath.Join(home, ".kube", "config"), owner)...)
	creds = append(creds, dockerCreds(filepath.Join(home, ".docker", "config.json"), owner)...)
	creds = append(creds, gitCreds(filepath.Join(home, ".git-credentials"), owner)...)
	creds = append(creds, netrcCreds(filepath.Join(home, ".netrc"), owner)...)
	creds = append(creds, pgpassCreds(filepath.Join(home, ".pgpass"), owner)...)
	creds = append(creds, mycnfCreds(filepath.Join(home, ".my.cnf"), owner)...)
	creds = append(creds, cloudDirCreds(home, owner)...)
	creds = append(creds, historySecrets(home, owner)...)
	return creds, known
}

func discoverSSHKeys(dir, owner string) []model.Credential {
	var out []model.Credential
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || strings.HasSuffix(n, ".pub") || n == "known_hosts" || n == "known_hosts2" ||
			n == "authorized_keys" || n == "authorized_keys2" || n == "config" || strings.HasSuffix(n, ".old") {
			continue
		}
		p := filepath.Join(dir, n)
		b, ok := readSmall(p)
		if !ok || len(b) > 64*1024 {
			continue
		}
		info := InspectPrivateKey(b)
		// zero the buffer: we never keep private key bytes around
		for i := range b {
			b[i] = 0
		}
		if !info.IsKey {
			continue
		}
		if info.Fingerprint == "" {
			if pb, ok := readSmall(p + ".pub"); ok {
				if kt, fp, _, _, err := ParseAuthorizedKeyLine(string(pb)); err == nil {
					info.Fingerprint, info.KeyType = fp, kt
				}
			}
		}
		d := fileDetails(p)
		d["format"] = info.Format
		if info.KeyType != "" {
			d["key_type"] = info.KeyType
		}
		out = append(out, model.Credential{
			Kind: "ssh_private_key", Owner: owner, Path: p, Fingerprint: info.Fingerprint,
			Encrypted: info.Encrypted, Details: d,
		})
	}
	// ssh client config: hosts the user connects to are useful lateral targets
	if b, ok := readSmall(filepath.Join(dir, "config")); ok {
		var targets []string
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			k, v := splitKV(strings.TrimSpace(sc.Text()))
			if strings.EqualFold(k, "HostName") && v != "" {
				targets = append(targets, v)
			}
		}
		if len(targets) > 0 {
			out = append(out, model.Credential{Kind: "ssh_config", Owner: owner, Path: filepath.Join(dir, "config"),
				Targets: uniq(targets), Details: map[string]any{}})
		}
	}
	return out
}

// parseINI returns section -> key -> value (lowercased keys).
func parseINI(b []byte) map[string]map[string]string {
	out := map[string]map[string]string{}
	sec := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sec = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if out[sec] == nil {
			out[sec] = map[string]string{}
		}
		out[sec][strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return out
}

func awsCreds(path, owner string) []model.Credential {
	b, ok := readSmall(path)
	if !ok {
		return nil
	}
	var out []model.Credential
	ini := parseINI(b)
	profiles := make([]string, 0, len(ini))
	for p := range ini {
		profiles = append(profiles, p)
	}
	sort.Strings(profiles)
	for _, prof := range profiles {
		kv := ini[prof]
		id := kv["aws_access_key_id"]
		if id == "" {
			continue
		}
		d := fileDetails(path)
		d["profile"] = prof
		d["has_session_token"] = kv["aws_session_token"] != ""
		d["long_lived"] = strings.HasPrefix(id, "AKIA")
		out = append(out, model.Credential{Kind: "aws", Owner: owner, Path: path, Identifier: MaskIdentifier(id),
			Fingerprint: idFingerprint("aws", id), Targets: []string{"aws"}, Details: d})
	}
	return out
}

var kubeServerRe = regexp.MustCompile(`(?m)^\s*server:\s*(\S+)`)

func kubeCreds(path, owner string) []model.Credential {
	b, ok := readSmall(path)
	if !ok {
		return nil
	}
	var targets []string
	for _, m := range kubeServerRe.FindAllSubmatch(b, -1) {
		targets = append(targets, strings.Trim(string(m[1]), `"'`))
	}
	s := string(b)
	d := fileDetails(path)
	d["embedded_client_key"] = strings.Contains(s, "client-key-data:")
	d["embedded_token"] = regexp.MustCompile(`(?m)^\s*token:\s*\S`).MatchString(s)
	d["exec_plugin"] = strings.Contains(s, "exec:")
	ids := strings.Join(targets, ",")
	return []model.Credential{{Kind: "kube", Owner: owner, Path: path, Targets: uniq(targets),
		Fingerprint: idFingerprint("kube", ids+"|"+owner), Details: d}}
}

func dockerCreds(path, owner string) []model.Credential {
	b, ok := readSmall(path)
	if !ok {
		return nil
	}
	var cfg struct {
		Auths       map[string]map[string]any `json:"auths"`
		CredsStore  string                    `json:"credsStore"`
		CredHelpers map[string]string         `json:"credHelpers"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return nil
	}
	var inline, helper []string
	for reg, a := range cfg.Auths {
		if v, _ := a["auth"].(string); v != "" {
			inline = append(inline, reg)
		} else {
			helper = append(helper, reg)
		}
	}
	for reg := range cfg.CredHelpers {
		helper = append(helper, reg)
	}
	if len(inline)+len(helper) == 0 {
		return nil
	}
	sort.Strings(inline)
	d := fileDetails(path)
	d["inline_auth_registries"] = inline
	d["creds_store"] = cfg.CredsStore
	return []model.Credential{{Kind: "docker", Owner: owner, Path: path, Targets: uniq(append(inline, helper...)), Details: d}}
}

func gitCreds(path, owner string) []model.Credential {
	b, ok := readSmall(path)
	if !ok {
		return nil
	}
	var out []model.Credential
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		u, err := url.Parse(strings.TrimSpace(sc.Text()))
		if err != nil || u.Host == "" || u.User == nil {
			continue
		}
		id := u.User.Username() + "@" + u.Host
		out = append(out, model.Credential{Kind: "git", Owner: owner, Path: path, Identifier: id,
			Fingerprint: idFingerprint("git", id), Targets: []string{u.Host}, Details: fileDetails(path)})
	}
	return out
}

func netrcCreds(path, owner string) []model.Credential {
	b, ok := readSmall(path)
	if !ok {
		return nil
	}
	var out []model.Credential
	toks := strings.Fields(string(b))
	machine, login := "", ""
	hasPw := false
	flush := func() {
		if machine != "" && (login != "" || hasPw) {
			id := login + "@" + machine
			out = append(out, model.Credential{Kind: "netrc", Owner: owner, Path: path, Identifier: id,
				Fingerprint: idFingerprint("netrc", id), Targets: []string{machine}, Details: fileDetails(path)})
		}
		machine, login, hasPw = "", "", false
	}
	for i := 0; i < len(toks); i++ {
		switch toks[i] {
		case "machine":
			flush()
			if i+1 < len(toks) {
				machine = toks[i+1]
				i++
			}
		case "default":
			flush()
			machine = "default"
		case "login":
			if i+1 < len(toks) {
				login = toks[i+1]
				i++
			}
		case "password":
			hasPw = true
			i++
		}
	}
	flush()
	return out
}

func pgpassCreds(path, owner string) []model.Credential {
	b, ok := readSmall(path)
	if !ok {
		return nil
	}
	var out []model.Credential
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.SplitN(line, ":", 5)
		if len(f) < 5 {
			continue
		}
		host, port, db, user := f[0], f[1], f[2], f[3]
		if port == "*" || port == "" {
			port = "5432"
		}
		id := user + "@" + host + ":" + port + "/" + db
		d := fileDetails(path)
		d["database"] = db
		out = append(out, model.Credential{Kind: "pgpass", Owner: owner, Path: path, Identifier: id,
			Fingerprint: idFingerprint("pgpass", id), Targets: []string{host + ":" + port}, Details: d})
	}
	return out
}

func mycnfCreds(path, owner string) []model.Credential {
	b, ok := readSmall(path)
	if !ok {
		return nil
	}
	ini := parseINI(b)
	var out []model.Credential
	for _, sec := range []string{"client", "mysql", "mysqldump"} {
		kv := ini[sec]
		if kv == nil || kv["password"] == "" {
			continue
		}
		host := kv["host"]
		if host == "" {
			host = "localhost"
		}
		port := kv["port"]
		if port == "" {
			port = "3306"
		}
		id := kv["user"] + "@" + host + ":" + port
		out = append(out, model.Credential{Kind: "mysql", Owner: owner, Path: path, Identifier: id,
			Fingerprint: idFingerprint("mysql", id), Targets: []string{host + ":" + port}, Details: fileDetails(path)})
		break
	}
	return out
}

func cloudDirCreds(home, owner string) []model.Credential {
	var out []model.Credential
	checks := []struct{ kind, path string }{
		{"gcp", ".config/gcloud/application_default_credentials.json"},
		{"gcp", ".config/gcloud/credentials.db"},
		{"azure", ".azure/msal_token_cache.json"},
		{"azure", ".azure/accessTokens.json"},
		{"azure", ".azure/msal_token_cache.bin"},
	}
	for _, c := range checks {
		p := filepath.Join(home, c.path)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			out = append(out, model.Credential{Kind: c.kind, Owner: owner, Path: p, Targets: []string{c.kind},
				Fingerprint: idFingerprint(c.kind, p), Details: fileDetails(p)})
		}
	}
	return out
}

// historySecretRe matches command lines that commonly carry inline secrets.
var historySecretRe = regexp.MustCompile(`(?i)(sshpass\s|mysql\s(.*\s)?-p\S|mysqladmin\s(.*\s)?-p\S|--password[= ]\S|PASSWORD=\S|PASSWD=\S|\bSECRET(_KEY)?=\S|\bTOKEN=\S|API_KEY=\S|AWS_SECRET_ACCESS_KEY=\S|curl\s(.*\s)?-u\s?\S+:\S|https?://[^/\s:@]+:[^@\s]+@)`)

// CountHistorySecrets counts lines matching the secret patterns.
func CountHistorySecrets(b []byte) int {
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if historySecretRe.Match(sc.Bytes()) {
			n++
		}
	}
	return n
}

func historySecrets(home, owner string) []model.Credential {
	var out []model.Credential
	for _, h := range []string{".bash_history", ".zsh_history", ".ash_history", ".sh_history", ".mysql_history",
		".psql_history", ".python_history", ".local/share/fish/fish_history"} {
		p := filepath.Join(home, h)
		b, ok := readSmall(p)
		if !ok {
			continue
		}
		n := CountHistorySecrets(b)
		if n == 0 {
			continue
		}
		d := fileDetails(p)
		d["matches"] = n
		out = append(out, model.Credential{Kind: "history_secret", Owner: owner, Path: p, Details: d})
	}
	return out
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// walkLimited walks root calling fn for each entry, stopping after max entries.
func walkLimited(root string, max int, fn func(path string, d fs.DirEntry) error) {
	n := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		n++
		if n > max {
			return fs.SkipAll
		}
		return fn(p, d)
	})
}
