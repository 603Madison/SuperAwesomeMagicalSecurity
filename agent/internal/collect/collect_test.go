package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dpkgStatus = `Package: openssl
Status: install ok installed
Priority: optional
Architecture: amd64
Version: 3.0.2-0ubuntu1.10
Description: Secure Sockets Layer toolkit
 This package contains the openssl binary.

Package: libssl3
Status: install ok installed
Architecture: amd64
Source: openssl (3.0.2-0ubuntu1.10)
Version: 3.0.2-0ubuntu1.10

Package: libc6
Status: install ok installed
Architecture: amd64
Source: glibc
Version: 2.35-0ubuntu3.4

Package: removed-thing
Status: deinstall ok config-files
Version: 1.0
`

func TestParseDpkgStatus(t *testing.T) {
	pkgs := ParseDpkgStatus(strings.NewReader(dpkgStatus))
	if len(pkgs) != 3 {
		t.Fatalf("want 3 installed packages, got %d: %+v", len(pkgs), pkgs)
	}
	by := map[string]int{}
	for i, p := range pkgs {
		by[p.Name] = i
	}
	ssl := pkgs[by["libssl3"]]
	if ssl.SourceName != "openssl" || ssl.SourceVersion != "3.0.2-0ubuntu1.10" || ssl.Manager != "dpkg" || ssl.Arch != "amd64" {
		t.Errorf("libssl3 source parsing wrong: %+v", ssl)
	}
	libc := pkgs[by["libc6"]]
	if libc.SourceName != "glibc" || libc.SourceVersion != "2.35-0ubuntu3.4" {
		t.Errorf("libc6 source without version should default to binary version: %+v", libc)
	}
	o := pkgs[by["openssl"]]
	if o.SourceName != "openssl" || o.SourceVersion != o.Version {
		t.Errorf("no Source field should default to self: %+v", o)
	}
}

func TestParseApkAndRpm(t *testing.T) {
	apk := ParseApkInstalled(strings.NewReader("C:Q1abc\nP:musl\nV:1.2.4-r2\nA:x86_64\no:musl\n\nP:libcrypto3\nV:3.1.4-r5\no:openssl\n"))
	if len(apk) != 2 || apk[1].SourceName != "openssl" || apk[0].Version != "1.2.4-r2" {
		t.Fatalf("apk: %+v", apk)
	}
	rpm := ParseRpmQuery(strings.NewReader("openssl-libs\t1\t3.0.7-25.el9_3\tx86_64\topenssl-3.0.7-25.el9_3.src.rpm\nbash\t(none)\t5.1.8-6.el9\tx86_64\tbash-5.1.8-6.el9.src.rpm\ngpg-pubkey\t(none)\tabc-def\t(none)\t(none)\n"))
	if len(rpm) != 2 {
		t.Fatalf("rpm: %+v", rpm)
	}
	if rpm[0].Version != "1:3.0.7-25.el9_3" || rpm[0].SourceName != "openssl" {
		t.Errorf("rpm epoch/source: %+v", rpm[0])
	}
	if rpm[1].Version != "5.1.8-6.el9" || rpm[1].SourceName != "bash" {
		t.Errorf("rpm no-epoch: %+v", rpm[1])
	}
}

func TestParseIdentity(t *testing.T) {
	users := ParsePasswd(strings.NewReader("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/zsh\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\nbob:x:1001:1001::/home/bob:/bin/bash\n"))
	groups := ParseGroup(strings.NewReader("root:x:0:\nsudo:x:27:alice\nalice:x:1000:\ndocker:x:998:bob,alice\nbob:x:1001:\n"))
	shadow := ParseShadow(strings.NewReader("root:!:19000::::::\nalice:$6$salt$hash:19000:0:99999:7:::\nbob::19000::::::\nwww-data:*:19000::::::\n"))
	MergeIdentity(users, groups, shadow)
	m := map[string]int{}
	for i, u := range users {
		m[u.Name] = i
	}
	a := users[m["alice"]]
	if !a.IsAdmin || a.PasswordState != "set" || strings.Join(a.Groups, ",") != "alice,docker,sudo" {
		t.Errorf("alice: %+v", a)
	}
	if users[m["root"]].PasswordState != "locked" || !users[m["root"]].IsAdmin {
		t.Errorf("root: %+v", users[m["root"]])
	}
	if users[m["bob"]].PasswordState != "empty" || users[m["bob"]].IsAdmin {
		t.Errorf("bob: %+v", users[m["bob"]])
	}
	if users[m["www-data"]].LoginEnabled {
		t.Errorf("www-data should not be login enabled")
	}
}

const sudoers = `# comment
Defaults env_reset
Defaults:alice !requiretty
User_Alias ADMINS = carol, dave
Cmnd_Alias RESTART = /bin/systemctl restart nginx, /bin/systemctl restart php-fpm
root	ALL=(ALL:ALL) ALL
%sudo	ALL=(ALL:ALL) ALL
alice ALL=(ALL) NOPASSWD: ALL
ADMINS ALL = (root) NOPASSWD: RESTART
deploy ALL=(www-data) NOEXEC: NOPASSWD: /usr/bin/rsync, \
    /usr/bin/git
#includedir /etc/sudoers.d
@include /etc/sudoers.local
`

func TestParseSudoers(t *testing.T) {
	res := ParseSudoers(strings.NewReader(sudoers), "/etc/sudoers", nil)
	if len(res.IncludeDirs) != 1 || res.IncludeDirs[0] != "/etc/sudoers.d" {
		t.Errorf("includedir: %v", res.IncludeDirs)
	}
	if len(res.Includes) != 1 || res.Includes[0] != "/etc/sudoers.local" {
		t.Errorf("include: %v", res.Includes)
	}
	by := map[string]int{}
	for i, r := range res.Rules {
		by[r.Principal] = i
	}
	if len(res.Rules) != 6 {
		t.Fatalf("want 6 rules, got %d: %+v", len(res.Rules), res.Rules)
	}
	al := res.Rules[by["alice"]]
	if !al.NoPasswd || al.RunAs != "ALL" || al.Commands[0] != "ALL" {
		t.Errorf("alice: %+v", al)
	}
	if res.Rules[by["%sudo"]].NoPasswd || res.Rules[by["%sudo"]].RunAs != "ALL:ALL" {
		t.Errorf("%%sudo: %+v", res.Rules[by["%sudo"]])
	}
	c := res.Rules[by["carol"]]
	if !c.NoPasswd || len(c.Commands) != 2 || c.Commands[0] != "/bin/systemctl restart nginx" {
		t.Errorf("alias expansion: %+v", c)
	}
	if _, ok := by["dave"]; !ok {
		t.Errorf("dave missing from User_Alias expansion")
	}
	d := res.Rules[by["deploy"]]
	if !d.NoPasswd || d.RunAs != "www-data" || len(d.Commands) != 2 || d.Commands[1] != "/usr/bin/git" {
		t.Errorf("deploy (multi-tag + continuation): %+v", d)
	}
}

func TestParseSSHDConfig(t *testing.T) {
	files := map[string]string{
		"/etc/ssh/sshd_config": `# test
Include /etc/ssh/sshd_config.d/*.conf
Port 2222
PermitRootLogin yes
PasswordAuthentication yes
AllowUsers alice bob
Match User guest
    PasswordAuthentication yes
    PermitRootLogin no
`,
		"/etc/ssh/sshd_config.d/50-hardening.conf": "PasswordAuthentication no\nMaxAuthTries=3\n",
	}
	// Include with a glob needs real files: write them to a temp dir
	dir := t.TempDir()
	for p, c := range files {
		fp := filepath.Join(dir, p)
		_ = os.MkdirAll(filepath.Dir(fp), 0o755)
		_ = os.WriteFile(fp, []byte(strings.ReplaceAll(c, "/etc/ssh", filepath.Join(dir, "etc/ssh"))), 0o644)
	}
	cfg := ParseSSHDConfig(filepath.Join(dir, "etc/ssh/sshd_config"), filepath.Join(dir, "etc/ssh"), nil)
	if !cfg.Present || cfg.Port != 2222 {
		t.Fatalf("cfg: %+v", cfg)
	}
	if cfg.PasswordAuthentication != "no" {
		t.Errorf("included file should win (first value): %q", cfg.PasswordAuthentication)
	}
	if cfg.PermitRootLogin != "yes" || cfg.MaxAuthTries != 3 {
		t.Errorf("cfg: %+v", cfg)
	}
	if cfg.PubkeyAuthentication != "yes" || cfg.X11Forwarding != "no" {
		t.Errorf("defaults not applied: %+v", cfg)
	}
	if strings.Join(cfg.AllowUsers, ",") != "alice,bob" {
		t.Errorf("allow users: %v", cfg.AllowUsers)
	}
	missing := ParseSSHDConfig(filepath.Join(dir, "nope"), dir, nil)
	if missing.Present {
		t.Errorf("missing config should not be present")
	}
}

type expectedKey struct {
	Fingerprint string `json:"fingerprint"`
	Pub         string `json:"pub"`
}

func loadExpected(t *testing.T) map[string]expectedKey {
	b, err := os.ReadFile("testdata/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]expectedKey
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSSHFingerprints(t *testing.T) {
	exp := loadExpected(t)
	for name, e := range exp {
		// authorized_keys line with options and comment
		line := `from="10.0.0.0/8",command="echo \"hi there\"" ` + e.Pub + " deploy key"
		kt, fp, comment, opts, err := ParseAuthorizedKeyLine(line)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if fp != e.Fingerprint {
			t.Errorf("%s authorized_keys fingerprint %s != %s", name, fp, e.Fingerprint)
		}
		if comment != "deploy key" || !strings.HasPrefix(opts, `from="10.0.0.0/8"`) || kt == "" {
			t.Errorf("%s: comment=%q opts=%q kt=%q", name, comment, opts, kt)
		}
		for _, variant := range []string{"_openssh", "_pkcs8"} {
			b, _ := os.ReadFile("testdata/id_" + name + variant)
			info := InspectPrivateKey(b)
			if !info.IsKey || info.Encrypted == nil || *info.Encrypted {
				t.Errorf("%s%s: expected unencrypted key: %+v", name, variant, info)
			}
			if info.Fingerprint != e.Fingerprint {
				t.Errorf("%s%s fingerprint %s != %s", name, variant, info.Fingerprint, e.Fingerprint)
			}
		}
		b, _ := os.ReadFile("testdata/id_" + name + "_openssh_enc")
		info := InspectPrivateKey(b)
		if info.Encrypted == nil || !*info.Encrypted {
			t.Errorf("%s openssh encrypted not detected: %+v", name, info)
		}
		if info.Fingerprint != e.Fingerprint {
			t.Errorf("%s encrypted openssh embedded pubkey fingerprint %s != %s", name, info.Fingerprint, e.Fingerprint)
		}
	}
	for _, f := range []string{"id_rsa_pem", "id_ecdsa_pem"} {
		b, _ := os.ReadFile("testdata/" + f)
		info := InspectPrivateKey(b)
		want := exp[strings.TrimSuffix(strings.TrimPrefix(f, "id_"), "_pem")].Fingerprint
		if info.Fingerprint != want || info.Encrypted == nil || *info.Encrypted {
			t.Errorf("%s: %+v want %s", f, info, want)
		}
	}
	b, _ := os.ReadFile("testdata/id_rsa_pem_enc")
	if info := InspectPrivateKey(b); info.Encrypted == nil || !*info.Encrypted || info.Fingerprint != "" {
		t.Errorf("encrypted PEM: %+v", info)
	}
	if info := InspectPrivateKey([]byte("not a key")); info.IsKey {
		t.Errorf("garbage detected as key")
	}
}

func TestDiscoverCredentials(t *testing.T) {
	exp := loadExpected(t)
	home := t.TempDir()
	must := func(p, c string, mode os.FileMode) {
		fp := filepath.Join(home, p)
		_ = os.MkdirAll(filepath.Dir(fp), 0o700)
		if err := os.WriteFile(fp, []byte(c), mode); err != nil {
			t.Fatal(err)
		}
	}
	rsaEnc, _ := os.ReadFile("testdata/id_rsa_pem_enc")
	edKey, _ := os.ReadFile("testdata/id_ed25519_openssh")
	must(".ssh/id_rsa", string(rsaEnc), 0o600)
	must(".ssh/id_rsa.pub", exp["rsa"].Pub+" me@host\n", 0o644)
	must(".ssh/id_ed25519", string(edKey), 0o644)
	must(".ssh/known_hosts", "10.0.0.7,web1 ssh-ed25519 AAAA\n[db.internal]:2222 ssh-rsa AAAA\n|1|abc=|def= ssh-ed25519 AAAA\n", 0o644)
	must(".ssh/config", "Host jump\n  HostName 10.0.0.9\n  User admin\n", 0o644)
	must(".aws/credentials", "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", 0o600)
	must(".kube/config", "clusters:\n- cluster:\n    server: https://10.0.0.50:6443\n  name: prod\nusers:\n- user:\n    token: abc123\n", 0o600)
	must(".pgpass", "db.internal:5432:app:appuser:s3cret\n", 0o600)
	must(".git-credentials", "https://bob:ghp_secrettoken@github.com\n", 0o600)
	must(".netrc", "machine ftp.example.com login anon password pw123\n", 0o600)
	must(".bash_history", "ls\nmysql -u root -pHunter2 app\nsshpass -p x ssh a@b\ncd /tmp\n", 0o600)
	must(".docker/config.json", `{"auths":{"registry.example.com":{"auth":"Ym9iOnB3"}}}`, 0o600)

	creds, known := DiscoverCredentials(home, "bob")
	raw, _ := json.Marshal(creds)
	for _, secret := range []string{"wJalrXUtnFEMI", "s3cret", "ghp_secrettoken", "pw123", "Hunter2", "abc123", "Ym9iOnB3", "AKIAIOSFODNN7EXAMPLE", "PRIVATE KEY"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("secret material %q leaked into credentials output", secret)
		}
	}
	kinds := map[string]int{}
	for _, c := range creds {
		kinds[c.Kind]++
		switch c.Kind {
		case "ssh_private_key":
			if strings.HasSuffix(c.Path, "id_rsa") {
				if c.Encrypted == nil || !*c.Encrypted || c.Fingerprint != exp["rsa"].Fingerprint {
					t.Errorf("encrypted rsa key should use .pub fingerprint: %+v", c)
				}
			} else {
				if c.Encrypted == nil || *c.Encrypted || c.Fingerprint != exp["ed25519"].Fingerprint || c.Details["world_readable"] != true {
					t.Errorf("ed25519 key: %+v", c)
				}
			}
		case "aws":
			if c.Identifier != "AKIA****MPLE" {
				t.Errorf("aws mask: %q", c.Identifier)
			}
		case "pgpass":
			if c.Targets[0] != "db.internal:5432" {
				t.Errorf("pgpass targets: %v", c.Targets)
			}
		case "history_secret":
			if c.Details["matches"] != 2 {
				t.Errorf("history matches: %v", c.Details["matches"])
			}
		}
	}
	for _, k := range []string{"ssh_private_key", "aws", "kube", "pgpass", "git", "netrc", "history_secret", "docker", "ssh_config"} {
		if kinds[k] == 0 {
			t.Errorf("missing credential kind %s (got %v)", k, kinds)
		}
	}
	if kinds["ssh_private_key"] != 2 {
		t.Errorf("want 2 private keys, got %d", kinds["ssh_private_key"])
	}
	hosts := map[string]bool{}
	hashed := 0
	for _, k := range known {
		hosts[k.Host] = true
		if k.Hashed {
			hashed++
		}
	}
	if !hosts["10.0.0.7"] || !hosts["web1"] || !hosts["db.internal:2222"] || hashed != 1 {
		t.Errorf("known_hosts: %+v", known)
	}
}

func TestParseProcNet(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000000000000 100 0 0 10 0
   2: 0500000A:0016 0700000A:D431 01 00000000:00000000 02:000A7A1C 00000000     0        0 33333 4 0000000000000000 20 4 30 10 -1
`
	es := ParseProcNet(strings.NewReader(tcp), false)
	if len(es) != 3 {
		t.Fatalf("got %d", len(es))
	}
	if es[0].LocalIP != "0.0.0.0" || es[0].LocalPort != 22 || es[0].State != "LISTEN" || es[0].Inode != 12345 {
		t.Errorf("0: %+v", es[0])
	}
	if es[1].LocalIP != "127.0.0.1" || es[1].LocalPort != 8080 || es[1].UID != 1000 {
		t.Errorf("1: %+v", es[1])
	}
	if es[2].LocalIP != "10.0.0.5" || es[2].RemoteIP != "10.0.0.7" || es[2].RemotePort != 54321 || es[2].State != "ESTABLISHED" {
		t.Errorf("2: %+v", es[2])
	}
	tcp6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 44444 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 55555 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00000500000A:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 66666 1 0000000000000000 100 0 0 10 0
`
	e6 := ParseProcNet(strings.NewReader(tcp6), false)
	if e6[0].LocalIP != "::" || e6[0].LocalPort != 80 {
		t.Errorf("v6 any: %+v", e6[0])
	}
	if e6[1].LocalIP != "::1" || e6[1].LocalPort != 631 {
		t.Errorf("v6 loopback: %+v", e6[1])
	}
	if e6[2].LocalIP != "10.0.0.5" || e6[2].LocalPort != 443 {
		t.Errorf("v4-mapped: %+v", e6[2])
	}
	udp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n  1: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 777 2 0000000000000000 0\n"
	eu := ParseProcNet(strings.NewReader(udp), true)
	if len(eu) != 1 || eu[0].State != "LISTEN" || eu[0].LocalPort != 53 {
		t.Errorf("udp: %+v", eu)
	}
}

func TestHistorySecretPatterns(t *testing.T) {
	cases := map[string]bool{
		"mysql -u root -psecret db":               true,
		"export AWS_SECRET_ACCESS_KEY=abc":        true,
		"curl -u admin:pw https://x":              true,
		"git clone https://user:tok@github.com/x": true,
		"ls -la":             false,
		"mysql -u root -p":   false,
		"ssh admin@10.0.0.1": false,
	}
	for line, want := range cases {
		if got := CountHistorySecrets([]byte(line)) == 1; got != want {
			t.Errorf("%q: got %v want %v", line, got, want)
		}
	}
}
