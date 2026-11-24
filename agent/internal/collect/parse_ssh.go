package collect

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/603madison/superawesomemagicalsecurity/agent/internal/model"
)

// ------------------------------------------------------------ fingerprints

// FingerprintBlob returns the OpenSSH SHA256 fingerprint of a wire-format
// public key blob ("SHA256:" + unpadded base64), identical to ssh-keygen -lf.
func FingerprintBlob(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

var sshKeyTypes = []string{"ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-sha2-", "sk-ssh-ed25519", "sk-ecdsa-sha2-", "ssh-ed448"}

func isKeyType(tok string) bool {
	for _, t := range sshKeyTypes {
		if strings.HasPrefix(tok, t) {
			return true
		}
	}
	return false
}

// tokenize splits on whitespace while honoring double quotes (authorized_keys options).
func tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	esc := false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\' && inQ:
			cur.WriteRune(r)
			esc = true
		case r == '"':
			inQ = !inQ
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// ParseAuthorizedKeyLine parses one authorized_keys / .pub line.
func ParseAuthorizedKeyLine(line string) (keyType, fingerprint, comment, options string, err error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", "", "", errors.New("empty")
	}
	toks := tokenize(line)
	for i, t := range toks {
		if !isKeyType(t) || i+1 >= len(toks) {
			continue
		}
		blob, derr := base64.StdEncoding.DecodeString(toks[i+1])
		if derr != nil {
			continue
		}
		// sanity: blob starts with its own key type string
		if bt, _, ok := readSSHString(blob); !ok || string(bt) != t {
			continue
		}
		return t, FingerprintBlob(blob), strings.Join(toks[i+2:], " "), strings.Join(toks[:i], " "), nil
	}
	return "", "", "", "", errors.New("no key found")
}

// ParseAuthorizedKeys parses a whole authorized_keys file.
func ParseAuthorizedKeys(r io.Reader, user, file string) []model.AuthorizedKey {
	var out []model.AuthorizedKey
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		kt, fp, comment, opts, err := ParseAuthorizedKeyLine(sc.Text())
		if err != nil {
			continue
		}
		out = append(out, model.AuthorizedKey{User: user, Fingerprint: fp, KeyType: kt, Comment: comment, Options: opts, File: file})
	}
	return out
}

func readSSHString(b []byte) ([]byte, []byte, bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(len(b)-4) < uint64(n) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

func sshMpint(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return sshString(b)
}

// MarshalPublicKey encodes a Go public key in SSH wire format.
func MarshalPublicKey(pub any) ([]byte, string, error) {
	var buf bytes.Buffer
	switch k := pub.(type) {
	case *rsa.PublicKey:
		buf.Write(sshString([]byte("ssh-rsa")))
		buf.Write(sshMpint(big.NewInt(int64(k.E))))
		buf.Write(sshMpint(k.N))
		return buf.Bytes(), "ssh-rsa", nil
	case ed25519.PublicKey:
		buf.Write(sshString([]byte("ssh-ed25519")))
		buf.Write(sshString(k))
		return buf.Bytes(), "ssh-ed25519", nil
	case *ecdsa.PublicKey:
		var curve string
		switch k.Curve {
		case elliptic.P256():
			curve = "nistp256"
		case elliptic.P384():
			curve = "nistp384"
		case elliptic.P521():
			curve = "nistp521"
		default:
			return nil, "", errors.New("unsupported curve")
		}
		kt := "ecdsa-sha2-" + curve
		buf.Write(sshString([]byte(kt)))
		buf.Write(sshString([]byte(curve)))
		//nolint:staticcheck // elliptic.Marshal is the SSH uncompressed point format
		buf.Write(sshString(elliptic.Marshal(k.Curve, k.X, k.Y)))
		return buf.Bytes(), kt, nil
	}
	return nil, "", errors.New("unsupported key type")
}

// PrivateKeyInfo describes a private key file without retaining secret material.
type PrivateKeyInfo struct {
	IsKey       bool
	Encrypted   *bool
	Format      string // openssh | pem-rsa | pem-ec | pkcs8 | pkcs8-encrypted | putty
	KeyType     string
	Fingerprint string // of the public half, when derivable
}

// InspectPrivateKey examines private key bytes. Secret material is parsed
// only to derive the public key (unencrypted PEM) and is discarded.
func InspectPrivateKey(data []byte) PrivateKeyInfo {
	info := PrivateKeyInfo{}
	if bytes.HasPrefix(data, []byte("PuTTY-User-Key-File")) {
		info.IsKey, info.Format = true, "putty"
		enc := !bytes.Contains(data, []byte("Encryption: none"))
		info.Encrypted = &enc
		return info
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return info
	}
	switch block.Type {
	case "OPENSSH PRIVATE KEY":
		info.IsKey, info.Format = true, "openssh"
		cipher, pubBlob, err := parseOpenSSHKeyV1(block.Bytes)
		if err != nil {
			return info
		}
		enc := cipher != "none"
		info.Encrypted = &enc
		if kt, _, ok := readSSHString(pubBlob); ok {
			info.KeyType = string(kt)
		}
		info.Fingerprint = FingerprintBlob(pubBlob)
	case "ENCRYPTED PRIVATE KEY":
		info.IsKey, info.Format = true, "pkcs8-encrypted"
		t := true
		info.Encrypted = &t
	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "PRIVATE KEY":
		info.IsKey = true
		info.Format = map[string]string{"RSA PRIVATE KEY": "pem-rsa", "EC PRIVATE KEY": "pem-ec",
			"DSA PRIVATE KEY": "pem-dsa", "PRIVATE KEY": "pkcs8"}[block.Type]
		//nolint:staticcheck // legacy PEM encryption detection only
		if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
			t := true
			info.Encrypted = &t
			return info
		}
		f := false
		info.Encrypted = &f
		var pub any
		switch block.Type {
		case "RSA PRIVATE KEY":
			if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				pub = &k.PublicKey
			}
		case "EC PRIVATE KEY":
			if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				pub = &k.PublicKey
			}
		case "PRIVATE KEY":
			if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				switch kk := k.(type) {
				case *rsa.PrivateKey:
					pub = &kk.PublicKey
				case *ecdsa.PrivateKey:
					pub = &kk.PublicKey
				case ed25519.PrivateKey:
					pub = kk.Public()
				}
			}
		}
		if pub != nil {
			if blob, kt, err := MarshalPublicKey(pub); err == nil {
				info.KeyType = kt
				info.Fingerprint = FingerprintBlob(blob)
			}
		}
	}
	return info
}

// parseOpenSSHKeyV1 returns the cipher name and the (always cleartext)
// first public key blob of an openssh-key-v1 container.
func parseOpenSSHKeyV1(b []byte) (cipher string, pub []byte, err error) {
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(b, []byte(magic)) {
		return "", nil, errors.New("bad magic")
	}
	rest := b[len(magic):]
	c, rest, ok := readSSHString(rest)
	if !ok {
		return "", nil, errors.New("truncated cipher")
	}
	if _, rest, ok = readSSHString(rest); !ok { // kdfname
		return "", nil, errors.New("truncated kdf")
	}
	if _, rest, ok = readSSHString(rest); !ok { // kdfoptions
		return "", nil, errors.New("truncated kdfopts")
	}
	if len(rest) < 4 {
		return "", nil, errors.New("truncated nkeys")
	}
	n := binary.BigEndian.Uint32(rest)
	rest = rest[4:]
	if n < 1 {
		return string(c), nil, errors.New("no keys")
	}
	pubBlob, _, ok := readSSHString(rest)
	if !ok {
		return string(c), nil, errors.New("truncated pubkey")
	}
	return string(c), pubBlob, nil
}

// ------------------------------------------------------------ known_hosts

// ParseKnownHosts returns one entry per host pattern.
func ParseKnownHosts(r io.Reader, user string) []model.KnownHost {
	var out []model.KnownHost
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if strings.HasPrefix(f[0], "@") { // @cert-authority / @revoked
			if f[0] == "@revoked" {
				continue
			}
			f = f[1:]
		}
		if len(f) < 3 {
			continue
		}
		kt := f[1]
		if strings.HasPrefix(f[0], "|1|") {
			out = append(out, model.KnownHost{User: user, Host: "", Hashed: true, KeyType: kt})
			continue
		}
		for _, h := range strings.Split(f[0], ",") {
			if h == "" || strings.ContainsAny(h, "*?!") {
				continue
			}
			// [host]:port -> host:port (keep port when non-standard)
			if strings.HasPrefix(h, "[") {
				if j := strings.Index(h, "]"); j > 0 {
					host, port := h[1:j], strings.TrimPrefix(h[j+1:], ":")
					if port != "" && port != "22" {
						h = host + ":" + port
					} else {
						h = host
					}
				}
			}
			out = append(out, model.KnownHost{User: user, Host: h, KeyType: kt})
		}
	}
	return out
}

// ------------------------------------------------------------ sshd_config

var sshdDefaults = model.SSHDConfig{
	Port: 22, PermitRootLogin: "prohibit-password", PasswordAuthentication: "yes",
	PubkeyAuthentication: "yes", PermitEmptyPasswords: "no", X11Forwarding: "no", MaxAuthTries: 6,
}

// ParseSSHDConfig computes the effective global sshd settings from the main
// config file. Semantics follow sshd: the first value obtained for a keyword
// wins, Include is processed in place (relative paths are under baseDir),
// and keywords inside Match blocks are conditional so they are ignored.
// readFile is injectable for tests.
func ParseSSHDConfig(path, baseDir string, readFile func(string) ([]byte, error)) model.SSHDConfig {
	if readFile == nil {
		readFile = os.ReadFile
	}
	vals := map[string]string{}
	var allowUsers []string
	present := false
	var walk func(p string, depth int)
	walk = func(p string, depth int) {
		if depth > 8 {
			return
		}
		data, err := readFile(p)
		if err != nil {
			return
		}
		present = true
		inMatch := false
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, val := splitKV(line)
			lk := strings.ToLower(key)
			if lk == "match" {
				inMatch = true
				continue
			}
			if inMatch {
				continue
			}
			if lk == "include" {
				for _, pat := range strings.Fields(val) {
					if !filepath.IsAbs(pat) {
						pat = filepath.Join(baseDir, pat)
					}
					matches, _ := filepath.Glob(pat)
					if len(matches) == 0 && !strings.ContainsAny(pat, "*?[") {
						matches = []string{pat}
					}
					for _, m := range matches {
						walk(m, depth+1)
					}
				}
				continue
			}
			if lk == "allowusers" {
				allowUsers = append(allowUsers, strings.Fields(val)...)
				continue
			}
			if _, ok := vals[lk]; !ok {
				vals[lk] = val
			}
		}
	}
	walk(path, 0)
	if !present {
		return model.SSHDConfig{Present: false}
	}
	c := sshdDefaults
	c.Present = true
	if v, ok := vals["port"]; ok {
		if p, err := strconv.Atoi(strings.Fields(v)[0]); err == nil {
			c.Port = p
		}
	}
	set := func(k string, dst *string) {
		if v, ok := vals[k]; ok {
			*dst = strings.ToLower(v)
		}
	}
	set("permitrootlogin", &c.PermitRootLogin)
	if c.PermitRootLogin == "without-password" {
		c.PermitRootLogin = "prohibit-password"
	}
	set("passwordauthentication", &c.PasswordAuthentication)
	set("pubkeyauthentication", &c.PubkeyAuthentication)
	set("permitemptypasswords", &c.PermitEmptyPasswords)
	set("x11forwarding", &c.X11Forwarding)
	if v, ok := vals["maxauthtries"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			c.MaxAuthTries = n
		}
	}
	c.AllowUsers = allowUsers
	return c
}

func splitKV(line string) (string, string) {
	// "Key value", "Key=value", "Key = value"
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return line, ""
	}
	k := line[:i]
	v := strings.TrimLeft(line[i:], " \t=")
	return k, strings.Trim(strings.TrimSpace(v), `"`)
}
