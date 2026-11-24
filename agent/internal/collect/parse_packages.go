package collect

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/603madison/superawesomemagicalsecurity/agent/internal/model"
)

// ParseDpkgStatus parses /var/lib/dpkg/status. Only packages whose Status is
// "install ok installed" are returned. The Source field ("name" or
// "name (version)") becomes source_name/source_version; when absent the
// binary name/version are used, since OSV matches Debian/Ubuntu advisories on
// source package names.
func ParseDpkgStatus(r io.Reader) []model.Package {
	var out []model.Package
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	fields := map[string]string{}
	lastKey := ""
	flush := func() {
		defer func() { fields = map[string]string{}; lastKey = "" }()
		if fields["Package"] == "" || fields["Version"] == "" {
			return
		}
		st := fields["Status"]
		if st != "" && !strings.HasSuffix(st, " installed") {
			return
		}
		if strings.Contains(st, "deinstall") || strings.Contains(st, "config-files") || strings.Contains(st, "not-installed") {
			return
		}
		p := model.Package{
			Name:    fields["Package"],
			Version: fields["Version"],
			Arch:    fields["Architecture"],
			Manager: "dpkg",
		}
		p.SourceName, p.SourceVersion = splitSourceField(fields["Source"])
		if p.SourceName == "" {
			p.SourceName = p.Name
		}
		if p.SourceVersion == "" {
			p.SourceVersion = p.Version
		}
		out = append(out, p)
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			// continuation of a multi-line field (Description, Conffiles...)
			_ = lastKey
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		lastKey = k
		fields[k] = strings.TrimSpace(v)
	}
	flush()
	return out
}

// splitSourceField parses dpkg's "Source: openssl (3.0.2-0ubuntu1.10)".
func splitSourceField(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	if i := strings.Index(s, " ("); i > 0 && strings.HasSuffix(s, ")") {
		return s[:i], s[i+2 : len(s)-1]
	}
	return s, ""
}

// ParseApkInstalled parses Alpine's /lib/apk/db/installed.
func ParseApkInstalled(r io.Reader) []model.Package {
	var out []model.Package
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	cur := model.Package{Manager: "apk"}
	flush := func() {
		if cur.Name != "" && cur.Version != "" {
			if cur.SourceName == "" {
				cur.SourceName = cur.Name
			}
			cur.SourceVersion = cur.Version
			out = append(out, cur)
		}
		cur = model.Package{Manager: "apk"}
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		v := line[2:]
		switch line[0] {
		case 'P':
			cur.Name = v
		case 'V':
			cur.Version = v
		case 'A':
			cur.Arch = v
		case 'o':
			cur.SourceName = v
		}
	}
	flush()
	return out
}

// ParseRpmQuery parses the output of
// rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n'.
func ParseRpmQuery(r io.Reader) []model.Package {
	var out []model.Package
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), "\t")
		if len(parts) < 4 || parts[0] == "" || strings.HasPrefix(parts[0], "gpg-pubkey") {
			continue
		}
		ver := parts[2]
		if e := parts[1]; e != "" && e != "(none)" && e != "0" {
			ver = e + ":" + ver
		}
		p := model.Package{Name: parts[0], Version: ver, Arch: parts[3], Manager: "rpm"}
		if len(parts) > 4 && parts[4] != "(none)" {
			p.SourceName = srpmName(parts[4])
		}
		out = append(out, p)
	}
	return out
}

// srpmName turns "openssl-3.0.7-25.el9.src.rpm" into "openssl".
func srpmName(srpm string) string {
	s := strings.TrimSuffix(srpm, ".src.rpm")
	s = strings.TrimSuffix(s, ".nosrc.rpm")
	// strip -release then -version
	for i := 0; i < 2; i++ {
		if j := strings.LastIndex(s, "-"); j > 0 {
			s = s[:j]
		}
	}
	return s
}

// ParsePythonMetadata reads Name/Version headers from a dist-info METADATA
// or egg-info PKG-INFO file.
func ParsePythonMetadata(r io.Reader) (name, version string) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break // end of headers
		}
		if v, ok := strings.CutPrefix(line, "Name: "); ok {
			name = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(line, "Version: "); ok {
			version = strings.TrimSpace(v)
		}
		if name != "" && version != "" {
			break
		}
	}
	return
}

// CollectPythonPackages scans site-packages style directories (glob
// patterns) for installed distributions. Bounded to maxPkgs results.
func CollectPythonPackages(patterns []string, maxPkgs int) []model.Package {
	var out []model.Package
	seen := map[string]bool{}
	for _, pat := range patterns {
		dirs, _ := filepath.Glob(pat)
		for _, dir := range dirs {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				n := e.Name()
				var meta string
				switch {
				case strings.HasSuffix(n, ".dist-info"):
					meta = filepath.Join(dir, n, "METADATA")
				case strings.HasSuffix(n, ".egg-info"):
					meta = filepath.Join(dir, n, "PKG-INFO")
					if !e.IsDir() {
						meta = filepath.Join(dir, n)
					}
				default:
					continue
				}
				f, err := os.Open(meta)
				if err != nil {
					continue
				}
				name, ver := ParsePythonMetadata(f)
				f.Close()
				if name == "" || ver == "" {
					continue
				}
				key := dir + "|" + strings.ToLower(name)
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, model.Package{Name: name, Version: ver, Manager: "pypi", Location: dir})
				if len(out) >= maxPkgs {
					return out
				}
			}
		}
	}
	return out
}

// CollectNpmGlobal reads package.json of globally installed node modules.
func CollectNpmGlobal(roots []string, maxPkgs int) []model.Package {
	var out []model.Package
	read := func(dir, loc string) {
		b, err := os.ReadFile(filepath.Join(dir, "package.json"))
		if err != nil {
			return
		}
		var pj struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(b, &pj) != nil || pj.Name == "" || pj.Version == "" {
			return
		}
		out = append(out, model.Package{Name: pj.Name, Version: pj.Version, Manager: "npm", Location: loc})
	}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if len(out) >= maxPkgs {
				return out
			}
			n := e.Name()
			if strings.HasPrefix(n, ".") {
				continue
			}
			p := filepath.Join(root, n)
			if strings.HasPrefix(n, "@") {
				sub, _ := os.ReadDir(p)
				for _, s := range sub {
					read(filepath.Join(p, s.Name()), root)
				}
				continue
			}
			read(p, root)
		}
	}
	return out
}
