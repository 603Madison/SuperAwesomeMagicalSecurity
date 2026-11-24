package collect

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/603madison/superawesomemagicalsecurity/agent/internal/model"
)

// collectUserArtifacts gathers authorized_keys, credentials and known_hosts
// for every user with a real home directory.
func (c *collector) collectUserArtifacts(users []model.User) error {
	seenHome := map[string]bool{}
	for _, u := range users {
		if u.Home == "" || seenHome[u.Home] {
			continue
		}
		// Skip system accounts without a login shell unless uid 0; service
		// accounts like www-data can still hold keys, so include them when
		// the home has a .ssh directory.
		if !u.LoginEnabled && u.UID != 0 {
			if _, err := os.Stat(filepath.Join(u.Home, ".ssh")); err != nil {
				continue
			}
		}
		seenHome[u.Home] = true
		for _, ak := range []string{".ssh/authorized_keys", ".ssh/authorized_keys2"} {
			p := filepath.Join(u.Home, ak)
			if f, err := os.Open(p); err == nil {
				c.inv.AuthorizedKeys = append(c.inv.AuthorizedKeys, ParseAuthorizedKeys(f, u.Name, p)...)
				f.Close()
			}
		}
		creds, known := DiscoverCredentials(u.Home, u.Name)
		c.inv.Credentials = append(c.inv.Credentials, creds...)
		c.inv.KnownHosts = append(c.inv.KnownHosts, known...)
	}
	return nil
}

// collectSudoers parses a sudoers file and its includes.
func (c *collector) collectSudoers(root string) error {
	aliases := map[string][]string{}
	visited := map[string]bool{}
	var parse func(path string, depth int)
	parse = func(path string, depth int) {
		if depth > 5 || visited[path] {
			return
		}
		visited[path] = true
		f, err := os.Open(path)
		if err != nil {
			if !os.IsNotExist(err) {
				c.errf("sudoers %s: %v", path, err)
			}
			return
		}
		res := ParseSudoers(f, path, aliases)
		f.Close()
		c.inv.SudoRules = append(c.inv.SudoRules, res.Rules...)
		for _, inc := range res.Includes {
			if !filepath.IsAbs(inc) {
				inc = filepath.Join(filepath.Dir(path), inc)
			}
			parse(inc, depth+1)
		}
		for _, dir := range res.IncludeDirs {
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				n := e.Name()
				// sudo skips files ending in ~ or containing a '.'
				if e.IsDir() || strings.HasSuffix(n, "~") || strings.Contains(n, ".") {
					continue
				}
				parse(filepath.Join(dir, n), depth+1)
			}
		}
	}
	parse(root, 0)
	return nil
}
