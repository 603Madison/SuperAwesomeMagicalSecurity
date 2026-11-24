package collect

import (
	"bufio"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/603madison/superawesomemagicalsecurity/agent/internal/model"
)

var adminGroups = map[string]bool{"sudo": true, "wheel": true, "admin": true, "root": false, "Administrators": true}

var nologinShells = []string{"nologin", "/false", "/sync", "/shutdown", "/halt"}

// ParsePasswd parses /etc/passwd format.
func ParsePasswd(r io.Reader) []model.User {
	var out []model.User
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		gid, _ := strconv.Atoi(f[3])
		u := model.User{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6], PasswordState: "unknown"}
		u.LoginEnabled = shellAllowsLogin(u.Shell)
		out = append(out, u)
	}
	return out
}

func shellAllowsLogin(shell string) bool {
	if shell == "" {
		return true // empty shell means /bin/sh
	}
	for _, s := range nologinShells {
		if strings.HasSuffix(shell, s) {
			return false
		}
	}
	return true
}

// ParseGroup parses /etc/group format.
func ParseGroup(r io.Reader) []model.Group {
	var out []model.Group
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 4 {
			continue
		}
		gid, _ := strconv.Atoi(f[2])
		g := model.Group{Name: f[0], GID: gid}
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				g.Members = append(g.Members, m)
			}
		}
		out = append(out, g)
	}
	return out
}

// ParseShadow returns user -> password_state (set|empty|locked).
// The hash itself is never retained.
func ParseShadow(r io.Reader) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 2 || f[0] == "" {
			continue
		}
		h := f[1]
		switch {
		case h == "":
			out[f[0]] = "empty"
		case strings.HasPrefix(h, "!") || strings.HasPrefix(h, "*"):
			out[f[0]] = "locked"
		default:
			out[f[0]] = "set"
		}
	}
	return out
}

// MergeIdentity fills user.Groups / IsAdmin / PasswordState from groups and shadow.
func MergeIdentity(users []model.User, groups []model.Group, shadow map[string]string) {
	gidName := map[int]string{}
	member := map[string][]string{}
	for _, g := range groups {
		gidName[g.GID] = g.Name
		for _, m := range g.Members {
			member[m] = append(member[m], g.Name)
		}
	}
	for i := range users {
		u := &users[i]
		set := map[string]bool{}
		if n, ok := gidName[u.GID]; ok {
			set[n] = true
		}
		for _, g := range member[u.Name] {
			set[g] = true
		}
		u.Groups = u.Groups[:0]
		for g := range set {
			u.Groups = append(u.Groups, g)
		}
		sort.Strings(u.Groups)
		u.IsAdmin = u.UID == 0
		for _, g := range u.Groups {
			if adminGroups[g] {
				u.IsAdmin = true
			}
		}
		if st, ok := shadow[u.Name]; ok {
			u.PasswordState = st
		}
		if u.Groups == nil {
			u.Groups = []string{}
		}
	}
}

// ---------------------------------------------------------------- sudoers

var sudoTagRe = regexp.MustCompile(`^(NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT|MAIL|NOMAIL|FOLLOW|NOFOLLOW|INTERCEPT|NOINTERCEPT)\s*:\s*`)

// SudoersParse holds the result of parsing one sudoers file.
type SudoersParse struct {
	Rules       []model.SudoRule
	Includes    []string // files from #include / @include
	IncludeDirs []string // dirs from #includedir / @includedir
}

// ParseSudoers parses a sudoers file. Aliases defined earlier in the same
// file (or passed in via aliases, shared across files) are expanded
// best-effort. Defaults lines are ignored.
func ParseSudoers(r io.Reader, source string, aliases map[string][]string) SudoersParse {
	if aliases == nil {
		aliases = map[string][]string{}
	}
	var res SudoersParse
	sc := bufio.NewScanner(r)
	var logical []string
	var buf strings.Builder
	for sc.Scan() {
		line := sc.Text()
		if strings.HasSuffix(line, "\\") {
			buf.WriteString(strings.TrimSuffix(line, "\\"))
			buf.WriteString(" ")
			continue
		}
		buf.WriteString(line)
		logical = append(logical, buf.String())
		buf.Reset()
	}
	if buf.Len() > 0 {
		logical = append(logical, buf.String())
	}

	for _, raw := range logical {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// include directives (the "#" form is not a comment)
		for _, p := range []string{"#includedir ", "@includedir "} {
			if v, ok := strings.CutPrefix(line, p); ok {
				res.IncludeDirs = append(res.IncludeDirs, strings.TrimSpace(v))
				line = ""
			}
		}
		for _, p := range []string{"#include ", "@include "} {
			if v, ok := strings.CutPrefix(line, p); ok {
				res.Includes = append(res.Includes, strings.TrimSpace(v))
				line = ""
			}
		}
		if line == "" {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || strings.HasPrefix(line, "Defaults") {
			continue
		}
		// aliases
		aliasDone := false
		for _, kw := range []string{"User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias", "Cmd_Alias"} {
			if v, ok := strings.CutPrefix(line, kw+" "); ok {
				// NAME = a, b : NAME2 = c
				for _, def := range strings.Split(v, ":") {
					name, vals, ok := strings.Cut(def, "=")
					if !ok {
						continue
					}
					aliases[strings.TrimSpace(name)] = splitList(vals)
				}
				aliasDone = true
				break
			}
		}
		if aliasDone {
			continue
		}
		left, right, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		lf := strings.Fields(left)
		if len(lf) < 2 {
			continue
		}
		userPart := strings.Join(lf[:len(lf)-1], " ")
		users := expand(splitList(userPart), aliases)

		right = strings.TrimSpace(right)
		runas := "root"
		if strings.HasPrefix(right, "(") {
			if j := strings.Index(right, ")"); j > 0 {
				runas = strings.TrimSpace(right[1:j])
				right = strings.TrimSpace(right[j+1:])
			}
		}
		nopasswd := false
		for {
			m := sudoTagRe.FindStringSubmatch(right)
			if m == nil {
				break
			}
			if m[1] == "NOPASSWD" {
				nopasswd = true
			} else if m[1] == "PASSWD" {
				nopasswd = false
			}
			right = right[len(m[0]):]
		}
		cmds := expand(splitList(right), aliases)
		if len(cmds) == 0 {
			continue
		}
		for _, u := range users {
			res.Rules = append(res.Rules, model.SudoRule{
				Principal: u, RunAs: runas, Commands: cmds, NoPasswd: nopasswd, Source: source,
			})
		}
	}
	return res
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func expand(items []string, aliases map[string][]string) []string {
	var out []string
	var walk func(string, int)
	walk = func(it string, depth int) {
		neg := strings.HasPrefix(it, "!")
		name := strings.TrimPrefix(it, "!")
		if vals, ok := aliases[name]; ok && depth < 8 && !neg {
			for _, v := range vals {
				walk(v, depth+1)
			}
			return
		}
		out = append(out, it)
	}
	for _, it := range items {
		walk(it, 0)
	}
	return out
}
