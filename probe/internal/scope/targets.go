// Package scope decides *what* the probe may scan: it parses port specs,
// expands and validates targets, and verifies server-signed job envelopes.
package scope

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strings"
)

// MaxCIDRHosts is the largest CIDR a single scope entry may expand to.
const MaxCIDRHosts = 256

// LookupFunc resolves a hostname to IPs (injectable for tests).
type LookupFunc func(ctx context.Context, host string) ([]net.IP, error)

// DefaultLookup uses the system resolver.
func DefaultLookup(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// Target is one scannable host.
type Target struct {
	Input  string   // as given (IP, or hostname; CIDRs are expanded to IPs)
	Host   string   // hostname or IP literal used for SNI / Host headers
	IsName bool     // Host is a DNS name
	IPs    []net.IP // resolved addresses; IPs[0] is scanned
}

// Refusal is a target that was rejected, with the reason.
type Refusal struct {
	Input  string
	Reason string
}

var hostnameRe = regexp.MustCompile(`^(?i)[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*\.?$`)

var disallowedNets = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",       // "this network"
		"10.0.0.0/8",      // RFC1918
		"100.64.0.0/10",   // CGNAT
		"127.0.0.0/8",     // loopback
		"169.254.0.0/16",  // link local
		"172.16.0.0/12",   // RFC1918
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"192.88.99.0/24",  // 6to4 relay anycast (deprecated)
		"192.168.0.0/16",  // RFC1918
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved + broadcast
		"::/128",          // unspecified
		"::1/128",         // loopback
		"64:ff9b:1::/48",  // local-use NAT64
		"100::/64",        // discard-only
		"2001:db8::/32",   // documentation
		"fc00::/7",        // ULA
		"fe80::/10",       // link local
		"ff00::/8",        // multicast
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}()

// Disallowed reports whether ip is private/loopback/link-local/CGNAT/multicast/
// reserved, i.e. something an off-network probe has no business scanning.
func Disallowed(ip net.IP) (bool, string) {
	if ip == nil {
		return true, "invalid address"
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range disallowedNets {
		if n.Contains(ip) {
			return true, fmt.Sprintf("%s is in non-public range %s", ip, n)
		}
	}
	return false, ""
}

// normalize strips schemes, paths, ports and whitespace from a target string.
func normalize(in string) string {
	s := strings.TrimSpace(strings.ToLower(in))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if isCIDR(s) {
		return s
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// strip :port for hostnames / IPv4 (not for bare IPv6)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.TrimSuffix(strings.Trim(s, "[]"), ".")
}

func isCIDR(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// Expand turns scope entries (IPs, CIDRs, hostnames) into targets, refusing
// anything non-public unless allowPrivate is set (standalone mode only).
func Expand(ctx context.Context, inputs []string, allowPrivate bool, lookup LookupFunc) ([]Target, []Refusal) {
	if lookup == nil {
		lookup = DefaultLookup
	}
	var targets []Target
	var refused []Refusal
	seen := map[string]bool{}
	add := func(t Target) {
		key := t.Host
		if seen[key] {
			return
		}
		seen[key] = true
		targets = append(targets, t)
	}
	for _, raw := range inputs {
		in := normalize(raw)
		if in == "" {
			continue
		}
		// CIDR
		if ip, n, err := net.ParseCIDR(in); err == nil {
			ones, bits := n.Mask.Size()
			count := new(big.Int).Lsh(big.NewInt(1), uint(bits-ones))
			if count.Cmp(big.NewInt(MaxCIDRHosts)) > 0 {
				refused = append(refused, Refusal{raw, fmt.Sprintf("CIDR %s has %s addresses (max %d)", in, count, MaxCIDRHosts)})
				continue
			}
			_ = ip
			for _, a := range expandCIDR(n) {
				if bad, why := Disallowed(a); bad && !allowPrivate {
					refused = append(refused, Refusal{a.String(), why})
					continue
				}
				add(Target{Input: a.String(), Host: a.String(), IPs: []net.IP{a}})
			}
			continue
		}
		// IP literal
		if ip := net.ParseIP(in); ip != nil {
			if bad, why := Disallowed(ip); bad && !allowPrivate {
				refused = append(refused, Refusal{raw, why})
				continue
			}
			add(Target{Input: in, Host: ip.String(), IPs: []net.IP{ip}})
			continue
		}
		// hostname
		if !hostnameRe.MatchString(in) || !strings.Contains(in, ".") && in != "localhost" {
			refused = append(refused, Refusal{raw, "not an IP, CIDR or fully-qualified hostname"})
			continue
		}
		ips, err := lookup(ctx, in)
		if err != nil || len(ips) == 0 {
			// keep the name: DNS checks (SPF/DMARC/dangling CNAME) are still useful.
			add(Target{Input: in, Host: in, IsName: true})
			continue
		}
		bad := ""
		if !allowPrivate {
			for _, ip := range ips {
				if b, why := Disallowed(ip); b {
					bad = why
					break
				}
			}
		}
		if bad != "" {
			refused = append(refused, Refusal{raw, "resolves to a non-public address: " + bad})
			continue
		}
		// prefer IPv4 for scanning (the probe may not have IPv6 egress)
		ordered := make([]net.IP, 0, len(ips))
		for _, ip := range ips {
			if ip.To4() != nil {
				ordered = append(ordered, ip)
			}
		}
		for _, ip := range ips {
			if ip.To4() == nil {
				ordered = append(ordered, ip)
			}
		}
		add(Target{Input: in, Host: in, IsName: true, IPs: ordered})
	}
	return targets, refused
}

func expandCIDR(n *net.IPNet) []net.IP {
	var out []net.IP
	ip := make(net.IP, len(n.IP))
	copy(ip, n.IP.Mask(n.Mask))
	for n.Contains(ip) {
		c := make(net.IP, len(ip))
		copy(c, ip)
		out = append(out, c)
		// increment
		for i := len(ip) - 1; i >= 0; i-- {
			ip[i]++
			if ip[i] != 0 {
				break
			}
		}
		if len(out) > MaxCIDRHosts {
			break
		}
	}
	return out
}
