package scan

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sort"
	"strings"
	"time"
)

// EvaluateSPF inspects the TXT records of a domain for SPF problems.
// Returns the SPF record ("" if none) and issues.
func EvaluateSPF(txt []string) (string, []Issue) {
	var spfs []string
	for _, t := range txt {
		lt := strings.ToLower(strings.TrimSpace(t))
		if lt == "v=spf1" || strings.HasPrefix(lt, "v=spf1 ") {
			spfs = append(spfs, strings.TrimSpace(t))
		}
	}
	if len(spfs) == 0 {
		return "", []Issue{{ID: "dns_spf_missing", Severity: "medium", Title: "No SPF record",
			Detail: "The domain publishes no SPF record, so anyone can send mail claiming to be from it. Publish e.g. \"v=spf1 -all\" (no mail) or list your senders and end with -all."}}
	}
	if len(spfs) > 1 {
		return spfs[0], []Issue{{ID: "dns_spf_multiple", Severity: "medium", Title: "Multiple SPF records",
			Detail: "More than one v=spf1 record is a PermError (RFC 7208 §4.5); receivers treat SPF as broken. Merge them into one record."}}
	}
	spf := spfs[0]
	var issues []Issue
	hasAll, hasRedirect := false, false
	for _, term := range strings.Fields(strings.ToLower(spf))[1:] {
		if strings.HasPrefix(term, "redirect=") {
			hasRedirect = true
		}
		q, mech := byte('+'), term
		if len(term) > 0 && strings.ContainsRune("+-~?", rune(term[0])) {
			q, mech = term[0], term[1:]
		}
		if mech != "all" {
			continue
		}
		hasAll = true
		switch q {
		case '+':
			issues = append(issues, Issue{ID: "dns_spf_permissive", Severity: "high", Title: "SPF allows any sender (+all)",
				Detail: "The SPF record ends in \"" + term + "\", authorizing every server on the internet to send as this domain. Use -all (or ~all while testing)."})
		case '?':
			issues = append(issues, Issue{ID: "dns_spf_permissive", Severity: "medium", Title: "SPF is neutral (?all)",
				Detail: "\"?all\" gives no protection against spoofing. Use -all (or ~all while testing)."})
		}
	}
	if !hasAll && !hasRedirect {
		issues = append(issues, Issue{ID: "dns_spf_permissive", Severity: "low", Title: "SPF has no 'all' mechanism",
			Detail: "Without a terminating -all/~all, unlisted senders get a neutral result. Append -all."})
	}
	return spf, issues
}

// EvaluateDMARC inspects TXT records at _dmarc.<domain>.
// Returns the record, the policy (p=) and issues.
func EvaluateDMARC(txt []string) (string, string, []Issue) {
	for _, t := range txt {
		rec := strings.TrimSpace(t)
		if !strings.HasPrefix(strings.ToLower(strings.ReplaceAll(rec, " ", "")), "v=dmarc1") {
			continue
		}
		tags := map[string]string{}
		for _, part := range strings.Split(rec, ";") {
			if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
				tags[strings.ToLower(strings.TrimSpace(k))] = strings.ToLower(strings.TrimSpace(v))
			}
		}
		p := tags["p"]
		switch p {
		case "reject", "quarantine":
			var issues []Issue
			if pct, ok := tags["pct"]; ok && pct != "100" {
				issues = append(issues, Issue{ID: "dns_dmarc_partial", Severity: "low", Title: "DMARC policy applies to only " + pct + "% of mail",
					Detail: "Raise pct to 100 once reports look clean."})
			}
			return rec, p, issues
		case "none":
			return rec, p, []Issue{{ID: "dns_dmarc_none", Severity: "low", Title: "DMARC policy is p=none (monitor only)",
				Detail: "Spoofed mail is still delivered. After reviewing aggregate reports, move to p=quarantine then p=reject."}}
		default:
			return rec, p, []Issue{{ID: "dns_dmarc_invalid", Severity: "medium", Title: "DMARC record has no valid policy",
				Detail: "The record lacks a valid p= tag (none|quarantine|reject); receivers may ignore it."}}
		}
	}
	return "", "", []Issue{{ID: "dns_dmarc_missing", Severity: "medium", Title: "No DMARC record",
		Detail: "No v=DMARC1 record at _dmarc. Receivers cannot enforce SPF/DKIM alignment, which makes spoofing this domain easy. Start with \"v=DMARC1; p=none; rua=mailto:...\" and tighten."}}
}

// checkAXFR asks a nameserver for a full zone transfer; true if it hands over records.
func checkAXFR(server, zone string, timeout time.Duration) (bool, error) {
	q, err := buildQuery(uint16(rand.Intn(65535)), zone, dnsTypeAXFR, false)
	if err != nil {
		return false, err
	}
	m, err := dnsExchangeTCP(server, q, timeout)
	if err != nil {
		return false, err
	}
	return m.Flags&dnsFlagQR != 0 && m.rcode() == 0 && len(m.Answers) > 0, nil
}

// checkOpenResolver sends a recursive query for a public name to server.
// Returns (responded, recursive).
func checkOpenResolver(server string, timeout time.Duration) (bool, bool) {
	q, err := buildQuery(uint16(rand.Intn(65535)), "example.com", dnsTypeA, true)
	if err != nil {
		return false, false
	}
	m, err := dnsExchangeUDP(server, q, timeout)
	if err != nil {
		return false, false
	}
	return true, m.Flags&dnsFlagRA != 0 && m.rcode() == 0 && len(m.Answers) > 0
}

func isNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// dnsChecks performs record lookups and email/DNS hygiene checks for a hostname target.
func (s *Scanner) dnsChecks(ctx context.Context, name string, tr *TargetResult) {
	r := net.DefaultResolver
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	d := tr.DNS

	if addrs, err := r.LookupIPAddr(ctx, name); err == nil {
		var a, aaaa []string
		for _, ip := range addrs {
			if ip.IP.To4() != nil {
				a = append(a, ip.IP.String())
			} else {
				aaaa = append(aaaa, ip.IP.String())
			}
		}
		d["a"], d["aaaa"] = nonNil(a), nonNil(aaaa)
	}
	var mx []string
	if recs, err := r.LookupMX(ctx, name); err == nil {
		for _, m := range recs {
			mx = append(mx, strings.TrimSuffix(m.Host, "."))
		}
	}
	d["mx"] = nonNil(mx)
	var ns []string
	if recs, err := r.LookupNS(ctx, name); err == nil {
		for _, n := range recs {
			ns = append(ns, strings.TrimSuffix(n.Host, "."))
		}
	}
	sort.Strings(ns)
	d["ns"] = nonNil(ns)
	txt, _ := r.LookupTXT(ctx, name)
	d["txt"] = nonNil(txt)

	// CAA via raw query to the system resolver
	resolver := s.opts.DNSServer
	if resolver == "" {
		resolver = systemNameserver()
	}
	if q, err := buildQuery(uint16(rand.Intn(65535)), name, dnsTypeCAA, true); err == nil {
		if m, err := dnsExchangeUDP(resolver, q, 3*time.Second); err == nil {
			var caa []string
			for _, a := range m.Answers {
				if a.Type == dnsTypeCAA {
					caa = append(caa, a.Value)
				}
			}
			d["caa"] = nonNil(caa)
		}
	}

	// Dangling CNAME (subdomain takeover candidate)
	if cname, err := r.LookupCNAME(ctx, name); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != "" && !strings.EqualFold(cname, strings.TrimSuffix(name, ".")) {
			d["cname"] = cname
			if _, err := r.LookupHost(ctx, cname); err != nil && isNotFound(err) {
				tr.Issues = append(tr.Issues, Issue{ID: "dns_dangling_cname", Severity: "high",
					Title:  "Dangling CNAME (possible subdomain takeover)",
					Detail: name + " is a CNAME to " + cname + ", which does not resolve. If that name belongs to a cloud service, an attacker may be able to claim it and serve content on your domain. Remove the record or re-provision the target."})
			}
		}
	} else if isNotFound(err) {
		d["nxdomain"] = true
	}

	// Email authentication: only meaningful for mail domains / zone apexes.
	if len(mx) > 0 || len(ns) > 0 {
		spf, spfIssues := EvaluateSPF(txt)
		d["spf"] = spf
		tr.Issues = append(tr.Issues, spfIssues...)
		dtxt, _ := r.LookupTXT(ctx, "_dmarc."+strings.TrimSuffix(name, "."))
		rec, policy, dIssues := EvaluateDMARC(dtxt)
		d["dmarc"], d["dmarc_policy"] = rec, policy
		tr.Issues = append(tr.Issues, dIssues...)
	} else {
		d["email_checks"] = "skipped (no MX or NS records; not a mail domain or zone apex)"
	}

	// Zone transfer against each authoritative server
	if len(ns) > 0 {
		axfrOpen := []string{}
		for i, server := range ns {
			if i >= 4 || ctx.Err() != nil {
				break
			}
			ips, err := r.LookupIP(ctx, "ip4", server)
			if err != nil || len(ips) == 0 {
				continue
			}
			if bad, _ := disallowed(ips[0]); bad && !s.opts.AllowPrivate {
				continue
			}
			if open, _ := checkAXFR(net.JoinHostPort(ips[0].String(), "53"), name, 4*time.Second); open {
				axfrOpen = append(axfrOpen, server)
			}
		}
		d["axfr_open"] = len(axfrOpen) > 0
		if len(axfrOpen) > 0 {
			tr.Issues = append(tr.Issues, Issue{ID: "dns_axfr_open", Severity: "high", Title: "DNS zone transfer (AXFR) allowed",
				Detail: "Nameserver(s) " + strings.Join(axfrOpen, ", ") + " hand the full zone to anyone, disclosing every hostname (internal names, VPN, admin hosts). Restrict AXFR to secondary nameservers (allow-transfer / TSIG)."})
		}
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
