package scan

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"
	"strings"
	"time"
)

var tlsVersionNames = map[uint16]string{
	tls.VersionTLS10: "TLS1.0",
	tls.VersionTLS11: "TLS1.1",
	tls.VersionTLS12: "TLS1.2",
	tls.VersionTLS13: "TLS1.3",
}

// allCipherSuites offers every suite Go implements, including insecure ones,
// so we learn what the *server* accepts rather than what Go prefers.
func allCipherSuites() []uint16 {
	var ids []uint16
	for _, c := range tls.CipherSuites() {
		ids = append(ids, c.ID)
	}
	for _, c := range tls.InsecureCipherSuites() {
		ids = append(ids, c.ID)
	}
	return ids
}

// weakCipherSuites are suites we flag if a server will negotiate them.
func weakCipherSuites() []uint16 {
	var ids []uint16
	for _, c := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if isWeakCipher(c.Name) {
			ids = append(ids, c.ID)
		}
	}
	return ids
}

func isWeakCipher(name string) bool {
	return strings.Contains(name, "RC4") || strings.Contains(name, "3DES") || strings.Contains(name, "CBC") ||
		strings.Contains(name, "NULL") || strings.Contains(name, "EXPORT")
}

func isBrokenCipher(name string) bool {
	return strings.Contains(name, "RC4") || strings.Contains(name, "3DES") || strings.Contains(name, "NULL") ||
		strings.Contains(name, "EXPORT")
}

func (s *Scanner) tlsDial(ip, sni string, port int, cfg *tls.Config) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: s.opts.ConnectTimeout}
	cfg.InsecureSkipVerify = true // we inspect certificates ourselves
	if sni != "" && net.ParseIP(sni) == nil {
		cfg.ServerName = sni
	}
	conn, err := d.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	tc := tls.Client(conn, cfg)
	_ = tc.SetDeadline(time.Now().Add(s.opts.IOTimeout))
	if err := tc.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return tc, nil
}

// detectTLS returns true if the port completes a TLS handshake.
func (s *Scanner) detectTLS(ip, sni string, port int) bool {
	c, err := s.tlsDial(ip, sni, port, &tls.Config{MinVersion: tls.VersionTLS10, CipherSuites: allCipherSuites()})
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// tlsInspect records protocol versions, certificate and cipher details.
func (s *Scanner) tlsInspect(ip, host string, isName bool, port int) (map[string]any, []Issue) {
	sni := ""
	if isName {
		sni = host
	}
	c, err := s.tlsDial(ip, sni, port, &tls.Config{MinVersion: tls.VersionTLS10, CipherSuites: allCipherSuites()})
	if err != nil {
		return nil, nil
	}
	st := c.ConnectionState()
	c.Close()

	info := map[string]any{
		"negotiated_version": tlsVersionNames[st.Version],
		"cipher":             tls.CipherSuiteName(st.CipherSuite),
	}
	var issues []Issue

	// supported protocol versions
	versions := []string{}
	var legacy []string
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {
		cfg := &tls.Config{MinVersion: v, MaxVersion: v}
		if v != tls.VersionTLS13 {
			cfg.CipherSuites = allCipherSuites()
		}
		if tc, err := s.tlsDial(ip, sni, port, cfg); err == nil {
			tc.Close()
			versions = append(versions, tlsVersionNames[v])
			if v < tls.VersionTLS12 {
				legacy = append(legacy, tlsVersionNames[v])
			}
		}
	}
	info["versions"] = versions
	if len(legacy) > 0 {
		issues = append(issues, Issue{ID: "tls_legacy_protocol", Severity: "medium", Port: port,
			Title:  "Deprecated TLS versions enabled: " + strings.Join(legacy, ", "),
			Detail: "TLS 1.0/1.1 are deprecated (RFC 8996) and lack modern protections. Disable them and require TLS 1.2+."})
	}
	if len(versions) > 0 && !contains(versions, "TLS1.2") && !contains(versions, "TLS1.3") {
		issues = append(issues, Issue{ID: "tls_no_modern_protocol", Severity: "high", Port: port,
			Title: "No TLS 1.2/1.3 support", Detail: "The service only speaks deprecated TLS versions."})
	}

	// weak ciphers: will the server agree to a suite from the weak list?
	weak := []string{}
	if tc, err := s.tlsDial(ip, sni, port, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12,
		CipherSuites: weakCipherSuites()}); err == nil {
		name := tls.CipherSuiteName(tc.ConnectionState().CipherSuite)
		tc.Close()
		weak = append(weak, name)
		sev := "low"
		if isBrokenCipher(name) {
			sev = "medium"
		}
		issues = append(issues, Issue{ID: "tls_weak_cipher", Severity: sev, Port: port,
			Title:  "Weak cipher suite accepted: " + name,
			Detail: "The server negotiates " + name + " when offered only weak suites. Restrict to AEAD suites (AES-GCM, ChaCha20-Poly1305) with ECDHE."})
	}
	info["weak_ciphers"] = weak

	// certificate
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		now := s.opts.Now()
		daysLeft := int(leaf.NotAfter.Sub(now).Hours() / 24)
		selfSigned := bytes.Equal(leaf.RawIssuer, leaf.RawSubject) && leaf.CheckSignatureFrom(leaf) == nil
		sans := append([]string{}, leaf.DNSNames...)
		for _, ip := range leaf.IPAddresses {
			sans = append(sans, ip.String())
		}
		info["cert_subject"] = leaf.Subject.String()
		info["cert_issuer"] = leaf.Issuer.String()
		info["sans"] = sans
		info["not_before"] = leaf.NotBefore.UTC().Format(time.RFC3339)
		info["not_after"] = leaf.NotAfter.UTC().Format(time.RFC3339)
		info["days_left"] = daysLeft
		info["self_signed"] = selfSigned
		info["sig_alg"] = leaf.SignatureAlgorithm.String()
		info["key_type"], info["key_bits"] = keyInfo(leaf)

		// chain trust against system roots
		inter := x509.NewCertPool()
		for _, c := range st.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		vopts := x509.VerifyOptions{Intermediates: inter, CurrentTime: now}
		if isName {
			vopts.DNSName = host
		}
		if _, err := leaf.Verify(vopts); err != nil {
			info["trusted"] = false
			info["verify_error"] = err.Error()
		} else {
			info["trusted"] = true
		}
		mismatch := false
		if isName {
			mismatch = leaf.VerifyHostname(host) != nil
		}
		info["hostname_mismatch"] = mismatch

		switch {
		case now.After(leaf.NotAfter):
			issues = append(issues, Issue{ID: "tls_cert_expired", Severity: "high", Port: port,
				Title:  "TLS certificate expired",
				Detail: "Certificate for " + leaf.Subject.CommonName + " expired on " + leaf.NotAfter.UTC().Format("2006-01-02") + ". Users learn to click through warnings, which enables MITM."})
		case daysLeft < 14:
			issues = append(issues, Issue{ID: "tls_cert_expiring", Severity: "low", Port: port,
				Title:  "TLS certificate expires in " + strconv.Itoa(daysLeft) + " days",
				Detail: "Renew the certificate (automate with ACME)."})
		}
		if selfSigned {
			issues = append(issues, Issue{ID: "tls_cert_self_signed", Severity: "medium", Port: port,
				Title:  "Self-signed TLS certificate",
				Detail: "Clients cannot authenticate this service. Use a publicly trusted certificate (e.g. Let's Encrypt) or don't expose it to the internet."})
		}
		if mismatch {
			issues = append(issues, Issue{ID: "tls_hostname_mismatch", Severity: "medium", Port: port,
				Title:  "TLS certificate does not match " + host,
				Detail: "The certificate is not valid for the name clients use (SANs: " + strings.Join(sans, ", ") + ")."})
		}
		if k, bits := info["key_type"], info["key_bits"]; k == "RSA" && bits.(int) < 2048 {
			issues = append(issues, Issue{ID: "tls_weak_key", Severity: "medium", Port: port,
				Title: "Weak RSA key (" + strconv.Itoa(bits.(int)) + " bits)", Detail: "Use RSA ≥ 2048 bits or ECDSA P-256."})
		}
	}
	return info, issues
}

func keyInfo(c *x509.Certificate) (string, int) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	}
	return "unknown", 0
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
