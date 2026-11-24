package scan

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxBody = 256 * 1024

// Fingerprint identifies a web application / admin interface.
type Fingerprint struct {
	Name    string
	Class   string   // admin | app | vpn | router
	Title   []string // case-insensitive substrings of <title>
	Body    []string // case-insensitive substrings of body
	Headers []string // "header-name" (presence) or "header-name:substring"
}

// Fingerprints is ordered: more specific first.
var Fingerprints = []Fingerprint{
	{Name: "pfSense", Class: "admin", Title: []string{"pfsense"}, Body: []string{"login to pfsense", "pfsense - login", "netgate"}},
	{Name: "OPNsense", Class: "admin", Title: []string{"opnsense"}, Body: []string{"opnsense"}},
	{Name: "UniFi OS", Class: "admin", Title: []string{"unifi os", "unifi network", "unifi"}, Body: []string{"unifi-os", "unifi network", "ubnt", "ui.com/unifi"}},
	{Name: "Synology DSM", Class: "admin", Title: []string{"synology", "diskstation"}, Body: []string{"synology", "syno."}},
	{Name: "QNAP QTS", Class: "admin", Title: []string{"qts", "qnap"}, Body: []string{"qnap"}},
	{Name: "Proxmox VE", Class: "admin", Title: []string{"proxmox"}, Body: []string{"proxmox virtual environment", "pve-manager", "proxmoxlib"}},
	{Name: "TrueNAS", Class: "admin", Title: []string{"truenas", "freenas"}, Body: []string{"truenas", "freenas"}},
	{Name: "VMware vCenter", Class: "admin", Title: []string{"vsphere", "vcenter"}, Body: []string{"vmware vcenter", "vsphere-client"}},
	{Name: "VMware ESXi", Class: "admin", Title: []string{"vmware esxi"}, Body: []string{"vmware esxi", "esxui"}},
	{Name: "Portainer", Class: "admin", Title: []string{"portainer"}, Body: []string{"portainer"}},
	{Name: "Webmin", Class: "admin", Title: []string{"webmin"}, Body: []string{"webmin"}, Headers: []string{"server:miniserv"}},
	{Name: "Cockpit", Class: "admin", Title: []string{"cockpit"}, Body: []string{"cockpit"}},
	{Name: "phpMyAdmin", Class: "admin", Title: []string{"phpmyadmin"}, Body: []string{"phpmyadmin"}},
	{Name: "Kibana", Class: "admin", Title: []string{"kibana", "elastic"}, Body: []string{"kibana"}, Headers: []string{"kbn-name", "kbn-license-sig"}},
	{Name: "Jenkins", Class: "admin", Title: []string{"jenkins"}, Body: []string{"jenkins"}, Headers: []string{"x-jenkins"}},
	{Name: "RabbitMQ Management", Class: "admin", Title: []string{"rabbitmq management"}, Body: []string{"rabbitmq"}},
	{Name: "MikroTik RouterOS", Class: "router", Title: []string{"routeros", "mikrotik"}, Body: []string{"mikrotik", "routeros"}},
	{Name: "Fortinet FortiGate", Class: "vpn", Title: []string{"fortigate", "fortinet"}, Body: []string{"fortinet", "fgt_lang", "forticlient"}},
	{Name: "SonicWall", Class: "vpn", Title: []string{"sonicwall"}, Body: []string{"sonicwall", "sonicui"}},
	{Name: "Cisco ASA / AnyConnect", Class: "vpn", Title: []string{"ssl vpn service", "cisco asdm"}, Body: []string{"/+cscoe+/", "anyconnect", "webvpn"}, Headers: []string{"x-transcend-version"}},
	{Name: "Microsoft Exchange OWA", Class: "app", Title: []string{"outlook web app", "outlook"}, Body: []string{"/owa/auth", "outlook web app"}, Headers: []string{"x-owa-version"}},
	{Name: "GitLab", Class: "app", Title: []string{"gitlab"}, Body: []string{"gitlab"}},
	{Name: "Grafana", Class: "app", Title: []string{"grafana"}, Body: []string{"grafana-app", "grafanabootdata"}},
	{Name: "Home Assistant", Class: "app", Title: []string{"home assistant"}, Body: []string{"home-assistant", "home assistant"}},
	{Name: "Nextcloud", Class: "app", Title: []string{"nextcloud"}, Body: []string{"nextcloud"}},
	{Name: "Plex Media Server", Class: "app", Title: []string{"plex"}, Body: []string{"plex"}, Headers: []string{"x-plex-protocol"}},
}

var routerVendors = []string{"netgear", "tp-link", "tplink", "linksys", "asus", "d-link", "dlink", "zyxel",
	"draytek", "huawei", "zte", "technicolor", "arris", "ubiquiti", "edgeos", "openwrt", "luci", "dd-wrt", "tomato"}

var (
	reTitle      = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	rePassword   = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?password`)
	reDirListing = regexp.MustCompile(`(?i)(<title>\s*index of /|<h1>\s*index of /|directory listing for /)`)
)

// FingerprintHTTP identifies an application from title, body and headers.
// Returns (name, class) or ("", "").
func FingerprintHTTP(title, body string, headers http.Header) (string, string) {
	lt, lb := strings.ToLower(title), strings.ToLower(body)
	for _, fp := range Fingerprints {
		for _, h := range fp.Headers {
			name, sub, hasSub := strings.Cut(h, ":")
			v := headers.Get(name)
			if v != "" && (!hasSub || strings.Contains(strings.ToLower(v), sub)) {
				return fp.Name, fp.Class
			}
		}
		for _, t := range fp.Title {
			if lt != "" && strings.Contains(lt, t) {
				return fp.Name, fp.Class
			}
		}
	}
	// body markers are weaker; require a login form or very specific marker
	login := rePassword.MatchString(body)
	for _, fp := range Fingerprints {
		for _, b := range fp.Body {
			if strings.Contains(lb, b) && (login || len(b) > 8) {
				return fp.Name, fp.Class
			}
		}
	}
	// generic router login (title or basic-auth realm names a vendor)
	realm := strings.ToLower(headers.Get("WWW-Authenticate"))
	for _, v := range routerVendors {
		if strings.Contains(realm, v) || ((strings.Contains(lt, v) || strings.Contains(lt, "router")) && (login || realm != "")) {
			return "Router login", "router"
		}
	}
	return "", ""
}

func extractTitle(body string) string {
	m := reTitle.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.Join(strings.Fields(m[1]), " ")
	if len(t) > 200 {
		t = t[:200]
	}
	return t
}

var keptHeaders = []string{"Server", "X-Powered-By", "Strict-Transport-Security", "Content-Security-Policy",
	"X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Location",
	"WWW-Authenticate", "X-Jenkins", "X-OWA-Version", "Via"}

// MissingSecurityHeaders returns the recommended headers absent from a response.
func MissingSecurityHeaders(h http.Header, https bool) []string {
	var missing []string
	if https && h.Get("Strict-Transport-Security") == "" {
		missing = append(missing, "Strict-Transport-Security")
	}
	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		missing = append(missing, "Content-Security-Policy")
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
		missing = append(missing, "X-Frame-Options")
	}
	if h.Get("X-Content-Type-Options") == "" {
		missing = append(missing, "X-Content-Type-Options")
	}
	if h.Get("Referrer-Policy") == "" {
		missing = append(missing, "Referrer-Policy")
	}
	return missing
}

func (s *Scanner) httpClient(ip, host string, isName bool) *http.Client {
	dialer := &net.Dialer{Timeout: s.opts.ConnectTimeout}
	tr := &http.Transport{
		// Always connect to the scanned IP regardless of the URL host: keeps us in scope.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
		},
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, CipherSuites: allCipherSuites()},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 5 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		Proxy:                 nil,
	}
	if isName {
		tr.TLSClientConfig.ServerName = host
	}
	return &http.Client{
		Transport: tr,
		Timeout:   8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			// never follow redirects off the scoped host
			if !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

type httpResp struct {
	status   int
	headers  http.Header
	body     string
	finalURL string
}

func (s *Scanner) httpGet(ctx context.Context, client *http.Client, u string) (*httpResp, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sams-probe/"+s.opts.Version+" (+external posture check)")
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && len(b) == 0 {
		return nil, err
	}
	return &httpResp{status: resp.StatusCode, headers: resp.Header, body: string(b), finalURL: resp.Request.URL.String()}, nil
}

// httpInspect fetches / (and benign metadata paths for a few APIs) and fingerprints the service.
func (s *Scanner) httpInspect(ctx context.Context, ip, host string, isName bool, port int, https bool, svc *Service) []Issue {
	scheme := "http"
	if https {
		scheme = "https"
	}
	hostPort := host
	if net.ParseIP(host) != nil && strings.Contains(host, ":") {
		hostPort = "[" + host + "]"
	}
	base := (&url.URL{Scheme: scheme, Host: hostPort + ":" + strconv.Itoa(port)}).String()
	client := s.httpClient(ip, host, isName)
	r, err := s.httpGet(ctx, client, base+"/")
	if err != nil {
		return nil
	}
	title := extractTitle(r.body)
	info := map[string]any{
		"status":    r.status,
		"title":     title,
		"server":    r.headers.Get("Server"),
		"final_url": r.finalURL,
	}
	hdrs := map[string]string{}
	for _, h := range keptHeaders {
		if v := r.headers.Get(h); v != "" {
			if len(v) > 300 {
				v = v[:300]
			}
			hdrs[h] = v
		}
	}
	info["headers"] = hdrs
	missing := MissingSecurityHeaders(r.headers, https)
	if missing == nil {
		missing = []string{}
	}
	info["missing_security_headers"] = missing
	loginForm := rePassword.MatchString(r.body)
	info["login_form"] = loginForm
	name, class := FingerprintHTTP(title, r.body, r.headers)
	info["login_page"] = name
	info["app_class"] = class
	dirListing := reDirListing.MatchString(r.body)
	info["directory_listing"] = dirListing

	if svc.Service == "" || svc.Service == "http" || svc.Service == "https" || svc.Service == "tls" || svc.Service == "http-alt" {
		svc.Service = scheme
	}
	if svc.Product == "" {
		svc.Product = r.headers.Get("Server")
	}

	// Benign version endpoints for APIs that are catastrophic when exposed.
	lb := strings.ToLower(r.body)
	switch {
	case strings.Contains(lb, "you know, for search") || (strings.Contains(lb, "cluster_name") && strings.Contains(lb, "lucene_version")):
		svc.Service, svc.Product = "elasticsearch", "Elasticsearch"
		svc.unauthenticated = true
		if m := regexp.MustCompile(`"number"\s*:\s*"([^"]+)"`).FindStringSubmatch(r.body); m != nil {
			svc.Version = m[1]
		}
	case port == 2375 || port == 2376 || port == 2379 || port == 2380:
		if vr, err := s.httpGet(ctx, client, base+"/version"); err == nil && vr.status == 200 {
			vb := vr.body
			switch {
			case strings.Contains(vb, "ApiVersion"):
				svc.Service, svc.Product = "docker", "Docker Engine API"
				svc.unauthenticated = true
				if m := regexp.MustCompile(`"Version"\s*:\s*"([^"]+)"`).FindStringSubmatch(vb); m != nil {
					svc.Version = m[1]
				}
			case strings.Contains(vb, "etcdserver"):
				svc.Service, svc.Product = "etcd", "etcd"
				svc.unauthenticated = true
				if m := regexp.MustCompile(`"etcdserver"\s*:\s*"([^"]+)"`).FindStringSubmatch(vb); m != nil {
					svc.Version = m[1]
				}
			}
		}
	}
	svc.HTTP = info

	var issues []Issue
	if name != "" {
		switch class {
		case "admin", "router":
			issues = append(issues, Issue{ID: "admin_panel_exposed", Severity: "high", Port: port,
				Title:  name + " management interface exposed to the internet",
				Detail: "Infrastructure admin interfaces are prime targets (credential stuffing, auth-bypass CVEs). Restrict to VPN/allowlisted sources or the management VLAN."})
		case "vpn":
			issues = append(issues, Issue{ID: "vpn_portal_exposed", Severity: "medium", Port: port,
				Title:  name + " VPN/SSL portal exposed",
				Detail: "VPN portals are often meant to be public but these products have a long history of actively exploited vulnerabilities (CISA KEV). Keep firmware current, enforce MFA, and disable the web management UI on WAN."})
		default:
			issues = append(issues, Issue{ID: "app_login_exposed", Severity: "medium", Port: port,
				Title:  name + " login exposed to the internet",
				Detail: "Make sure it is patched, enforces MFA, and is rate-limited; consider placing it behind a VPN or identity-aware proxy."})
		}
	}
	if !https && (loginForm || name != "") {
		issues = append(issues, Issue{ID: "http_login_cleartext", Severity: "medium", Port: port,
			Title: "Login served over unencrypted HTTP", Detail: "Credentials can be intercepted. Serve only over HTTPS and redirect HTTP."})
	}
	if dirListing {
		issues = append(issues, Issue{ID: "http_directory_listing", Severity: "medium", Port: port,
			Title: "Directory listing enabled", Detail: "The web server lists directory contents, which often leaks backups, configs and source. Disable autoindex."})
	}
	if https && contains(missing, "Strict-Transport-Security") && r.status < 400 {
		issues = append(issues, Issue{ID: "http_missing_hsts", Severity: "low", Port: port,
			Title: "HSTS header missing", Detail: "Without Strict-Transport-Security, users can be downgraded to HTTP by a network attacker."})
	}
	others := []string{}
	for _, m := range missing {
		if m != "Strict-Transport-Security" {
			others = append(others, m)
		}
	}
	if len(others) > 0 && r.status < 400 {
		issues = append(issues, Issue{ID: "http_missing_security_headers", Severity: "info", Port: port,
			Title: "Missing security headers: " + strings.Join(others, ", "), Detail: "Add the headers to reduce clickjacking, MIME sniffing and XSS impact."})
	}
	return issues
}
