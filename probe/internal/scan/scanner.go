package scan

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/603madison/superawesomemagicalsecurity/probe/internal/scope"
)

// Valid check names.
var AllChecks = []string{"tcp", "banner", "tls", "http", "dns", "udp"}

// DefaultChecks are used when a job does not specify any.
var DefaultChecks = []string{"tcp", "banner", "tls", "http", "dns"}

var disallowed = scope.Disallowed

// httpAPIServices speak HTTP but must be reported by their real identity.
var httpAPIServices = map[string]bool{"kubelet": true, "kubernetes-api": true, "docker": true, "docker-tls": true,
	"etcd": true, "winrm": true, "winrm-https": true, "elasticsearch": true, "couchdb": true, "influxdb": true}

// Options control a scan.
type Options struct {
	Ports           []int
	Checks          []string
	RatePerSec      int           // new connections per second across the whole scan
	Concurrency     int           // concurrent port probes
	ConnectTimeout  time.Duration // TCP connect timeout
	GreetingTimeout time.Duration // how long to wait for an unprompted banner
	IOTimeout       time.Duration // read/write timeout after connect
	UDPTimeout      time.Duration
	AllowPrivate    bool // standalone mode only
	Lookup          scope.LookupFunc
	DNSServer       string // host:port for raw DNS queries (CAA); default: system resolver
	Version         string
	Logf            func(format string, args ...any)
	Now             func() time.Time
}

func (o *Options) defaults() {
	if o.RatePerSec <= 0 {
		o.RatePerSec = 200
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 64
	}
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = 2 * time.Second
	}
	if o.GreetingTimeout <= 0 {
		o.GreetingTimeout = 2 * time.Second
	}
	if o.IOTimeout <= 0 {
		o.IOTimeout = 4 * time.Second
	}
	if o.UDPTimeout <= 0 {
		o.UDPTimeout = 2 * time.Second
	}
	if len(o.Checks) == 0 {
		o.Checks = DefaultChecks
	}
	if len(o.Ports) == 0 {
		o.Ports = scope.Top100
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Version == "" {
		o.Version = "dev"
	}
}

// limiter paces new connections (simple GCRA/token pacing, burst 1).
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
	ctx      context.Context
}

func newLimiter(ctx context.Context, perSec int) *limiter {
	return &limiter{interval: time.Second / time.Duration(perSec), ctx: ctx}
}

func (l *limiter) wait() bool {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	delay := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()
	if delay <= 0 {
		return l.ctx.Err() == nil
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-l.ctx.Done():
		return false
	}
}

// Scanner runs checks against targets.
type Scanner struct {
	opts    Options
	checks  map[string]bool
	limiter *limiter
}

func (s *Scanner) has(check string) bool { return s.checks[check] }

// Run scans all targets and returns an ExternalScanResult. Context
// cancellation/deadline yields partial results.
func Run(ctx context.Context, targets []string, opts Options) *Result {
	opts.defaults()
	s := &Scanner{opts: opts, checks: map[string]bool{}, limiter: newLimiter(ctx, opts.RatePerSec)}
	for _, c := range opts.Checks {
		s.checks[c] = true
	}
	res := &Result{StartedAt: opts.Now().UTC(), Targets: []TargetResult{}}

	expanded, refused := scope.Expand(ctx, targets, opts.AllowPrivate, opts.Lookup)
	for _, r := range refused {
		tr := newTargetResult(r.Input)
		tr.Reachable = false
		tr.Issues = append(tr.Issues, Issue{ID: "scope_refused", Severity: "info",
			Title: "Target not scanned", Detail: r.Reason})
		res.Targets = append(res.Targets, tr)
	}

	results := make([]TargetResult, len(expanded))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4) // targets in parallel
	for i, t := range expanded {
		wg.Add(1)
		go func(i int, t scope.Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = s.scanTarget(ctx, t)
		}(i, t)
	}
	wg.Wait()
	res.Targets = append(res.Targets, results...)
	res.FinishedAt = opts.Now().UTC()
	return res
}

func (s *Scanner) scanTarget(ctx context.Context, t scope.Target) TargetResult {
	tr := newTargetResult(t.Input)
	for _, ip := range t.IPs {
		tr.Resolved = append(tr.Resolved, ip.String())
	}
	s.opts.Logf("scanning %s (%v)", t.Input, tr.Resolved)

	if t.IsName && s.has("dns") {
		s.dnsChecks(ctx, t.Host, &tr)
	}
	if len(t.IPs) == 0 {
		tr.Reachable = false
		if len(tr.DNS) == 0 {
			tr.DNS["error"] = "name did not resolve"
		}
		return tr
	}
	ip := t.IPs[0].String()

	alive := false
	var open []int
	if s.has("tcp") || s.has("banner") || s.has("tls") || s.has("http") {
		open, alive = s.portScan(ctx, ip)
	}

	services := make([]Service, len(open))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i, port := range open {
		wg.Add(1)
		go func(i, port int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			svc, issues := s.probeService(ctx, ip, t.Host, t.IsName, port)
			mu.Lock()
			services[i] = svc
			tr.Issues = append(tr.Issues, issues...)
			mu.Unlock()
		}(i, port)
	}
	wg.Wait()
	tr.Services = append(tr.Services, services...)

	if s.has("udp") && ctx.Err() == nil {
		before := len(tr.Services)
		s.udpChecks(ip, &tr)
		if len(tr.Services) > before {
			alive = true
		}
	}
	for _, svc := range tr.Services {
		if svc.Proto == "tcp" {
			tr.Issues = append(tr.Issues, serviceIssues(svc)...)
		}
	}
	tr.Reachable = alive || len(open) > 0
	sort.SliceStable(tr.Issues, func(a, b int) bool { return sevRank(tr.Issues[a].Severity) > sevRank(tr.Issues[b].Severity) })
	return tr
}

func sevRank(s string) int {
	return map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[s]
}

// portScan does a rate-limited TCP connect scan. alive is true if any port
// answered (open or actively refused), proving the host is up.
func (s *Scanner) portScan(ctx context.Context, ip string) ([]int, bool) {
	var (
		mu    sync.Mutex
		open  []int
		alive bool
		wg    sync.WaitGroup
	)
	sem := make(chan struct{}, s.opts.Concurrency)
	d := net.Dialer{Timeout: s.opts.ConnectTimeout}
	for _, port := range s.opts.Ports {
		if !s.limiter.wait() {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
			if err == nil {
				c.Close()
				mu.Lock()
				open = append(open, port)
				alive = true
				mu.Unlock()
				return
			}
			if errors.Is(err, syscall.ECONNREFUSED) {
				mu.Lock()
				alive = true
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	sort.Ints(open)
	return open, alive
}

// probeService identifies one open TCP port.
func (s *Scanner) probeService(ctx context.Context, ip, host string, isName bool, port int) (Service, []Issue) {
	svc := Service{Port: port, Proto: "tcp", State: "open"}
	var issues []Issue
	if ctx.Err() != nil {
		svc.Service = portNames[port]
		return svc, nil
	}
	if s.has("banner") {
		s.limiter.wait()
		s.grabBanner(ip, host, port, &svc)
	}
	isTLS := false
	if s.has("tls") || s.has("http") {
		// Try TLS on known TLS ports, and on any port that stayed silent / looks like HTTP-on-TLS.
		if tlsPorts[port] || svc.Service == "" || (svc.Service == "http" && svc.Product == "") {
			s.limiter.wait()
			isTLS = s.detectTLS(ip, host, port)
		}
	}
	if isTLS && s.has("tls") {
		s.limiter.wait()
		info, tIssues := s.tlsInspect(ip, host, isName, port)
		if info != nil {
			svc.TLS = info
			issues = append(issues, tIssues...)
		}
		if svc.Service == "" {
			svc.Service = "tls"
		}
	}
	if s.has("http") && (isTLS || svc.Service == "http" || (svc.Service == "" && httpPorts[port])) {
		s.limiter.wait()
		issues = append(issues, s.httpInspect(ctx, ip, host, isName, port, isTLS, &svc)...)
	}
	// HTTP(S)-speaking APIs keep their specific identity (kubelet, docker, winrm...)
	if n := portNames[port]; n != "" {
		generic := svc.Service == "" || svc.Service == "tls" || svc.Service == "http" || svc.Service == "https"
		if generic && (svc.Service == "" || httpAPIServices[n] || (svc.Service == "tls" && n != "https")) {
			svc.Service = n
		}
	}
	if svc.Service == "" {
		svc.Service = "unknown"
	}
	return svc, issues
}
