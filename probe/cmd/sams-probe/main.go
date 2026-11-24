// sams-probe is the SuperAwesomeMagicalSecurity external probe: an outside-in
// scanner meant to run on a host that is completely OFF the assessed network
// (a cheap VPS / cloud instance) and sees the organization exactly as an
// internet attacker would.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/603madison/superawesomemagicalsecurity/probe/internal/client"
	"github.com/603madison/superawesomemagicalsecurity/probe/internal/scan"
	"github.com/603madison/superawesomemagicalsecurity/probe/internal/scope"
)

var version = "0.1.0-dev"

const usage = `sams-probe — SuperAwesomeMagicalSecurity external (outside-in) probe

Usage:
  sams-probe enroll --server URL --token TOKEN [--config PATH] [--ca-file PEM] [--insecure-skip-verify]
  sams-probe run    [--config PATH] [--poll 60s] [--once] [--max-job-duration 2h]
  sams-probe scan   --target HOST[,HOST...] [--ports top100|top1000|all|1-1024|22,80]
                    [--checks tcp,banner,tls,http,dns,udp] [--rate 200] [--json] [--allow-private]
  sams-probe version

Only scan systems you own or are explicitly authorized to test.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "enroll":
		err = cmdEnroll(ctx, os.Args[2:])
	case "run":
		err = cmdRun(ctx, os.Args[2:])
	case "scan":
		err = cmdScan(ctx, os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("sams-probe %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func cmdEnroll(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "sams-server base URL, e.g. https://sams.example.com:8443")
	token := fs.String("token", "", "one-time enrollment token (sams token create --kind probe)")
	cfgPath := fs.String("config", client.DefaultConfigPath(), "where to store credentials")
	caFile := fs.String("ca-file", "", "PEM CA bundle to trust for the server")
	insecure := fs.Bool("insecure-skip-verify", false, "do not verify the server TLS certificate (lab use only)")
	name := fs.String("name", "", "probe name (default: hostname)")
	_ = fs.Parse(args)
	if *server == "" || *token == "" {
		return errors.New("--server and --token are required")
	}
	if u, err := url.Parse(*server); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("invalid --server %q", *server)
	} else if u.Scheme == "http" {
		log.Printf("WARNING: enrolling over plain HTTP; the agent key and all results travel unencrypted")
	}
	hc, err := client.HTTPClient(*caFile, *insecure)
	if err != nil {
		return err
	}
	host := *name
	if host == "" {
		host, _ = os.Hostname()
	}
	er, err := client.Enroll(ctx, hc, *server, *token, host, version, runtime.GOOS+"/"+runtime.GOARCH)
	if err != nil {
		return err
	}
	cfg := &client.Config{Server: strings.TrimRight(*server, "/"), AgentID: er.AgentID, AgentKey: er.AgentKey,
		ServerPublicKey: er.ServerPublicKey, KeyID: er.KeyID, CAFile: *caFile, InsecureSkipVerify: *insecure}
	if err := cfg.Save(*cfgPath); err != nil {
		return err
	}
	fmt.Printf("enrolled as %s; pinned server signing key %s; config saved to %s\n", er.AgentID, er.KeyID, *cfgPath)
	return nil
}

var jobIDRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

func cmdRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", client.DefaultConfigPath(), "enrollment config")
	poll := fs.Duration("poll", 60*time.Second, "job poll interval")
	once := fs.Bool("once", false, "poll once, process at most one job, then exit")
	maxDur := fs.Duration("max-job-duration", 2*time.Hour, "hard cap on a single job's runtime")
	_ = fs.Parse(args)

	cfg, err := client.Load(*cfgPath)
	if err != nil {
		return err
	}
	c, err := client.New(cfg, version)
	if err != nil {
		return err
	}
	log.Printf("sams-probe %s running as %s against %s (key %s)", version, cfg.AgentID, cfg.Server, cfg.KeyID)

	backoff := *poll
	for {
		didJob, err := runOnce(ctx, c, *maxDur)
		if err != nil {
			log.Printf("error: %v", err)
		}
		if *once {
			if !didJob && err == nil {
				log.Printf("no job queued")
			}
			return err
		}
		wait := *poll
		switch {
		case err != nil:
			backoff = min(backoff*2, 15*time.Minute)
			wait = backoff
		case didJob:
			backoff, wait = *poll, 0 // check immediately for more work
		default:
			backoff = *poll
		}
		select {
		case <-ctx.Done():
			log.Printf("shutting down")
			return nil
		case <-time.After(wait):
		}
	}
}

func runOnce(ctx context.Context, c *client.Client, maxDur time.Duration) (bool, error) {
	cfg := c.Config()
	seenIP, err := c.Heartbeat(ctx, version)
	if err != nil {
		return false, fmt.Errorf("heartbeat: %w", err)
	}
	env, err := c.NextJob(ctx)
	if err != nil || env == nil {
		return false, err
	}
	// Signature is verified over the raw payload bytes BEFORE anything is parsed.
	job, err := scope.OpenJob(*env, cfg.ServerPublicKey, cfg.AgentID, time.Now())
	if err != nil {
		// Never act on (or echo back to) an unverifiable instruction.
		return true, fmt.Errorf("REJECTED job envelope (key %q): %w", env.KeyID, err)
	}
	if !jobIDRe.MatchString(job.JobID) {
		return true, fmt.Errorf("REJECTED job with malformed id %q", job.JobID)
	}
	if ip := seenIP; ip != "" {
		if parsed := parseIP(ip); parsed != nil {
			if bad, why := scope.Disallowed(parsed); bad {
				log.Printf("WARNING: server sees this probe at %s (%s): the probe may be INSIDE the network or behind the same NAT; results will not reflect an external view", ip, why)
			}
		}
	}

	deadline := job.Expiry()
	if hard := time.Now().Add(maxDur); deadline.IsZero() || hard.Before(deadline) {
		deadline = hard
	}
	jctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	checks := job.Checks
	if len(checks) == 0 {
		checks = scan.DefaultChecks
	}
	checks = filterChecks(checks)
	ports := job.Ports
	if len(ports) == 0 {
		ports = scope.Top100
	}
	log.Printf("job %s: %d target(s), %d port(s), checks=%v, rate=%d/s, deadline %s",
		job.JobID, len(job.Targets), len(ports), checks, job.RatePerSec, deadline.Format(time.RFC3339))

	res := scan.Run(jctx, job.Targets, scan.Options{
		Ports: ports, Checks: checks, RatePerSec: job.RatePerSec, AllowPrivate: false, Version: version,
		Logf: log.Printf,
	})
	res.ProbeID, res.JobID, res.ProbePublicIP = cfg.AgentID, job.JobID, seenIP
	if jctx.Err() != nil {
		log.Printf("job %s hit its deadline; reporting partial results", job.JobID)
	}
	// Upload with a fresh context so a just-expired job still reports.
	uctx, ucancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer ucancel()
	if err := c.PostResult(uctx, url.PathEscape(job.JobID), res); err != nil {
		return true, fmt.Errorf("upload result for %s: %w", job.JobID, err)
	}
	issues := 0
	for _, t := range res.Targets {
		issues += len(t.Issues)
	}
	log.Printf("job %s done: %d target(s), %d issue(s)", job.JobID, len(res.Targets), issues)
	return true, nil
}

func filterChecks(in []string) []string {
	valid := map[string]bool{}
	for _, c := range scan.AllChecks {
		valid[c] = true
	}
	var out []string
	for _, c := range in {
		c = strings.ToLower(strings.TrimSpace(c))
		if valid[c] {
			out = append(out, c)
		}
	}
	return out
}

func cmdScan(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	targets := fs.String("target", "", "comma-separated IPs, CIDRs (<= 256 addresses) or hostnames")
	portSpec := fs.String("ports", "top100", "top100 | top1000 | all | 1-1024 | 22,80,443")
	checkSpec := fs.String("checks", strings.Join(scan.DefaultChecks, ","), "comma list of: "+strings.Join(scan.AllChecks, ","))
	rate := fs.Int("rate", 200, "max new connections per second")
	asJSON := fs.Bool("json", false, "print an ExternalScanResult JSON document")
	allowPrivate := fs.Bool("allow-private", false, "permit private/reserved targets (testing only)")
	timeout := fs.Duration("timeout", 30*time.Minute, "overall scan deadline")
	_ = fs.Parse(args)
	if *targets == "" {
		return errors.New("--target is required")
	}
	ports, err := scope.ParsePorts(*portSpec)
	if err != nil {
		return err
	}
	checks := filterChecks(strings.Split(*checkSpec, ","))
	if len(checks) == 0 {
		return fmt.Errorf("no valid checks in %q", *checkSpec)
	}
	fmt.Fprintln(os.Stderr, "WARNING: only scan systems you own or have written authorization to test.")
	if *allowPrivate {
		fmt.Fprintln(os.Stderr, "WARNING: --allow-private set; private/reserved targets will be scanned.")
	}
	sctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	logf := func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }
	res := scan.Run(sctx, strings.Split(*targets, ","), scan.Options{
		Ports: ports, Checks: checks, RatePerSec: *rate, AllowPrivate: *allowPrivate, Version: version, Logf: logf,
	})
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	printHuman(res)
	return nil
}

func printHuman(res *scan.Result) {
	for _, t := range res.Targets {
		fmt.Printf("\n== %s  resolved=%v reachable=%v\n", t.Target, t.Resolved, t.Reachable)
		if len(t.Services) > 0 {
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "PORT\tSERVICE\tPRODUCT\tVERSION\tDETAIL")
			for _, s := range t.Services {
				detail := s.Banner
				if s.HTTP != nil {
					detail = fmt.Sprintf("%v %q %v", s.HTTP["status"], s.HTTP["title"], s.HTTP["login_page"])
				}
				if s.TLS != nil {
					detail += fmt.Sprintf(" tls=%v", s.TLS["versions"])
				}
				if len(detail) > 80 {
					detail = detail[:80]
				}
				fmt.Fprintf(w, "%d/%s\t%s\t%s\t%s\t%s\n", s.Port, s.Proto, s.Service, s.Product, s.Version, detail)
			}
			w.Flush()
		}
		if len(t.DNS) > 0 {
			keys := make([]string, 0, len(t.DNS))
			for k := range t.DNS {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			fmt.Println("DNS:")
			for _, k := range keys {
				fmt.Printf("  %-13s %v\n", k, t.DNS[k])
			}
		}
		if len(t.Issues) > 0 {
			fmt.Println("Issues:")
			for _, i := range t.Issues {
				port := ""
				if i.Port != 0 {
					port = fmt.Sprintf(" [%d]", i.Port)
				}
				fmt.Printf("  %-8s %s%s — %s\n", strings.ToUpper(i.Severity), i.Title, port, i.ID)
				if i.ID == "scope_refused" {
					fmt.Printf("           %s\n", i.Detail)
				}
			}
		}
	}
}

func parseIP(s string) net.IP { return net.ParseIP(strings.TrimSpace(s)) }
