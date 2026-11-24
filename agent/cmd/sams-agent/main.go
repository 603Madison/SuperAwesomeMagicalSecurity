// sams-agent: SuperAwesomeMagicalSecurity host agent.
//
//	sams-agent enroll --server https://sams.example:8443 --token <enroll-token> [--ca-file ca.pem]
//	sams-agent run
//	sams-agent collect [--pretty]
//	sams-agent version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/603madison/superawesomemagicalsecurity/agent/internal/client"
	"github.com/603madison/superawesomemagicalsecurity/agent/internal/collect"
	"github.com/603madison/superawesomemagicalsecurity/agent/internal/config"
	"github.com/603madison/superawesomemagicalsecurity/agent/internal/logs"
	"github.com/603madison/superawesomemagicalsecurity/agent/internal/tasks"
)

var version = "0.1.0-dev"

func usage() {
	fmt.Fprintf(os.Stderr, `sams-agent %s - SuperAwesomeMagicalSecurity host agent

Usage:
  sams-agent enroll --server URL --token TOKEN [--ca-file PEM] [--insecure-skip-verify] [--config PATH]
  sams-agent run [--config PATH]
  sams-agent collect [--pretty] [--config PATH]
  sams-agent version

Config defaults to %s (override with --config or SAMS_AGENT_CONFIG).
`, version, config.DefaultPath())
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetPrefix("sams-agent: ")
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "enroll":
		err = cmdEnroll(args)
	case "run":
		err = cmdRun(args)
	case "collect":
		err = cmdCollect(args)
	case "version", "--version", "-v":
		fmt.Printf("sams-agent %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "server base URL, e.g. https://sams.dmz.example:8443")
	token := fs.String("token", "", "one-time enrollment token")
	caFile := fs.String("ca-file", "", "PEM CA bundle to trust for the server certificate")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS verification (labs only)")
	cfgPath := fs.String("config", config.DefaultPath(), "config file path")
	allowPatch := fs.Bool("allow-patching", false, "permit signed patch tasks from the server")
	_ = fs.Parse(args)
	if *server == "" || *token == "" {
		return errors.New("--server and --token are required")
	}
	cl, err := client.New(*server, version, client.Options{CAFile: *caFile, InsecureSkipVerify: *insecure})
	if err != nil {
		return err
	}
	hn, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := cl.Enroll(ctx, client.EnrollRequest{Token: *token, Kind: "host", Hostname: hn, Version: version, OS: runtime.GOOS})
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	cfg := &config.Config{}
	if existing, err := config.Load(*cfgPath); err == nil {
		cfg = existing // keep local policy settings across re-enrollment
	}
	cfg.ServerURL, cfg.AgentID, cfg.AgentKey = *server, resp.AgentID, resp.AgentKey
	cfg.ServerPublicKey, cfg.KeyID = resp.ServerPublicKey, resp.KeyID
	cfg.CAFile, cfg.InsecureSkipVerify = *caFile, *insecure
	if *allowPatch {
		cfg.AllowPatching = true
	}
	if err := cfg.Save(*cfgPath); err != nil {
		return err
	}
	fmt.Printf("enrolled as %s; server key %s pinned; config written to %s\n", resp.AgentID, resp.KeyID, *cfgPath)
	if !cfg.AllowPatching {
		fmt.Println("note: patch tasks are disabled; set \"allow_patching\": true in the config to permit them")
	}
	return nil
}

func cmdCollect(args []string) error {
	fs := flag.NewFlagSet("collect", flag.ExitOnError)
	pretty := fs.Bool("pretty", false, "indent JSON")
	cfgPath := fs.String("config", config.DefaultPath(), "config file path (optional)")
	_ = fs.Parse(args)
	opt := collect.Options{AgentVersion: version}
	if cfg, err := config.Load(*cfgPath); err == nil {
		opt.SensitivePaths = cfg.SensitivePaths
	}
	inv := collect.Collect(context.Background(), opt)
	enc := json.NewEncoder(os.Stdout)
	if *pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(inv)
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "config file path")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config (did you run enroll?): %w", err)
	}
	if !cfg.Enrolled() {
		return errors.New("agent is not enrolled; run `sams-agent enroll` first")
	}
	cl, err := client.New(cfg.ServerURL, version, client.Options{CAFile: cfg.CAFile, InsecureSkipVerify: cfg.InsecureSkipVerify})
	if err != nil {
		return err
	}
	cl.AgentID, cl.AgentKey = cfg.AgentID, cfg.AgentKey

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// server-suggested settings; local config overrides
	interval := time.Hour
	sources := []string{"/var/log/auth.log", "/var/log/secure", "journald"}
	if runtime.GOOS == "windows" {
		sources = []string{"windows"}
	}
	if sc, err := cl.GetConfig(ctx); err == nil {
		if sc.CollectIntervalSeconds > 0 {
			interval = time.Duration(sc.CollectIntervalSeconds) * time.Second
		}
		if len(sc.LogSources) > 0 {
			sources = sc.LogSources
		}
	} else {
		log.Printf("fetch config: %v (using defaults)", err)
	}
	if cfg.CollectIntervalSeconds > 0 {
		interval = time.Duration(cfg.CollectIntervalSeconds) * time.Second
	}
	if len(cfg.LogSources) > 0 {
		sources = cfg.LogSources
	}
	if interval < 5*time.Minute {
		interval = 5 * time.Minute
	}
	log.Printf("agent %s running: inventory every %s, logs from %v, patching allowed=%v", cfg.AgentID, interval, sources, cfg.AllowPatching)

	collectCh := make(chan chan error, 1)
	submit := func(ctx context.Context) error {
		inv := collect.Collect(ctx, collect.Options{AgentVersion: version, SensitivePaths: cfg.SensitivePaths})
		res, err := cl.PostInventory(ctx, inv)
		if err != nil {
			return err
		}
		log.Printf("inventory submitted: %d packages, %d listeners, %d errors -> %v", len(inv.Packages), len(inv.Listeners), len(inv.Errors), res)
		return nil
	}

	// inventory loop
	go func() {
		timer := time.NewTimer(time.Duration(rand.Intn(30)) * time.Second) // jitter first run
		for {
			var reply chan error
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			case reply = <-collectCh:
			}
			err := submit(ctx)
			if err != nil {
				log.Printf("inventory: %v", err)
			}
			if reply != nil {
				reply <- err
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			jitter := time.Duration(rand.Int63n(int64(interval / 10)))
			timer.Reset(interval + jitter)
		}
	}()

	// logs
	if !cfg.DisableLogs {
		st := logs.LoadState(filepath.Join(cfg.StateDir(), "log_state.json"))
		hn, _ := os.Hostname()
		sh := &logs.Shipper{Client: cl, State: st, Hostname: hn}
		go sh.Run(ctx, sources)
	}

	// tasks
	ex := &tasks.Executor{
		AgentID: cfg.AgentID, ServerPubKey: cfg.ServerPublicKey, AllowPatching: cfg.AllowPatching,
		StateDir: cfg.StateDir(), Client: cl,
		OnCollect: func(ctx context.Context) error {
			reply := make(chan error, 1)
			select {
			case collectCh <- reply:
			case <-ctx.Done():
				return ctx.Err()
			}
			select {
			case err := <-reply:
				return err
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()
	for {
		if err := ex.Poll(ctx); err != nil && ctx.Err() == nil {
			log.Printf("tasks: %v", err)
		}
		select {
		case <-ctx.Done():
			log.Printf("shutting down")
			time.Sleep(500 * time.Millisecond) // let the log shipper flush
			return nil
		case <-tick.C:
		}
	}
}
