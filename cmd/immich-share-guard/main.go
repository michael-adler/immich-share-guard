// Command immich-share-guard is a reverse proxy that exposes only Immich's shared
// link pages to the public, using Immich's own web UI. See README.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/michael-adler/immich-share-guard/internal/proxy"
)

// envPrefix starts the name of every setting, in the environment and in the
// env file.
const envPrefix = "SHARE_GUARD_"

// defaultEnvFile is read if it exists and -env isn't given.
const defaultEnvFile = ".env"

type options struct {
	proxy.Config
	listen    string
	verbose   bool
	checkSpec string // check this spec file and exit
	envFile   string // the env file that was read, or ""
}

// A setting is one SHARE_GUARD_* variable.
type setting struct {
	name  string // without envPrefix
	def   string // default, for the usage message
	usage string
	set   func(string) error
}

// settings returns the variables that set opts, with opts' current values as
// the defaults.
func settings(opts *options) []setting {
	cfg := &opts.Config
	return []setting{
		{"UPSTREAM", "", "internal Immich URL, e.g. http://127.0.0.1:2283 (required)", func(v string) error {
			u, err := url.Parse(v)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return errors.New("must be an http or https URL")
			}
			if u.Path != "" && u.Path != "/" || u.RawQuery != "" {
				return errors.New("must not have a path or query")
			}
			u.Path = ""
			cfg.Upstream = u
			return nil
		}},
		{"LISTEN", opts.listen, "address to listen on", func(v string) error {
			opts.listen = v
			return nil
		}},
		{"MODE", "enforce", `"enforce" blocks disallowed requests, "log" only logs them`, func(v string) error {
			switch v {
			case "enforce":
				cfg.LogOnly = false
			case "log":
				cfg.LogOnly = true
			default:
				return errors.New(`must be "enforce" or "log"`)
			}
			return nil
		}},
		boolSetting("ALLOW_SLUGS", "allow custom-URL shares (/s/<slug>), which are guessable", &cfg.AllowSlugs),
		boolSetting("ALLOW_UPLOAD", "allow uploads to shares that permit them (body is not validated)", &cfg.AllowUpload),
		{"TRUSTED_PROXIES", formatNets(cfg.TrustedProxies), "comma-separated CIDRs whose X-Forwarded-* headers are trusted", func(v string) (err error) {
			cfg.TrustedProxies, err = parseNets(v)
			return err
		}},
		{"FAIL_LIMIT", strconv.Itoa(cfg.FailLimit), "failed requests per IP per window before blocking (0 disables)", func(v string) (err error) {
			cfg.FailLimit, err = strconv.Atoi(v)
			return err
		}},
		durationSetting("FAIL_WINDOW", "window for "+envPrefix+"FAIL_LIMIT", &cfg.FailWindow),
		durationSetting("SHARE_CHECK_TTL", "how long a successful share check is cached (0 checks every request)", &cfg.ShareCheckTTL),
		int64Setting("MAX_BODY", "maximum validated request body size in bytes", &cfg.MaxBody),
		int64Setting("MAX_SCRUB_BODY", "maximum size in bytes of a JSON response that is rewritten", &cfg.MaxScrubBody),
		durationSetting("SPEC_INTERVAL", "how often to fetch the upstream spec again to detect an Immich upgrade (0 checks only at startup)", &cfg.SpecInterval),
	}
}

func boolSetting(name, usage string, p *bool) setting {
	return setting{name, strconv.FormatBool(*p), usage, func(v string) (err error) {
		*p, err = strconv.ParseBool(v)
		return err
	}}
}

func int64Setting(name, usage string, p *int64) setting {
	return setting{name, strconv.FormatInt(*p, 10), usage, func(v string) (err error) {
		*p, err = strconv.ParseInt(v, 10, 64)
		return err
	}}
}

func durationSetting(name, usage string, p *time.Duration) setting {
	return setting{name, p.String(), usage, func(v string) (err error) {
		*p, err = time.ParseDuration(v)
		return err
	}}
}

// parseArgs parses the command line and the settings, which come from environ
// (in os.Environ form) or, for variables environ doesn't have, the env file.
func parseArgs(args, environ []string) (options, error) {
	opts := options{Config: proxy.DefaultConfig(), listen: "127.0.0.1:2284"}
	list := settings(&opts)

	fset := flag.NewFlagSet("immich-share-guard", flag.ContinueOnError)
	var envFile string
	fset.BoolVar(&opts.verbose, "v", false, "log every request, not just blocked ones")
	fset.StringVar(&opts.checkSpec, "check-spec", "", "compare the allowlist with an Immich OpenAPI spec file, report drift, and exit")
	fset.StringVar(&envFile, "env", "", "read settings from `file` (default "+defaultEnvFile+" in the current directory, if it exists)")
	fset.Usage = func() {
		w := fset.Output()
		fmt.Fprintln(w, "Usage: immich-share-guard [-v] [-env file] [-check-spec file]")
		fset.PrintDefaults()
		fmt.Fprintln(w, "\nSettings, from the environment or the env file (the environment wins):")
		for _, s := range list {
			def := ""
			if s.def != "" {
				def = " (default " + s.def + ")"
			}
			fmt.Fprintf(w, "  %s%s%s\n    \t%s\n", envPrefix, s.name, def, s.usage)
		}
	}
	if err := fset.Parse(args); err != nil {
		return opts, err
	}
	if fset.NArg() > 0 {
		return opts, fmt.Errorf("unexpected arguments: %v", fset.Args())
	}

	known := make(map[string]bool, len(list))
	for _, s := range list {
		known[envPrefix+s.name] = true
	}

	path := envFile
	if path == "" {
		path = defaultEnvFile
	}
	file, err := readEnvFile(path)
	switch {
	case err == nil:
		opts.envFile = path
	case envFile == "" && errors.Is(err, fs.ErrNotExist):
	default:
		return opts, err
	}
	for name := range file {
		if !known[name] {
			return opts, fmt.Errorf("%s: unknown setting %s", path, name)
		}
	}

	env := make(map[string]string)
	for _, kv := range environ {
		name, v, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, envPrefix) {
			continue
		}
		if !known[name] {
			return opts, fmt.Errorf("unknown environment variable %s", name)
		}
		env[name] = v
	}

	for _, s := range list {
		name := envPrefix + s.name
		v, ok := env[name]
		if !ok {
			v, ok = file[name]
		}
		if !ok {
			continue
		}
		if err := s.set(v); err != nil {
			return opts, fmt.Errorf("invalid %s %q: %v", name, v, unwrapNum(err))
		}
	}

	if opts.checkSpec == "" && opts.Upstream == nil {
		return opts, errors.New(envPrefix + "UPSTREAM is required")
	}
	return opts, nil
}

// unwrapNum drops the strconv function name and input from err, which the
// caller already reports.
func unwrapNum(err error) error {
	var ne *strconv.NumError
	if errors.As(err, &ne) {
		return ne.Err
	}
	return err
}

// readEnvFile reads NAME=value lines, as in Immich's .env file. Blank lines
// and lines starting with # are skipped, "export " before a name is allowed,
// and a value may be in single or double quotes. In an unquoted value, a #
// after a space starts a comment.
func readEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	vals := make(map[string]string)
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		name, v, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(strings.TrimPrefix(name, "export "))
		if !ok || name == "" {
			return nil, fmt.Errorf("%s:%d: expected NAME=value", path, i+1)
		}
		v = strings.TrimSpace(v)
		if v != "" && (v[0] == '"' || v[0] == '\'') {
			end := strings.IndexByte(v[1:], v[0])
			if end < 0 {
				return nil, fmt.Errorf("%s:%d: unterminated quote", path, i+1)
			}
			if rest := strings.TrimSpace(v[end+2:]); rest != "" && rest[0] != '#' {
				return nil, fmt.Errorf("%s:%d: text after closing quote", path, i+1)
			}
			v = v[1 : end+1]
		} else if c := strings.Index(v, " #"); c >= 0 {
			v = strings.TrimSpace(v[:c])
		}
		if _, dup := vals[name]; dup {
			return nil, fmt.Errorf("%s:%d: %s set again", path, i+1, name)
		}
		vals[name] = v
	}
	return vals, nil
}

// parseNets parses comma-separated CIDRs. A bare address is a single host.
func parseNets(list string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, s := range strings.Split(list, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		cidr := s
		if !strings.Contains(s, "/") {
			// An IPv6 literal, IPv4-mapped ones included, needs /128.
			if strings.Contains(s, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("bad entry %q", s)
		}
		out = append(out, n)
	}
	return out, nil
}

func formatNets(nets []*net.IPNet) string {
	s := make([]string, len(nets))
	for i, n := range nets {
		s[i] = n.String()
	}
	return strings.Join(s, ",")
}

func main() {
	opts, err := parseArgs(os.Args[1:], os.Environ())
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "immich-share-guard:", err)
		os.Exit(2)
	}
	if opts.checkSpec != "" {
		os.Exit(checkSpec(opts))
	}

	level := slog.LevelInfo
	if opts.verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	p := proxy.New(opts.Config, log)
	srv := &http.Server{
		Addr:              opts.listen,
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		// No ReadTimeout/WriteTimeout: originals, videos, and zip archives can
		// take a long time to transfer.
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// ListenAndServe returns as soon as Shutdown starts, so main waits on
	// this channel for open requests to finish (or the grace period to end).
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		stop() // a second signal now kills the process at once
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Warn("shutdown incomplete", "err", err)
		}
	}()

	go p.WatchSpec(ctx)

	mode := "enforce"
	if opts.LogOnly {
		mode = "log-only"
	}
	log.Info("starting", "env_file", opts.envFile, "listen", opts.listen, "upstream", opts.Upstream.Redacted(),
		"mode", mode, "allow_slugs", opts.AllowSlugs, "allow_upload", opts.AllowUpload)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server failed", "err", err)
		os.Exit(1)
	}
	<-shutdownDone
}

// checkSpec runs the drift check against a local spec file and returns the
// exit status: 0 for no drift, 1 for drift, 2 for an error.
func checkSpec(opts options) int {
	raw, err := os.ReadFile(opts.checkSpec)
	if err == nil {
		var ok bool
		ok, err = proxy.CheckSpec(os.Stdout, raw, opts.Config)
		if err == nil && ok {
			return 0
		}
		if err == nil {
			return 1
		}
	}
	fmt.Fprintln(os.Stderr, "immich-share-guard:", err)
	return 2
}
