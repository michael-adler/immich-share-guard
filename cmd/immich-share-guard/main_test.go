// Tests of parsing the command line, the env file and the environment.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeEnv(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guard.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseArgs(t *testing.T) {
	t.Chdir(t.TempDir()) // no default .env

	path := writeEnv(t, `
# comment
SHARE_GUARD_UPSTREAM=http://immich:2283/
export SHARE_GUARD_MODE="log"
SHARE_GUARD_TRUSTED_PROXIES='10.0.0.1, fd00::/8'  # the front end
SHARE_GUARD_SPEC_INTERVAL=1h # comment
SHARE_GUARD_FAIL_LIMIT=5
`)
	opts, err := parseArgs([]string{"-env", path, "-v"}, []string{"SHARE_GUARD_FAIL_LIMIT=7", "HOME=/"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.Upstream.String() != "http://immich:2283" || !opts.LogOnly || opts.SpecInterval != time.Hour ||
		!opts.verbose || opts.envFile != path {
		t.Errorf("got %+v", opts)
	}
	if opts.FailLimit != 7 {
		t.Errorf("environment should override file: fail limit %d", opts.FailLimit)
	}
	if got := formatNets(opts.TrustedProxies); got != "10.0.0.1/32,fd00::/8" {
		t.Errorf("trusted proxies %s", got)
	}

	// Environment only, no file: defaults.
	opts, err = parseArgs(nil, []string{"SHARE_GUARD_UPSTREAM=http://immich:2283"})
	if err != nil {
		t.Fatal(err)
	}
	if got := formatNets(opts.TrustedProxies); got != "127.0.0.1/32,::1/128" {
		t.Errorf("default trusted proxies %s", got)
	}
	if opts.FailLimit != 30 || opts.listen != "127.0.0.1:2284" || opts.LogOnly || opts.envFile != "" {
		t.Errorf("defaults %+v", opts)
	}

	// An empty list is allowed.
	opts, err = parseArgs(nil, []string{"SHARE_GUARD_UPSTREAM=http://immich", "SHARE_GUARD_TRUSTED_PROXIES="})
	if err != nil || len(opts.TrustedProxies) != 0 {
		t.Errorf("empty trusted proxies: %v %v", opts.TrustedProxies, err)
	}

	// Default .env in the current directory.
	if err := os.WriteFile(".env", []byte("SHARE_GUARD_UPSTREAM=http://dot-env:2283\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, err = parseArgs(nil, nil)
	if err != nil || opts.Upstream.Host != "dot-env:2283" || opts.envFile != ".env" {
		t.Errorf("default .env: %+v %v", opts, err)
	}
	os.Remove(".env")

	if _, err := parseArgs([]string{"-check-spec", "x.json"}, nil); err != nil {
		t.Errorf("-check-spec without upstream: %v", err)
	}
	opts, err = parseArgs([]string{"-check-spec", "x.json"}, []string{"SHARE_GUARD_ALLOW_UPLOAD=true"})
	if err != nil || !opts.AllowUpload {
		t.Errorf("-check-spec should read settings: %+v %v", opts, err)
	}

	up := "SHARE_GUARD_UPSTREAM=http://immich"
	for _, c := range []struct {
		args, env []string
		file      string
		want      string
	}{
		{nil, nil, "", "UPSTREAM is required"},
		{nil, []string{"SHARE_GUARD_UPSTREAM=ftp://immich"}, "", "http or https"},
		{nil, []string{"SHARE_GUARD_UPSTREAM=http://immich/api"}, "", "path or query"},
		{nil, []string{up, "SHARE_GUARD_MODE=off"}, "", "SHARE_GUARD_MODE"},
		{nil, []string{up, "SHARE_GUARD_TRUSTED_PROXIES=bogus"}, "", "bogus"},
		{nil, []string{up, "SHARE_GUARD_FAIL_LIMIT=x"}, "", "invalid syntax"},
		{nil, []string{up, "SHARE_GUARD_FAIL_WINDOW=10"}, "", "SHARE_GUARD_FAIL_WINDOW"},
		{nil, []string{up, "SHARE_GUARD_ALLOW_SLUG=true"}, "", "unknown environment variable"},
		{[]string{"extra"}, []string{up}, "", "unexpected arguments"},
		{[]string{"-upstream", "http://immich"}, nil, "", "not defined"},
		{[]string{"-env", "/nonexistent/guard.env"}, []string{up}, "", "no such file"},
		{nil, nil, up + "\nSHARE_GUARD_LISTN=:80\n", "unknown setting"},
		{nil, nil, up + "\nnot a setting\n", ":2: expected NAME=value"},
		{nil, nil, up + "\nSHARE_GUARD_MODE=\"log\n", "unterminated quote"},
		{nil, nil, up + "\nSHARE_GUARD_MODE=\"log\" x\n", "after closing quote"},
		{nil, nil, up + "\n" + up + "\n", "set again"},
	} {
		args := c.args
		if c.file != "" {
			args = append([]string{"-env", writeEnv(t, c.file)}, args...)
		}
		_, err := parseArgs(args, c.env)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("args %v env %v file %q: got %v, want %q", c.args, c.env, c.file, err, c.want)
		}
	}
}

func TestParseNets(t *testing.T) {
	nets, err := parseNets("192.0.2.1, ::ffff:192.0.2.2, 2001:db8::1, 10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	// An IPv4-mapped address is a single host, not an IPv6 /32.
	if got := formatNets(nets); got != "192.0.2.1/32,192.0.2.2/32,2001:db8::1/128,10.0.0.0/8" {
		t.Errorf("got %s", got)
	}
	if _, err := parseNets("nonsense"); err == nil || !strings.Contains(err.Error(), `"nonsense"`) {
		t.Errorf("error should quote the entry as given: %v", err)
	}
}
