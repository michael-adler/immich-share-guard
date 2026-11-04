// Test helpers shared by the proxy tests: a fake Immich upstream that
// records requests, test proxies, and request builders.

package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

const (
	testKey   = "m09rsrwLhZn1fOja0-uLwpt50l7F05ixebVNR9l_76YvAzUhkDnWy_gtM6FXcYFLp5M"
	testAlbum = "4aadf66a-68ef-4c66-b191-49ba024f42eb"
	testAsset = "3d209807-b91f-4f96-b864-a6899e46df0b"
)

type seen struct {
	method, path, rawQuery, body string
	header                       http.Header
}

type upstream struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []seen
	// handler for responses. Default: 200 {"ok":true}.
	respond func(w http.ResponseWriter, r *http.Request)
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.reqs = append(u.reqs, seen{r.Method, r.URL.Path, r.URL.RawQuery, string(b), r.Header.Clone()})
		u.mu.Unlock()
		if u.respond != nil {
			u.respond(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *upstream) last(t *testing.T) seen {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.reqs) == 0 {
		t.Fatal("upstream received no request")
	}
	return u.reqs[len(u.reqs)-1]
}

func (u *upstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.reqs)
}

func testConfig(t *testing.T, up *upstream) Config {
	t.Helper()
	u, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Upstream = u
	return cfg
}

func newTestProxy(t *testing.T, up *upstream, mutate func(*Config)) *Proxy {
	t.Helper()
	cfg := testConfig(t, up)
	if mutate != nil {
		mutate(&cfg)
	}
	return New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func do(p *Proxy, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}

func get(target string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = "203.0.113.7:5555"
	return r
}

func post(target, contentType, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	r.RemoteAddr = "203.0.113.7:5555"
	return r
}

func (u *upstream) countPath(path string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, r := range u.reqs {
		if r.path == path {
			n++
		}
	}
	return n
}
