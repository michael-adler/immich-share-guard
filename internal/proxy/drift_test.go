// Tests of the drift check, the reviewed request shapes, the periodic spec
// fetch, and CheckSpec.

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const fixture = "testdata/immich-openapi-3.3.5.json"

func readFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The allowlist must match the spec of the Immich version it was checked
// against. On an Immich upgrade, replace the fixture (from
// <immich>/api/spec.json) and work through the failures.
func TestDriftFixtureClean(t *testing.T) {
	raw := readFixture(t)
	for _, upload := range []bool{false, true} {
		info, issues, err := analyzeSpec(raw, buildRoutes(Config{AllowUpload: upload}))
		if err != nil {
			t.Fatal(err)
		}
		for _, i := range issues {
			t.Errorf("allow-upload=%v: %s", upload, i)
		}
		if info.version != reviewed.Version {
			t.Errorf("fixture version %s, reviewed-api.json has %s", info.version, reviewed.Version)
		}
		var ids []string
		for _, rt := range info.shareRoutes {
			ids = append(ids, rt.id())
		}
		want := "POST /search/metadata"
		if !upload {
			want += ",POST /assets"
		}
		if got := strings.Join(ids, ","); !sameSet(got, want) {
			t.Errorf("allow-upload=%v: unserved share routes = %s, want %s", upload, got, want)
		}
	}
}

func sameSet(a, b string) bool {
	as, bs := strings.Split(a, ","), strings.Split(b, ",")
	if len(as) != len(bs) {
		return false
	}
	m := map[string]bool{}
	for _, x := range as {
		m[x] = true
	}
	for _, x := range bs {
		if !m[x] {
			return false
		}
	}
	return true
}

// mutatedSpec returns the fixture with changes of every kind the drift check
// should report.
func mutatedSpec(t *testing.T) []byte {
	t.Helper()
	var s map[string]any
	if err := json.Unmarshal(readFixture(t), &s); err != nil {
		t.Fatal(err)
	}
	paths := s["paths"].(map[string]any)
	op := func(path, method string) map[string]any {
		return paths[path].(map[string]any)[method].(map[string]any)
	}
	addParam := func(o map[string]any, name, in string) {
		o["parameters"] = append(o["parameters"].([]any), map[string]any{"name": name, "in": in, "schema": map[string]any{"type": "string"}})
	}
	schemas := s["components"].(map[string]any)["schemas"].(map[string]any)
	props := func(name string) map[string]any {
		return schemas[name].(map[string]any)["properties"].(map[string]any)
	}

	s["info"].(map[string]any)["version"] = "9.9.9"
	addParam(op("/timeline/buckets", "get"), "foo", "query")
	addParam(op("/assets/{id}/thumbnail", "get"), "x-immich-foo", "header")
	delete(paths, "/server/features")
	paths["/albums/{id}/stats"] = map[string]any{"get": map[string]any{
		"parameters": []any{
			map[string]any{"name": "id", "in": "path"},
			map[string]any{"name": "key", "in": "query"},
		},
		"security": []any{map[string]any{"bearer": []any{}}},
	}}
	orig := op("/assets/{id}/original", "get")
	var kept []any
	for _, prm := range orig["parameters"].([]any) {
		if prm.(map[string]any)["name"] != "key" {
			kept = append(kept, prm)
		}
	}
	orig["parameters"] = kept
	op("/server/config", "get")["security"] = []any{map[string]any{"bearer": []any{}}}
	props("DownloadInfoDto")["zip"] = map[string]any{"type": "boolean"}
	delete(props("DownloadArchiveDto"), "archiveName")
	delete(props("DownloadInfoDto"), "userId")
	sizes := schemas["AssetMediaSize"].(map[string]any)
	sizes["enum"] = append(sizes["enum"].([]any), "huge")
	sizes["description"] = "ignored"
	op("/albums/{id}", "get")["x-immich-permission"] = "album.update"
	for _, prm := range op("/timeline/bucket", "get")["parameters"].([]any) {
		if prm.(map[string]any)["name"] == "order" {
			prm.(map[string]any)["required"] = true
		}
	}
	props("DownloadInfoDto")["archiveSize"].(map[string]any)["minimum"] = 1024

	out, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

var update = flag.Bool("update", false, "rewrite reviewed-api.json from the fixture")

// reviewed-api.json must match the fixture. After replacing the fixture, run
// go test ./internal/proxy -run TestReviewedAPI -update and review the diff of
// reviewed-api.json: it shows every change to the share API.
func TestReviewedAPI(t *testing.T) {
	s, err := buildShape(readFixture(t), buildRoutes(Config{AllowUpload: true}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	if *update {
		if err := os.WriteFile("reviewed-api.json", out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(out, reviewedJSON) {
		t.Error("reviewed-api.json doesn't match the fixture: run go test ./internal/proxy -run TestReviewedAPI -update and review the diff")
	}
}

func TestDriftDetects(t *testing.T) {
	_, issues, err := analyzeSpec(mutatedSpec(t), buildRoutes(Config{}))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, i := range issues {
		got[i.String()] = true
	}
	want := []string{
		`GET /timeline/buckets: unreviewed query parameter: "foo": allow it with a validator or deny it with a reason`,
		`GET /assets/{id}/thumbnail: unreviewed header parameter: "X-Immich-Foo"`,
		"GET /server/features: route removed: the allowlist has it, but the spec doesn't",
		"GET /albums/{id}/stats: new share route: Immich accepts share keys here, but the allowlist doesn't. Add it to buildRoutes or to excludedShareRoutes.",
		"GET /assets/{id}/original: no longer accepts share keys: the spec has no key parameter",
		"GET /server/config: no longer public: the spec now requires authentication",
		`POST /download/info: unreviewed body field: "zip": add it to the body struct or deny it with a reason`,
		`POST /download/archive: allowed body field not in spec: "archiveName"`,
		`POST /download/info: denied body field not in spec: "userId"`,
		`GET /assets/{id}/thumbnail: request schema changed: query size: reviewed {"required":false,"schema":{"enum":["fullsize","original","preview","thumbnail"],"type":"string"}}, now {"required":false,"schema":{"enum":["fullsize","huge","original","preview","thumbnail"],"type":"string"}}`,
		`GET /albums/{id}: request schema changed: permission: reviewed "album.read", now "album.update"`,
		`GET /timeline/bucket: request schema changed: query order: reviewed {"required":false,"schema":{"enum":["asc","desc"],"type":"string"}}, now {"required":true,"schema":{"enum":["asc","desc"],"type":"string"}}`,
		`POST /download/info: request schema changed: body application/json field archiveSize: reviewed {"maximum":9007199254740991,"minimum":1,"type":"integer"}, now {"maximum":9007199254740991,"minimum":1024,"type":"integer"}`,
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing issue: %s", w)
		}
		delete(got, w)
	}
	for g := range got {
		t.Errorf("unexpected issue: %s", g)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newLoggedProxy(t *testing.T, up *upstream) (*Proxy, *syncBuffer) {
	t.Helper()
	cfg := testConfig(t, up)
	cfg.FailLimit = 0
	buf := &syncBuffer{}
	return New(cfg, slog.New(slog.NewTextHandler(buf, nil))), buf
}

func TestBlockedRequestClassification(t *testing.T) {
	up := newUpstream(t)
	p, logs := newLoggedProxy(t, up)
	info, _, err := analyzeSpec(mutatedSpec(t), p.routes)
	if err != nil {
		t.Fatal(err)
	}
	p.spec.Store(info)

	k := "key=" + testKey
	cases := []struct {
		name  string
		req   *http.Request
		drift bool
		text  string
	}{
		{"new share route", get("/api/albums/" + testAlbum + "/stats?" + k), true,
			"share route GET /albums/{id}/stats is not in the allowlist"},
		{"excluded share route", post("/api/search/metadata?"+k, "application/json", "{}"), false,
			"excluded share route POST /search/metadata"},
		{"unknown route", get("/api/users/me?" + k), false, "API route not allowed"},
		{"unknown query parameter", get("/api/timeline/buckets?albumId=" + testAlbum + "&foo=1&" + k), true,
			`unknown query parameter \"foo\"`},
		{"invalid value", get("/api/assets/" + testAsset + "/thumbnail?size=huge&" + k), true,
			`invalid value for query parameter \"size\"`},
		{"denied query parameter", get("/api/timeline/buckets?albumId=" + testAlbum + "&userId=" + testAlbum + "&" + k), false,
			"share keys can't read user timelines"},
		{"unknown body field", post("/api/download/info?"+k, "application/json", `{"albumId":"`+testAlbum+`","zip":true}`), true,
			`unknown field \"zip\"`},
		{"denied body field", post("/api/download/info?"+k, "application/json", `{"albumId":"`+testAlbum+`","userId":"`+testAlbum+`"}`), false,
			"share keys can't download other users' assets"},
	}
	for _, c := range cases {
		before := len(logs.String())
		if w := do(p, c.req); w.Code < 400 {
			t.Errorf("%s: got %d", c.name, w.Code)
		}
		line := logs.String()[before:]
		if !strings.Contains(line, c.text) {
			t.Errorf("%s: log %q lacks %q", c.name, line, c.text)
		}
		if isDrift := strings.Contains(line, driftMsg); isDrift != c.drift {
			t.Errorf("%s: drift=%v, want %v: %s", c.name, isDrift, c.drift, line)
		}
	}
}

func TestWatchSpec(t *testing.T) {
	var mu sync.Mutex
	var fails int
	spec := readFixture(t)
	setSpec := func(raw []byte) { mu.Lock(); spec = raw; mu.Unlock() }
	up := newUpstream(t)
	up.respond = func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if fails > 0 {
			fails--
			http.Error(w, "starting", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(spec)
	}
	fails = 3
	p, logs := newLoggedProxy(t, up)
	p.cfg.SpecInterval = 20 * time.Millisecond
	p.specRetryMin, p.specRetryMax = time.Millisecond, 4*time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.WatchSpec(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	waitFor := func(what string, n int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for strings.Count(logs.String(), what) < n {
			if time.Now().After(deadline) {
				t.Fatalf("no %d× %q in log: %s", n, what, logs.String())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	// Startup: retried until Immich answers.
	waitFor("drift check passed", 1)
	if n := strings.Count(logs.String(), "drift check failed"); n != 3 {
		t.Errorf("%d failures logged, want 3", n)
	}
	if p.spec.Load() == nil {
		t.Fatal("spec not loaded")
	}

	// An unchanged spec is not reported again.
	before := up.count()
	for up.count() < before+3 {
		time.Sleep(5 * time.Millisecond)
	}
	if n := strings.Count(logs.String(), "drift check passed"); n != 1 {
		t.Errorf("unchanged spec reported %d times", n)
	}

	// An upgrade while running is noticed and replaces the stored spec.
	old := p.spec.Load()
	setSpec(mutatedSpec(t))
	waitFor("upstream spec changed", 1)
	waitFor("drift check found differences", 1)
	if p.spec.Load() == old {
		t.Error("stored spec not replaced")
	}

	// A fetch failure after a success is retried and keeps the stored spec.
	cur := p.spec.Load()
	mu.Lock()
	fails = 2
	mu.Unlock()
	waitFor("drift check failed", 5)
	if p.spec.Load() != cur {
		t.Error("stored spec dropped after a fetch failure")
	}
}

func TestCheckSpec(t *testing.T) {
	var out bytes.Buffer
	ok, err := CheckSpec(&out, mutatedSpec(t), Config{})
	if err != nil || ok || !strings.Contains(out.String(), "new share route") {
		t.Errorf("mutated: ok %v, err %v, output %s", ok, err, out.String())
	}
	out.Reset()
	ok, err = CheckSpec(&out, readFixture(t), Config{})
	if err != nil || !ok || !strings.Contains(out.String(), "no drift") {
		t.Errorf("fixture: ok %v, err %v, output %s", ok, err, out.String())
	}
	if _, err := CheckSpec(&out, []byte("{}"), Config{}); err == nil {
		t.Error("empty spec accepted")
	}
}
