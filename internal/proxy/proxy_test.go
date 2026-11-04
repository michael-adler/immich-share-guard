// Tests of request handling: the allowlists, share checks, credential
// stripping, query and body canonicalization, response rewriting, rate
// limiting and forwarded headers.

package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAllowedRoutes(t *testing.T) {
	up := newUpstream(t)
	p := newTestProxy(t, up, nil)
	k := "key=" + testKey
	cases := []string{
		"/api/server/config",
		"/api/server/features",
		"/api/shared-links/me?" + k,
		"/api/albums/" + testAlbum + "?" + k,
		"/api/albums/" + testAlbum + "/map-markers?" + k,
		"/api/timeline/buckets?albumId=" + testAlbum + "&order=desc&" + k,
		"/api/timeline/bucket?albumId=" + testAlbum + "&timeBucket=2020-01-01T00:00:00.000Z&order=desc&" + k,
		"/api/assets/" + testAsset + "?" + k,
		"/api/assets/" + testAsset + "/thumbnail?size=preview&c=TestOnlyAbCdEf%2BGhIjKlMn01234%3D&edited=true&" + k,
		"/api/assets/" + testAsset + "/original?edited=true&" + k,
		"/api/assets/" + testAsset + "/video/playback?c=abc&" + k,
		"/api/assets/" + testAsset + "/video/stream/main.m3u8?" + k,
		"/api/assets/" + testAsset + "/video/stream/" + testAlbum + "/0/playlist.m3u8?" + k,
		"/api/assets/" + testAsset + "/video/stream/" + testAlbum + "/1/seg-00012.m4s?" + k,
		"/share/" + testKey,
		"/share/" + testKey + "/photos/" + testAsset,
		"/_app/immutable/entry/start.AbCd1234.js",
		"/favicon-32.png",
		"/custom.css",
		"/light_skeleton.png",
		"/dark_skeleton.png",
		"/manifest-icon-192.maskable.png",
		"/api/server/media-types",
		"/apple-touch-icon.png",
		"/site.webmanifest",
	}
	for _, c := range cases {
		w := do(p, get(c))
		if w.Code != http.StatusOK {
			t.Errorf("GET %s: got %d %s", c, w.Code, w.Body)
		}
	}
	// Each case reached upstream (share checks add shared-links/me requests).
	if n := up.count() - up.countPath("/api/shared-links/me"); n != len(cases)-1 {
		t.Errorf("upstream saw %d non-check requests, want %d", n, len(cases)-1)
	}
}

// passwordUpstream simulates a password-protected share: shared-links/me
// returns 401 unless the share cookie is present, and every other route
// succeeds with the bare key, as Immich 3.3.5 does.
func passwordUpstream(t *testing.T) *upstream {
	up := newUpstream(t)
	up.respond = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/shared-links/me" {
			if c, err := r.Cookie(sharedLinkCookie); err != nil || c.Value != "good" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"message":"Password required"}`)
				return
			}
		}
		_, _ = io.WriteString(w, `{}`)
	}
	return up
}

func TestShareCheckEnforcesPassword(t *testing.T) {
	up := passwordUpstream(t)
	p := newTestProxy(t, up, func(c *Config) { c.FailLimit = 0 })
	asset := "/api/assets/" + testAsset + "/thumbnail?key=" + testKey

	if w := do(p, get(asset)); w.Code != http.StatusUnauthorized {
		t.Errorf("without cookie: got %d", w.Code)
	}
	if n := up.count() - up.countPath("/api/shared-links/me"); n != 0 {
		t.Errorf("content request reached upstream without password")
	}

	r := get(asset)
	r.Header.Set("Cookie", sharedLinkCookie+"=wrong")
	if w := do(p, r); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong cookie: got %d", w.Code)
	}

	r = get(asset)
	r.Header.Set("Cookie", sharedLinkCookie+"=good")
	if w := do(p, r); w.Code != http.StatusOK {
		t.Errorf("good cookie: got %d", w.Code)
	}
	if up.last(t).path != "/api/assets/"+testAsset+"/thumbnail" {
		t.Errorf("content request not forwarded")
	}

	// shared-links/me itself is not pre-checked: Immich answers it directly.
	before := up.count()
	if w := do(p, get("/api/shared-links/me?key="+testKey)); w.Code != http.StatusUnauthorized {
		t.Errorf("shared-links/me: got %d", w.Code)
	}
	if up.count() != before+1 {
		t.Errorf("shared-links/me made %d upstream requests, want 1", up.count()-before)
	}
}

func TestShareCheckCachedAndMerged(t *testing.T) {
	up := newUpstream(t)
	release := make(chan struct{})
	up.respond = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/shared-links/me" {
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}
	p := newTestProxy(t, up, nil)

	var wg sync.WaitGroup
	codes := make([]int, 20)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = do(p, get("/api/assets/"+testAsset+"/thumbnail?key="+testKey)).Code
		}()
	}
	// Let all requests queue behind the first check, then release it.
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	for i, c := range codes {
		if c != 200 {
			t.Errorf("request %d: got %d", i, c)
		}
	}
	do(p, get("/api/assets/"+testAsset+"?key="+testKey))
	if n := up.countPath("/api/shared-links/me"); n != 1 {
		t.Errorf("share checks = %d, want 1", n)
	}
}

func TestShareCheckUpstreamError(t *testing.T) {
	up := newUpstream(t)
	up.respond = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}
	p := newTestProxy(t, up, nil)
	if w := do(p, get("/api/assets/"+testAsset+"?key="+testKey)); w.Code != http.StatusBadGateway {
		t.Errorf("got %d, want 502", w.Code)
	}
	if n := up.count(); n != 1 {
		t.Errorf("upstream saw %d requests, want only the check", n)
	}
}

// An unreachable upstream must not put the full share key in the logged
// reason, which a *url.Error would.
func TestShareCheckErrorRedacted(t *testing.T) {
	up := newUpstream(t)
	var buf bytes.Buffer
	cfg := testConfig(t, up)
	up.Close()
	p := New(cfg, slog.New(slog.NewTextHandler(&buf, nil)))
	if w := do(p, get("/api/assets/"+testAsset+"?key="+testKey)); w.Code != http.StatusBadGateway {
		t.Fatalf("got %d, want 502", w.Code)
	}
	if strings.Contains(buf.String(), testKey) {
		t.Errorf("share key logged:\n%s", buf.String())
	}
}

func TestShareCheckLogMode(t *testing.T) {
	up := passwordUpstream(t)
	p := newTestProxy(t, up, func(c *Config) { c.LogOnly = true })
	if w := do(p, get("/api/assets/"+testAsset+"?key="+testKey)); w.Code != 200 {
		t.Errorf("log mode should forward, got %d", w.Code)
	}
}

func TestBlockedRoutes(t *testing.T) {
	up := newUpstream(t)
	p := newTestProxy(t, up, func(c *Config) { c.FailLimit = 0 })
	k := "key=" + testKey
	cases := []struct {
		method, target string
		want           int
	}{
		{"GET", "/api/users/me?" + k, 404},
		{"GET", "/api/socket.io/?EIO=4&transport=websocket", 404},
		{"POST", "/api/auth/login", 404},
		{"GET", "/api/server/about?" + k, 404},
		{"GET", "/api/albums?" + k, 404},
		{"GET", "/api/albums/not-a-uuid?" + k, 404},
		{"PUT", "/api/albums/" + testAlbum + "?" + k, 404},
		{"DELETE", "/api/assets/" + testAsset + "?" + k, 404},
		{"POST", "/api/search/metadata?" + k, 404},
		{"POST", "/api/assets?" + k, 404}, // upload disabled by default
		{"GET", "/api/assets/" + testAsset + "/video/stream/" + testAlbum + "/0/..?" + k, 404},
		{"GET", "/api/assets/" + testAsset + "%2Fthumbnail?" + k, 404},
		{"GET", "/api//assets/" + testAsset + "?" + k, 404},
		{"GET", "/api/shared-links/me", 401},
		{"GET", "/api/assets/" + testAsset, 401},
		{"GET", "/api/shared-links/me?key=bad!key", 400},
		{"GET", "/api/shared-links/me?slug=my-trip", 400}, // slugs disabled
		{"GET", "/api/shared-links/me?" + k + "&key=" + testKey, 400},
		{"GET", "/api/shared-links/me?" + k + "&withExif=true", 400},
		{"GET", "/api/timeline/buckets?" + k, 400}, // albumId required
		{"GET", "/api/timeline/buckets?albumId=" + testAlbum + "&userId=" + testAlbum + "&" + k, 400},
		{"GET", "/api/timeline/buckets?albumId=" + testAlbum + "&personId=" + testAlbum + "&" + k, 400},
		{"GET", "/api/timeline/buckets?albumId=" + testAlbum + "&order=sideways&" + k, 400},
		{"GET", "/api/assets/" + testAsset + "/thumbnail?size=original&" + k, 400},
		{"GET", "/photos", 404},
		{"GET", "/auth/login", 404},
		{"GET", "/admin", 404},
		{"GET", "/s/my-trip", 404},
		{"GET", "/.well-known/immich", 404},
		{"GET", "/x.php", 404},
		{"GET", "/.env", 404},
		{"GET", "/a/b.png", 404},
		{"POST", "/share/" + testKey, 405},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.target, nil)
		r.RemoteAddr = "203.0.113.7:5555"
		w := do(p, r)
		if w.Code != c.want {
			t.Errorf("%s %s: got %d, want %d", c.method, c.target, w.Code, c.want)
		}
	}
	if n := up.count(); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
}

func TestStripsCredentials(t *testing.T) {
	up := newUpstream(t)
	p := newTestProxy(t, up, nil)
	r := get("/api/shared-links/me?key=" + testKey + "&apiKey=secret&sessionKey=secret")
	r.Header.Set("Authorization", "Bearer secret")
	r.Header.Set("X-Api-Key", "secret")
	r.Header.Set("X-Immich-User-Token", "secret")
	r.Header.Set("X-Immich-Session-Token", "secret")
	r.Header.Set("X-Immich-Share-Key", "other")
	r.Header.Add("Cookie", "immich_access_token=secret; immich_is_authenticated=true")
	r.Header.Add("Cookie", "immich_shared_link_token=abc=,def=; other=1")
	w := do(p, r)
	if w.Code != 200 {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
	s := up.last(t)
	for _, h := range []string{"Authorization", "X-Api-Key", "X-Immich-User-Token", "X-Immich-Session-Token", "X-Immich-Share-Key"} {
		if v := s.header.Get(h); v != "" {
			t.Errorf("header %s reached upstream: %q", h, v)
		}
	}
	if got := s.header.Get("Cookie"); got != "immich_shared_link_token=abc=,def=" {
		t.Errorf("Cookie upstream = %q", got)
	}
	q, _ := url.ParseQuery(s.rawQuery)
	if q.Has("apiKey") || q.Has("sessionKey") || q.Get("key") != testKey {
		t.Errorf("query upstream = %q", s.rawQuery)
	}
}

func TestCredentialsStrippedInLogMode(t *testing.T) {
	up := newUpstream(t)
	p := newTestProxy(t, up, func(c *Config) { c.LogOnly = true })
	r := get("/api/users/me?apiKey=secret")
	r.Header.Set("X-Api-Key", "secret")
	r.Header.Set("Cookie", "immich_access_token=secret")
	if w := do(p, r); w.Code != 200 {
		t.Fatalf("log mode should forward, got %d", w.Code)
	}
	s := up.last(t)
	if s.path != "/api/users/me" || s.header.Get("X-Api-Key") != "" || s.header.Get("Cookie") != "" || strings.Contains(s.rawQuery, "apiKey") {
		t.Errorf("credentials reached upstream in log mode: %+v", s)
	}
}

func TestCanonicalQuery(t *testing.T) {
	up := newUpstream(t)
	p := newTestProxy(t, up, nil)
	do(p, get("/api/timeline/buckets?order=desc&albumId="+testAlbum+"&key="+testKey))
	s := up.last(t)
	want := "albumId=" + testAlbum + "&key=" + testKey + "&order=desc"
	if s.rawQuery != want {
		t.Errorf("query = %q, want %q", s.rawQuery, want)
	}
}

func TestDownloadInfoBody(t *testing.T) {
	up := newUpstream(t)
	p := newTestProxy(t, up, func(c *Config) { c.FailLimit = 0 })
	target := "/api/download/info?key=" + testKey

	w := do(p, post(target, "application/json", `{"albumId":"`+testAlbum+`"}`))
	if w.Code != 200 {
		t.Fatalf("valid body: got %d %s", w.Code, w.Body)
	}
	if got := up.last(t).body; got != `{"albumId":"`+testAlbum+`"}` {
		t.Errorf("canonical body = %s", got)
	}

	bad := []struct{ ct, body string }{
		{"application/json", `{"albumId":"` + testAlbum + `","userId":"` + testAlbum + `"}`},
		{"application/json", `{"ALBUMID":"` + testAlbum + `"}`}, // names must match exactly
		{"application/json", `["` + testAlbum + `"]`},
		{"application/json", `{"assetIds":["x"]}`},
		{"application/json", `{}`},
		{"application/json", `{"albumId":"` + testAlbum + `"} {}`},
		{"application/json", `{"albumId":"` + testAlbum + `","archiveSize":0}`},
		{"text/plain", `{"albumId":"` + testAlbum + `"}`},
	}
	before := up.count()
	for _, b := range bad {
		if w := do(p, post(target, b.ct, b.body)); w.Code == 200 {
			t.Errorf("accepted %s %s", b.ct, b.body)
		}
	}
	if up.count() != before {
		t.Error("invalid bodies reached upstream")
	}
}

func TestDownloadArchiveForm(t *testing.T) {
	up := newUpstream(t)
	p := newTestProxy(t, up, func(c *Config) { c.FailLimit = 0 })
	target := "/api/download/archive?key=" + testKey
	form := url.Values{"assetIds": {testAsset + "," + testAlbum}, "archiveName": {"Immich-20261103_120000"}, "edited": {"true"}}
	w := do(p, post(target, "application/x-www-form-urlencoded", form.Encode()))
	if w.Code != 200 {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
	s := up.last(t)
	got, _ := url.ParseQuery(s.body)
	if got.Get("assetIds") != testAsset+","+testAlbum || got.Get("archiveName") != "Immich-20261103_120000" {
		t.Errorf("body upstream = %q", s.body)
	}
	if s.header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Errorf("content type = %q", s.header.Get("Content-Type"))
	}

	for _, body := range []string{
		"assetIds=" + testAsset + "&userId=" + testAlbum,
		"assetIds=" + testAsset + ",nope",
		"assetIds=" + testAsset + "&assetIds=" + testAsset,
		"archiveName=x",
		"assetIds=" + testAsset + "&archiveName=..%2F..%2Fetc",
	} {
		if w := do(p, post(target, "application/x-www-form-urlencoded", body)); w.Code != 400 {
			t.Errorf("body %q: got %d", body, w.Code)
		}
	}
	if w := do(p, post(target, "application/json", `{"assetIds":["`+testAsset+`"],"edited":true}`)); w.Code != 200 {
		t.Errorf("JSON archive body: got %d %s", w.Code, w.Body)
	}
}

func TestLogModeForwardsOriginalBody(t *testing.T) {
	up := newUpstream(t)
	p := newTestProxy(t, up, func(c *Config) { c.LogOnly = true })
	body := `{"albumId":"` + testAlbum + `","userId":"x"}`
	do(p, post("/api/download/info?key="+testKey, "application/json", body))
	if got := up.last(t).body; got != body {
		t.Errorf("body upstream = %q, want original", got)
	}
}

func TestBodyTooLarge(t *testing.T) {
	up := newUpstream(t)
	p := newTestProxy(t, up, func(c *Config) { c.MaxBody = 100 })
	body := `{"assetIds":["` + strings.Repeat(testAsset+`","`, 10) + testAsset + `"]}`
	if w := do(p, post("/api/download/info?key="+testKey, "application/json", body)); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("got %d", w.Code)
	}
}

func TestScrubOriginalPath(t *testing.T) {
	up := newUpstream(t)
	up.respond = func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "" && r.Header.Get("Accept-Encoding") != "gzip" {
			t.Errorf("client Accept-Encoding forwarded on scrubbed route: %q", r.Header.Get("Accept-Encoding"))
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(w, `{"id":"`+testAsset+`","originalPath":"/data/library/user/2020/01/x <1>.webp",`+
			`"exifInfo":{"fileSizeInByte":12345678901234,"latitude":12.345678},`+
			`"assets":[{"originalPath":"C:\\photos\\y.jpg"}],"tags":[],"password":"secret",`+
			`"owner":{"name":"Test User","email":"user@example.com","profileImagePath":"/data/profile/x.jpg"},`+
			`"albumUsers":[{"role":"editor","user":{"name":"Other","email":"other@example.com"}}]}`)
	}
	p := newTestProxy(t, up, nil)
	for _, path := range []string{"/api/assets/" + testAsset, "/api/shared-links/me", "/api/albums/" + testAlbum + "/map-markers"} {
		r := get(path + "?key=" + testKey)
		r.Header.Set("Accept-Encoding", "br, deflate")
		w := do(p, r)
		if w.Code != 200 {
			t.Fatalf("%s: got %d", path, w.Code)
		}
		if cl := w.Header().Get("Content-Length"); cl != strconv.Itoa(w.Body.Len()) {
			t.Errorf("%s: Content-Length %q, body %d bytes", path, cl, w.Body.Len())
		}
		var d map[string]any
		dec := json.NewDecoder(w.Body)
		dec.UseNumber()
		if err := dec.Decode(&d); err != nil {
			t.Fatal(err)
		}
		if d["originalPath"] != "x <1>.webp" {
			t.Errorf("%s: originalPath = %v", path, d["originalPath"])
		}
		if got := d["assets"].([]any)[0].(map[string]any)["originalPath"]; got != "y.jpg" {
			t.Errorf("%s: nested originalPath = %v", path, got)
		}
		if got := d["owner"].(map[string]any)["profileImagePath"]; got != "" {
			t.Errorf("%s: profileImagePath = %v, want blank", path, got)
		}
		if got := d["owner"].(map[string]any)["email"]; got != "" {
			t.Errorf("%s: owner email = %v, want blank", path, got)
		}
		au := d["albumUsers"].([]any)[0].(map[string]any)
		if got := au["user"].(map[string]any)["email"]; got != "" {
			t.Errorf("%s: album user email = %v, want blank", path, got)
		}
		if got := d["password"]; got != "" {
			t.Errorf("%s: password = %v, want blank", path, got)
		}
		if au["role"] != "editor" {
			t.Errorf("%s: album user role = %v", path, au["role"])
		}
		if got := d["owner"].(map[string]any)["name"]; got != "Test User" {
			t.Errorf("%s: unrelated field changed: %v", path, got)
		}
		if got := d["exifInfo"].(map[string]any)["fileSizeInByte"]; got != json.Number("12345678901234") {
			t.Errorf("%s: number not preserved: %v", path, got)
		}
	}
}

func TestSetCookieFiltered(t *testing.T) {
	up := newUpstream(t)
	up.respond = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "immich_shared_link_token=abc; Path=/; HttpOnly")
		w.Header().Add("Set-Cookie", "immich_access_token=secret; Path=/")
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}
	p := newTestProxy(t, up, nil)
	w := do(p, post("/api/shared-links/login?key="+testKey, "application/json", `{"password":"hunter2"}`))
	if w.Code != 200 {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
	cookies := w.Result().Header.Values("Set-Cookie")
	if len(cookies) != 1 || !strings.HasPrefix(cookies[0], "immich_shared_link_token=") {
		t.Errorf("Set-Cookie = %q", cookies)
	}
	if w.Header().Get("X-Powered-By") != "" {
		t.Error("X-Powered-By not removed")
	}
}

func TestRateLimit(t *testing.T) {
	up := newUpstream(t)
	up.respond = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message":"Invalid share key"}`)
	}
	p := newTestProxy(t, up, func(c *Config) { c.FailLimit = 3; c.FailWindow = time.Minute })
	now := time.Now()
	p.limiter.now = func() time.Time { return now }

	guess := "/api/shared-links/me?key=" + strings.Repeat("A", 67)
	for i := 0; i < 3; i++ {
		if w := do(p, get(guess)); w.Code != 401 {
			t.Fatalf("attempt %d: got %d", i, w.Code)
		}
	}
	if w := do(p, get(guess)); w.Code != http.StatusTooManyRequests {
		t.Fatalf("after limit: got %d", w.Code)
	}
	other := get(guess)
	other.RemoteAddr = "198.51.100.1:1"
	if w := do(p, other); w.Code != 401 {
		t.Errorf("other IP: got %d", w.Code)
	}
	now = now.Add(time.Minute)
	if w := do(p, get(guess)); w.Code != 401 {
		t.Errorf("after window: got %d", w.Code)
	}
}

func TestWebProbesNotRateLimited(t *testing.T) {
	up := newUpstream(t)
	p := newTestProxy(t, up, func(c *Config) { c.FailLimit = 2 })
	for i := 0; i < 5; i++ {
		if w := do(p, get("/wp-login.php")); w.Code != 404 {
			t.Fatalf("probe %d: got %d", i, w.Code)
		}
	}
	if w := do(p, get("/api/server/config")); w.Code != 200 {
		t.Errorf("after web probes: got %d, want 200", w.Code)
	}
	for i := 0; i < 2; i++ {
		do(p, get("/api/users/me"))
	}
	if w := do(p, get("/api/server/config")); w.Code != http.StatusTooManyRequests {
		t.Errorf("after API failures: got %d, want 429", w.Code)
	}
}

func TestClientIP(t *testing.T) {
	up := newUpstream(t)
	p := newTestProxy(t, up, nil)
	cases := []struct{ remote, xff, want string }{
		{"203.0.113.7:1", "1.2.3.4", "203.0.113.7"},      // untrusted remote: ignore XFF
		{"127.0.0.1:1", "1.2.3.4", "1.2.3.4"},            // trusted: use XFF
		{"127.0.0.1:1", "6.6.6.6, 1.2.3.4", "1.2.3.4"},   // rightmost untrusted wins
		{"127.0.0.1:1", "1.2.3.4, 127.0.0.1", "1.2.3.4"}, // skip trusted hops
		{"127.0.0.1:1", "", "127.0.0.1"},                 // no XFF
		{"[::1]:1", "2001:db8::1", "2001:db8::1"},        // IPv6
		{"127.0.0.1:1", "garbage, 1.2.3.4", "1.2.3.4"},   // stop at garbage only if reached
		{"127.0.0.1:1", "1.2.3.4, garbage", "127.0.0.1"}, // unparsable hop: fall back
	}
	for _, c := range cases {
		r := get("/")
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := p.clientIP(r); got != c.want {
			t.Errorf("remote %s xff %q: got %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
}

func TestForwardedHeaders(t *testing.T) {
	up := newUpstream(t)
	p := newTestProxy(t, up, nil)
	r := get("/api/server/config")
	r.RemoteAddr = "127.0.0.1:1"
	r.Host = "internal"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "photos.example.com")
	do(p, r)
	h := up.last(t).header
	if h.Get("X-Forwarded-For") != "1.2.3.4" || h.Get("X-Forwarded-Proto") != "https" || h.Get("X-Forwarded-Host") != "photos.example.com" {
		t.Errorf("forwarded headers = %v %v %v", h.Get("X-Forwarded-For"), h.Get("X-Forwarded-Proto"), h.Get("X-Forwarded-Host"))
	}

	// Only the entry added by the nearest proxy counts.
	for _, c := range []struct {
		proto, host []string
		wantProto   string
		wantHost    string
	}{
		{[]string{"http, https"}, []string{"evil.example, photos.example.com"}, "https", "photos.example.com"},
		{[]string{"https", "http"}, []string{"evil.example", "photos.example.com:8443"}, "http", "photos.example.com:8443"},
		{[]string{"https,"}, []string{"[2001:db8::1]:443"}, "https", "[2001:db8::1]:443"},
		{[]string{"gopher"}, []string{"photos.example.com, bad host"}, "http", "internal"},
		{nil, []string{"x/y"}, "http", "internal"},
	} {
		r = get("/api/server/config")
		r.RemoteAddr = "127.0.0.1:1"
		r.Host = "internal"
		for _, v := range c.proto {
			r.Header.Add("X-Forwarded-Proto", v)
		}
		for _, v := range c.host {
			r.Header.Add("X-Forwarded-Host", v)
		}
		do(p, r)
		h = up.last(t).header
		if got := h.Values("X-Forwarded-Proto"); len(got) != 1 || got[0] != c.wantProto {
			t.Errorf("proto %q: forwarded %q, want %q", c.proto, got, c.wantProto)
		}
		if got := h.Values("X-Forwarded-Host"); len(got) != 1 || got[0] != c.wantHost {
			t.Errorf("host %q: forwarded %q, want %q", c.host, got, c.wantHost)
		}
	}

	r = get("/api/server/config") // untrusted remote: spoofed headers ignored
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Forwarded-Proto", "https")
	do(p, r)
	h = up.last(t).header
	if h.Get("X-Forwarded-For") != "203.0.113.7" || h.Get("X-Forwarded-Proto") != "http" {
		t.Errorf("spoofed forwarded headers passed: %v %v", h.Get("X-Forwarded-For"), h.Get("X-Forwarded-Proto"))
	}
}

func TestUploadFlag(t *testing.T) {
	up := newUpstream(t)
	p := newTestProxy(t, up, func(c *Config) { c.AllowUpload = true })
	r := post("/api/assets?key="+testKey, "multipart/form-data; boundary=x", "--x--")
	if w := do(p, r); w.Code != 200 {
		t.Errorf("upload: got %d %s", w.Code, w.Body)
	}
	r = post("/api/assets?key="+testKey, "application/json", "{}")
	if w := do(p, r); w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("non-multipart upload: got %d", w.Code)
	}
}

func TestRedactURL(t *testing.T) {
	for _, raw := range []string{
		"/share/" + testKey + "?key=" + testKey + "&size=preview",
		"/api/users/me?apiKey=SECRET&sessionKey=SECRET",
		"/api/albums/" + testAlbum + "?slug=SECRET",
		"/s/SECRET/photos/" + testAsset,
		"/api/shared-links/login?key=" + testKey + "&password=SECRET",
	} {
		u, _ := url.Parse(raw)
		got := redactURL(u)
		if strings.Contains(got, testKey) || strings.Contains(got, "SECRET") {
			t.Errorf("%s: not redacted: %s", raw, got)
		}
	}
}

// A client that sends an API key and is rate limited must not get the key
// logged: that log line is written before credentials are stripped.
func TestRateLimitLogRedacted(t *testing.T) {
	up := newUpstream(t)
	var buf bytes.Buffer
	cfg := testConfig(t, up)
	cfg.FailLimit = 1
	p := New(cfg, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	do(p, get("/api/nope"))
	if w := do(p, get("/api/nope?apiKey=SECRET")); w.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", w.Code)
	}
	if strings.Contains(buf.String(), "SECRET") {
		t.Errorf("API key logged:\n%s", buf.String())
	}
}

// For a share without a password, the cookie must not reach the cache key,
// or varying it would force a new upstream check on every request.
func TestShareCheckIgnoresCookieWithoutPassword(t *testing.T) {
	up := newUpstream(t)
	p := newTestProxy(t, up, nil)
	for i := range 5 {
		r := get("/api/assets/" + testAsset + "?key=" + testKey)
		r.Header.Set("Cookie", sharedLinkCookie+"=junk"+strconv.Itoa(i))
		if w := do(p, r); w.Code != 200 {
			t.Fatalf("request %d: got %d", i, w.Code)
		}
	}
	if n := up.countPath("/api/shared-links/me"); n != 1 {
		t.Errorf("share checks = %d, want 1", n)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	for _, r := range up.reqs {
		if r.path == "/api/shared-links/me" && r.header.Get("Cookie") != "" {
			t.Errorf("share check sent cookie %q", r.header.Get("Cookie"))
		}
	}
}

// Wrong cookies for a password share each count as a failure.
func TestShareCheckWrongCookiesRateLimited(t *testing.T) {
	up := passwordUpstream(t)
	p := newTestProxy(t, up, func(c *Config) { c.FailLimit = 3 })
	for i := range 5 {
		r := get("/api/assets/" + testAsset + "?key=" + testKey)
		r.Header.Set("Cookie", sharedLinkCookie+"=junk"+strconv.Itoa(i))
		do(p, r)
	}
	if n := up.countPath("/api/shared-links/me"); n > 4 {
		t.Errorf("share checks = %d, want at most 4 (one without cookie, three with)", n)
	}
	r := get("/api/assets/" + testAsset + "?key=" + testKey)
	r.Header.Set("Cookie", sharedLinkCookie+"=good")
	if w := do(p, r); w.Code != http.StatusTooManyRequests {
		t.Errorf("after wrong cookies: got %d, want 429", w.Code)
	}
}

func TestHeadKeepsContentLength(t *testing.T) {
	up := newUpstream(t)
	up.respond = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "11")
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, `{"ok":true}`)
		}
	}
	p := newTestProxy(t, up, nil)
	r := httptest.NewRequest(http.MethodHead, "/api/assets/"+testAsset+"?key="+testKey, nil)
	r.RemoteAddr = "203.0.113.7:5555"
	w := do(p, r)
	// Immich's length is of the unscrubbed body, so it must not be passed on.
	if w.Code != 200 || w.Header().Get("Content-Length") != "" {
		t.Errorf("HEAD: got %d, Content-Length %q, want 200, none", w.Code, w.Header().Get("Content-Length"))
	}
}

// Immich validates the key or slug of a share entry page itself. Its 404s
// must count, or slugs could be guessed without limit.
func TestShareEntryPage404sRateLimited(t *testing.T) {
	up := newUpstream(t)
	up.respond = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
	}
	p := newTestProxy(t, up, func(c *Config) { c.FailLimit = 3; c.AllowSlugs = true })

	// Deep links and query strings get a 404 from Immich even for valid
	// shares, so they don't count.
	for range 5 {
		do(p, get("/share/"+testKey+"/photos/"+testAsset))
		do(p, get("/share/"+testKey+"?x=1"))
	}
	if w := do(p, get("/api/server/config")); w.Code != 404 {
		t.Fatalf("deep links counted as failures: got %d", w.Code)
	}

	for i := range 3 {
		do(p, get("/s/guess"+strconv.Itoa(i)))
	}
	if w := do(p, get("/s/another")); w.Code != http.StatusTooManyRequests {
		t.Errorf("after slug guesses: got %d, want 429", w.Code)
	}
}

func TestRateLimitIPv6Prefix(t *testing.T) {
	up := newUpstream(t)
	p := newTestProxy(t, up, func(c *Config) { c.FailLimit = 3 })
	for i := range 3 {
		r := get("/api/users/me")
		r.RemoteAddr = "[2001:db8:1:2::" + strconv.Itoa(i+1) + "]:1"
		do(p, r)
	}
	r := get("/api/server/config")
	r.RemoteAddr = "[2001:db8:1:2:ffff::9]:1"
	if w := do(p, r); w.Code != http.StatusTooManyRequests {
		t.Errorf("same /64: got %d, want 429", w.Code)
	}
	r = get("/api/server/config")
	r.RemoteAddr = "[2001:db8:1:3::1]:1"
	if w := do(p, r); w.Code != 200 {
		t.Errorf("other /64: got %d, want 200", w.Code)
	}
}
