// Package proxy implements a reverse proxy that exposes only Immich's shared
// link pages, using Immich's own web UI. Every request is checked against an
// allowlist of the routes, parameters and bodies the share page uses, and
// every API request must carry a valid share key.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const sharedLinkCookie = "immich_shared_link_token"

// Credentials and other headers that are always removed from client requests.
// The share key headers are removed too: the web UI sends the key as a query
// parameter, and accepting only one form keeps validation unambiguous.
var strippedHeaders = []string{
	"Authorization",
	"Proxy-Authorization",
	"X-Api-Key",
	"X-Immich-User-Token",
	"X-Immich-Session-Token",
	"X-Immich-Share-Key",
	"X-Immich-Share-Slug",
	"Upgrade", // no websockets: the share page never opens one
}

// Query parameters that Immich treats as credentials. Always removed.
var strippedQuery = []string{"apiKey", "sessionKey"}

type reqInfo struct {
	ip    string
	api   bool
	route *route // nil for web paths, or for unmatched API paths in log-only mode
}

type ctxKey struct{}

// verdict is the result of checking a request. A zero status means allowed.
type verdict struct {
	status int
	reason string
	// drift marks rejections that a legitimate web UI would cause after an
	// Immich API change: unknown parameters or fields on allowed routes,
	// invalid values, and share routes missing from the allowlist.
	drift bool
}

var allow = verdict{}

func reject(status int, reason string) verdict { return verdict{status: status, reason: reason} }
func drifted(status int, reason string) verdict {
	return verdict{status: status, reason: reason, drift: true}
}

// Proxy is the http.Handler. It strips credentials from each request, checks
// it, forwards it to Immich, and rewrites the response.
type Proxy struct {
	cfg       Config
	log       *slog.Logger
	routes    []*route
	limiter   *failLimiter
	shares    *shareChecker
	transport http.RoundTripper
	rp        *httputil.ReverseProxy
	spec      atomic.Pointer[specInfo] // set by WatchSpec, nil until then

	specRetryMin, specRetryMax time.Duration // WatchSpec backoff
}

// New returns a proxy for cfg.Upstream. Call WatchSpec to run the drift check.
func New(cfg Config, log *slog.Logger) *Proxy {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	p := &Proxy{
		cfg:       cfg,
		log:       log,
		routes:    buildRoutes(cfg),
		limiter:   newFailLimiter(cfg.FailLimit, cfg.FailWindow),
		shares:    newShareChecker(cfg.Upstream, transport, cfg.ShareCheckTTL),
		transport: transport,

		specRetryMin: 5 * time.Second,
		specRetryMax: 5 * time.Minute,
	}
	p.rp = &httputil.ReverseProxy{
		Transport:      transport,
		Rewrite:        p.rewrite,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.errorHandler,
		ErrorLog:       slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info := &reqInfo{ip: p.clientIP(r)}

	if p.limiter.blocked(info.ip) {
		if !p.cfg.LogOnly {
			p.log.Debug("rate limited", "ip", info.ip, "method", r.Method, "url", redactURL(r.URL))
			writeError(w, http.StatusTooManyRequests)
			return
		}
		p.log.Warn("would rate limit", "ip", info.ip, "method", r.Method, "url", redactURL(r.URL))
	}

	if stripped := sanitizeRequest(r); len(stripped) > 0 {
		p.log.Info("stripped credentials", "ip", info.ip, "method", r.Method, "url", redactURL(r.URL), "items", stripped)
	}

	v := p.check(r, info)
	if v.status == 0 && info.route != nil && !info.route.public && !info.route.noShareCheck {
		v = p.checkShare(r, info)
	}
	if v.status == 0 {
		p.log.Debug("allow", "ip", info.ip, "method", r.Method, "url", redactURL(r.URL))
	} else {
		attrs := []any{"status", v.status, "reason", v.reason, "ip", info.ip, "method", r.Method, "url", redactURL(r.URL)}
		switch {
		case v.drift && p.cfg.LogOnly:
			p.log.Warn(driftMsg+": would block", attrs...)
		case p.cfg.LogOnly:
			p.log.Warn("would block", attrs...)
		case v.status == http.StatusBadGateway:
			p.log.Error("share check failed", attrs...)
			writeError(w, v.status)
			return
		default:
			if v.drift {
				p.log.Warn(driftMsg+": blocked", attrs...)
			} else {
				p.log.Info("blocked", attrs...)
			}
			// Only API rejections count: that's where keys, IDs, and
			// passwords can be guessed. Browsers routinely probe web paths
			// that don't exist, such as /apple-touch-icon.png. (Immich's own
			// 404s for share pages are counted in modifyResponse.)
			if info.api {
				p.limiter.fail(info.ip)
			}
			writeError(w, v.status)
			return
		}
	}

	r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, info))
	p.rp.ServeHTTP(w, r)
}

// check validates a sanitized request. It may replace the request's query
// and body with canonical versions. On a body validation failure the
// original body is restored, so log-only mode can forward it.
func (p *Proxy) check(r *http.Request, info *reqInfo) verdict {
	path := r.URL.Path
	if r.URL.RawPath != "" || strings.Contains(path, "//") || strings.Contains(path, "/.") ||
		strings.ContainsAny(path, "\\\x00") {
		return reject(http.StatusNotFound, "suspicious path")
	}
	if path == "/api" || strings.HasPrefix(path, "/api/") {
		info.api = true
		return p.checkAPI(r, info)
	}
	return p.checkWeb(r)
}

func (p *Proxy) checkWeb(r *http.Request) verdict {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return reject(http.StatusMethodNotAllowed, "method not allowed on web path")
	}
	if hasBody(r) {
		return reject(http.StatusBadRequest, "unexpected body")
	}
	if !webPathAllowed(r.URL.Path, p.cfg.AllowSlugs) {
		return reject(http.StatusNotFound, "web path not allowed")
	}
	return allow
}

// unmatchedAPI classifies an API request that matches no allowed route.
func (p *Proxy) unmatchedAPI(method, rel string) verdict {
	if si := p.spec.Load(); si != nil {
		if srt := matchRoute(si.shareRoutes, method, rel); srt != nil {
			if reason, ok := excludedShareRoutes[srt.id()]; ok {
				return reject(http.StatusNotFound, "excluded share route "+srt.id()+": "+reason)
			}
			return drifted(http.StatusNotFound, "share route "+srt.id()+" is not in the allowlist")
		}
	}
	return reject(http.StatusNotFound, "API route not allowed")
}

func (p *Proxy) checkAPI(r *http.Request, info *reqInfo) verdict {
	rel := strings.TrimPrefix(r.URL.Path, "/api/")
	rt := matchRoute(p.routes, r.Method, rel)
	if rt == nil {
		return p.unmatchedAPI(r.Method, rel)
	}
	info.route = rt

	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return reject(http.StatusBadRequest, "malformed query string")
	}
	for _, name := range sortedKeys(q) {
		vals := q[name]
		if len(vals) != 1 {
			return reject(http.StatusBadRequest, "repeated query parameter "+strconv.Quote(name))
		}
		v := vals[0]
		switch name {
		case "key":
			if !vShareKey(v) {
				return reject(http.StatusBadRequest, "malformed share key")
			}
		case "slug":
			if !p.cfg.AllowSlugs {
				return reject(http.StatusBadRequest, "slug access is disabled")
			}
			if !vSlug(v) {
				return reject(http.StatusBadRequest, "malformed slug")
			}
		default:
			if reason, ok := rt.deny[name]; ok {
				return reject(http.StatusBadRequest, "query parameter "+strconv.Quote(name)+" not allowed: "+reason)
			}
			val, ok := rt.query[name]
			if !ok {
				return drifted(http.StatusBadRequest, "unknown query parameter "+strconv.Quote(truncate(name, 40)))
			}
			if !val(v) {
				return drifted(http.StatusBadRequest, "invalid value for query parameter "+strconv.Quote(name))
			}
		}
	}
	for _, name := range rt.required {
		if q.Get(name) == "" {
			return drifted(http.StatusBadRequest, "missing query parameter "+strconv.Quote(name))
		}
	}
	if !rt.public && q.Get("key") == "" && q.Get("slug") == "" {
		return reject(http.StatusUnauthorized, "missing share key")
	}
	for _, name := range sortedKeys(rt.headers) {
		if vs := r.Header.Values(name); len(vs) > 1 || (len(vs) == 1 && !rt.headers[name](vs[0])) {
			return drifted(http.StatusBadRequest, "invalid header "+name)
		}
	}

	switch rt.body {
	case bodyNone:
		if hasBody(r) {
			return reject(http.StatusBadRequest, "unexpected body")
		}
	case bodyStream:
		if mediaType(r.Header.Get("Content-Type")) != rt.mediaReq {
			return reject(http.StatusUnsupportedMediaType, "content type must be "+rt.mediaReq)
		}
		if r.Header.Get("Content-Encoding") != "" {
			return reject(http.StatusUnsupportedMediaType, "encoded request body")
		}
	case bodyCanon:
		if v := p.canonBody(r, rt); v.status != 0 {
			return v
		}
	}

	// Forward a canonical query string, so Immich parses exactly what was checked.
	r.URL.RawQuery = q.Encode()
	return allow
}

// checkShare asks Immich whether the request's share key (or slug) and share
// cookie grant access, enforcing share passwords on every content route.
func (p *Proxy) checkShare(r *http.Request, info *reqInfo) verdict {
	q := r.URL.Query()
	param, value := "key", q.Get("key")
	if value == "" {
		param, value = "slug", q.Get("slug")
	}
	err := p.shares.check(param, value, r.Header.Get("Cookie"), info.ip)
	switch {
	case err == nil:
		return allow
	case errors.Is(err, errShareDenied):
		return reject(http.StatusUnauthorized, "share denied by Immich (password required, expired, or invalid)")
	default:
		return reject(http.StatusBadGateway, err.Error())
	}
}

func (p *Proxy) canonBody(r *http.Request, rt *route) verdict {
	if r.Header.Get("Content-Encoding") != "" {
		return reject(http.StatusUnsupportedMediaType, "encoded request body")
	}
	if r.Body == nil {
		r.Body = http.NoBody
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, p.cfg.MaxBody+1))
	if err != nil {
		return reject(http.StatusBadRequest, "reading body: "+err.Error())
	}
	if int64(len(raw)) > p.cfg.MaxBody {
		// Restore what was read, followed by the rest, for log-only mode.
		r.Body = readCloser{io.MultiReader(bytes.NewReader(raw), r.Body), r.Body}
		return reject(http.StatusRequestEntityTooLarge, "body too large")
	}
	canon, ct, err := rt.bodyFn(raw, r.Header.Get("Content-Type"))
	if err != nil {
		setBody(r, raw, r.Header.Get("Content-Type"))
		var fe *fieldError
		if errors.As(err, &fe) && fe.reason == "" {
			return drifted(http.StatusBadRequest, "invalid body: "+err.Error())
		}
		return reject(http.StatusBadRequest, "invalid body: "+err.Error())
	}
	setBody(r, canon, ct)
	return allow
}

type readCloser struct {
	io.Reader
	io.Closer
}

func setBody(r *http.Request, b []byte, contentType string) {
	r.Body = io.NopCloser(bytes.NewReader(b))
	r.ContentLength = int64(len(b))
	r.TransferEncoding = nil
	r.Header.Del("Content-Length")
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
}

func hasBody(r *http.Request) bool {
	return r.ContentLength > 0 || len(r.TransferEncoding) > 0
}

// sanitizeRequest removes every credential except the share key and the
// password-protected share cookie. It returns what was removed, for logging.
func sanitizeRequest(r *http.Request) []string {
	var stripped []string
	for _, h := range strippedHeaders {
		if _, ok := r.Header[http.CanonicalHeaderKey(h)]; ok {
			stripped = append(stripped, "header:"+h)
			r.Header.Del(h)
		}
	}

	// Rebuild the Cookie header from raw pairs, keeping only the share cookie.
	// Raw pairs are kept verbatim, because the cookie's value is a
	// comma-separated list that net/http would quote on re-serialization.
	var keep []string
	for _, line := range r.Header.Values("Cookie") {
		for _, pair := range strings.Split(line, ";") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			name, _, _ := strings.Cut(pair, "=")
			if name == sharedLinkCookie {
				keep = append(keep, pair)
			} else {
				stripped = append(stripped, "cookie:"+truncate(name, 40))
			}
		}
	}
	r.Header.Del("Cookie")
	if len(keep) > 0 {
		r.Header.Set("Cookie", strings.Join(keep, "; "))
	}

	if r.URL.RawQuery != "" {
		q := r.URL.Query()
		changed := false
		for _, name := range strippedQuery {
			if q.Has(name) {
				q.Del(name)
				stripped = append(stripped, "query:"+name)
				changed = true
			}
		}
		if changed {
			r.URL.RawQuery = q.Encode()
		}
	}
	return stripped
}

func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	info, _ := pr.In.Context().Value(ctxKey{}).(*reqInfo)
	pr.SetURL(p.cfg.Upstream)

	// ReverseProxy has already removed incoming X-Forwarded-* headers.
	proto, host := "http", pr.In.Host
	if pr.In.TLS != nil {
		proto = "https"
	}
	if p.trustedRemote(pr.In) {
		if v := lastForwarded(pr.In.Header, "X-Forwarded-Proto"); v == "http" || v == "https" {
			proto = v
		}
		if v := lastForwarded(pr.In.Header, "X-Forwarded-Host"); reForwardedHost.MatchString(v) {
			host = v
		}
	}
	if info != nil {
		pr.Out.Header.Set("X-Forwarded-For", info.ip)
	}
	pr.Out.Header.Set("X-Forwarded-Proto", proto)
	pr.Out.Header.Set("X-Forwarded-Host", host)

	if info != nil && info.api {
		// JSON API responses are rewritten. Without a client Accept-Encoding,
		// the transport requests gzip itself and decompresses transparently.
		pr.Out.Header.Del("Accept-Encoding")
	}
}

// lastForwarded returns the last entry of a comma-separated forwarding
// header, across all its lines. That is the entry added by the nearest
// proxy. Some proxies, Apache's mod_proxy among them, append to a value the
// client sent instead of replacing it, so earlier entries can be forged.
func lastForwarded(h http.Header, name string) string {
	vals := h.Values(name)
	for i := len(vals) - 1; i >= 0; i-- {
		parts := strings.Split(vals[i], ",")
		for j := len(parts) - 1; j >= 0; j-- {
			if v := strings.TrimSpace(parts[j]); v != "" {
				return v
			}
		}
	}
	return ""
}

// A host name or IP literal with an optional port.
var reForwardedHost = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:.]{2,45}\])(?::[0-9]{1,5})?$`)

func (p *Proxy) modifyResponse(resp *http.Response) error {
	info, _ := resp.Request.Context().Value(ctxKey{}).(*reqInfo)

	filterSetCookies(resp.Header)
	resp.Header.Del("X-Powered-By")

	if info == nil {
		return nil
	}
	if !info.api {
		// Immich answers /share/<key> and /s/<slug> with 404 when the key or
		// slug is invalid, and otherwise with page metadata that includes
		// the share key. Count those 404s, or the web page would be an
		// unlimited oracle for guessing slugs.
		if resp.StatusCode == http.StatusNotFound && isShareEntry(resp.Request.URL) {
			p.limiter.fail(info.ip)
		}
		return nil
	}
	switch resp.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		// Includes invalid share keys and "no access" to asset or album IDs.
		p.limiter.fail(info.ip)
		p.log.Debug("upstream rejected", "status", resp.StatusCode, "ip", info.ip,
			"method", resp.Request.Method, "url", redactURL(resp.Request.URL))
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 ||
		mediaType(resp.Header.Get("Content-Type")) != "application/json" {
		return nil
	}
	if resp.Request.Method == http.MethodHead {
		// No body to scrub, and Immich's Content-Length is that of the
		// unscrubbed GET body, so it would be wrong.
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
		return nil
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && ce != "identity" {
		return fmt.Errorf("unexpected content encoding %q on JSON response", ce)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, p.cfg.MaxScrubBody+1))
	resp.Body.Close()
	if err != nil {
		return err
	}
	if int64(len(raw)) > p.cfg.MaxScrubBody {
		return errors.New("JSON response too large to scrub")
	}
	out := raw
	if len(bytes.TrimSpace(raw)) > 0 {
		if out, err = scrubJSON(raw); err != nil {
			return fmt.Errorf("scrubbing JSON response: %w", err)
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return nil
}

// filterSetCookies drops every Set-Cookie except the share password cookie.
func filterSetCookies(h http.Header) {
	vals := h.Values("Set-Cookie")
	if len(vals) == 0 {
		return
	}
	h.Del("Set-Cookie")
	for _, v := range vals {
		name, _, _ := strings.Cut(v, "=")
		if strings.TrimSpace(name) == sharedLinkCookie {
			h.Add("Set-Cookie", v)
		}
	}
}

func (p *Proxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, context.Canceled) && r.Context().Err() != nil {
		// The client went away, e.g. it scrolled past a timeline bucket or
		// seeked in a video. Nothing to report and nobody to answer.
		p.log.Debug("client canceled", "method", r.Method, "url", redactURL(r.URL))
		return
	}
	p.log.Error("upstream error", "method", r.Method, "url", redactURL(r.URL), "err", err)
	writeError(w, http.StatusBadGateway)
}

func writeError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"message": http.StatusText(status), "statusCode": status})
}

func (p *Proxy) trustedRemote(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return p.trusted(net.ParseIP(host))
}

func (p *Proxy) trusted(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range p.cfg.TrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP returns the remote address, or, when the request comes from a
// trusted proxy, the rightmost untrusted address in X-Forwarded-For.
func (p *Proxy) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !p.trusted(net.ParseIP(host)) {
		return host
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for _, h := range strings.Split(v, ",") {
			hops = append(hops, strings.TrimSpace(h))
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(hops[i])
		if ip == nil {
			break
		}
		if !p.trusted(ip) {
			return ip.String()
		}
		host = ip.String()
	}
	return host
}

// Share entry pages, which Immich validates itself: /share/<key> or
// /s/<slug>, with no further segments and no query. Deeper paths and query
// strings get a 404 status from Immich even for valid shares, because it
// matches the rest of the URL as part of the key.
var reShareEntry = regexp.MustCompile(`^/(share|s)/[^/]+$`)

func isShareEntry(u *url.URL) bool {
	return u.RawQuery == "" && reShareEntry.MatchString(u.Path)
}

var (
	reShareInPath = regexp.MustCompile(`^/share/([A-Za-z0-9_-]{6})[A-Za-z0-9_-]*`)
	reSlugInPath  = regexp.MustCompile(`^/s/[^/]+`)
)

// Query parameters removed from logged URLs. Slugs are short and often
// guessable, so even a prefix would help a guesser.
var redactedQuery = append([]string{"password", "slug"}, strippedQuery...)

// redactURL shortens share keys and removes other credentials, so logs don't
// contain usable ones. It is also used before sanitizeRequest has run.
func redactURL(u *url.URL) string {
	path := reShareInPath.ReplaceAllString(u.Path, "/share/$1...")
	path = reSlugInPath.ReplaceAllString(path, "/s/<redacted>")
	if u.RawQuery == "" {
		return path
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return path + "?<malformed>"
	}
	if k := q.Get("key"); k != "" {
		q.Set("key", truncate(k, 6))
	}
	for _, name := range redactedQuery {
		if q.Has(name) {
			q.Set(name, "<redacted>")
		}
	}
	return path + "?" + q.Encode()
}
