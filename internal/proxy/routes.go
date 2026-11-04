// The allowlists: which API routes, path parameters and query parameters
// are forwarded, with validators for their values, and which web paths are
// served.

package proxy

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// validator reports whether a single query, path, or header value is acceptable.
type validator func(string) bool

func re(pattern string) validator {
	r := regexp.MustCompile(pattern)
	return r.MatchString
}

func oneOf(values ...string) validator {
	return func(s string) bool {
		for _, v := range values {
			if s == v {
				return true
			}
		}
		return false
	}
}

var (
	vUUID       = re(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	vInt        = re(`^[0-9]{1,9}$`)
	vNumber     = re(`^[0-9]{1,9}(\.[0-9]{1,9})?$`)
	vBool       = oneOf("true", "false")
	vOrder      = oneOf("asc", "desc")
	vThumbSize  = oneOf("thumbnail", "preview", "fullsize")
	vTimeBucket = re(`^[0-9]{4}-[0-9]{2}-[0-9]{2}(T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,3})?Z)?$`)
	// The web UI uses the asset thumbhash (base64) as a cache-busting "c" parameter.
	vCacheKey = re(`^[A-Za-z0-9+/=_.:-]{1,128}$`)
	// HLS segment file names. No leading dot, so no "..".
	vSegment  = re(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}$`)
	vChecksum = re(`^[A-Za-z0-9+/=]{1,128}$`)
	// Share keys are 50 random bytes, base64url (67 chars) or hex (100 chars).
	vShareKey = re(`^[A-Za-z0-9_-]{16,128}$`)
	vSlug     = re(`^[A-Za-z0-9_.~-]{1,128}$`)
	// Any single path segment. Used only for spec routes the proxy doesn't
	// serve, to classify blocked requests.
	vAny = re(`^[^/]+$`)
)

// pathParams maps path parameter names used in route patterns to validators.
// The names match Immich's OpenAPI spec, so patterns compare directly.
var pathParams = map[string]validator{
	"id":           vUUID,
	"sessionId":    vUUID,
	"variantIndex": vInt,
	"filename":     vSegment,
}

// undocumentedQuery lists query parameters the web UI sends that Immich's
// spec doesn't document. The drift check doesn't report them as stale.
var undocumentedQuery = map[string]string{
	"c": "cache-busting parameter added by the web UI, ignored by Immich",
}

// excludedShareRoutes are routes that accept share keys but are deliberately
// not allowed. Keys are "METHOD /path" as in the OpenAPI spec.
var excludedShareRoutes = map[string]string{
	"POST /search/metadata": "only used by the /search page, never the share page",
	"POST /assets":          "uploads, enabled with SHARE_GUARD_ALLOW_UPLOAD",
}

type bodyKind int

const (
	bodyNone   bodyKind = iota // request must not have a body
	bodyCanon                  // body is parsed, validated, and re-encoded by bodyFn
	bodyStream                 // body is streamed through unvalidated (uploads only)
)

// bodyFn validates a raw request body and returns the canonical body and
// content type to forward upstream.
type bodyFn func(raw []byte, contentType string) (canon []byte, canonType string, err error)

type segment struct {
	literal string
	param   validator // nil for a literal segment
}

type route struct {
	method  string
	pattern string // relative to /api/, e.g. "assets/{id}/thumbnail"
	segs    []segment
	public  bool // no share key required
	// noShareCheck skips the shared-links/me pre-check (see sharecheck.go).
	// Only for routes where Immich checks the share password itself.
	noShareCheck bool

	// Every query parameter Immich documents for the route must be either
	// allowed (query) or denied with a reason (deny). key and slug are
	// handled for all routes. The drift check reports anything else.
	query    map[string]validator
	deny     map[string]string
	required []string
	headers  map[string]validator // header parameters, validated when present

	body     bodyKind
	bodyFn   bodyFn
	bodySpec *bodyPolicy // field decisions, for bodyCanon routes
	mediaReq string      // required media type, for bodyStream routes
}

// id returns the route's key in the OpenAPI spec, e.g. "GET /assets/{id}".
func (rt *route) id() string { return rt.method + " /" + rt.pattern }

func (rt *route) String() string { return rt.id() }

// compile parses the pattern. With lenient, path parameters match any
// segment, which is used for spec routes the proxy doesn't serve.
func (rt *route) compile(lenient bool) *route {
	for _, s := range strings.Split(rt.pattern, "/") {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			v, ok := pathParams[s[1:len(s)-1]]
			switch {
			case lenient:
				v = vAny
			case !ok:
				panic(fmt.Sprintf("route %q: unknown path parameter %s", rt.pattern, s))
			}
			rt.segs = append(rt.segs, segment{param: v})
		} else {
			rt.segs = append(rt.segs, segment{literal: s})
		}
	}
	return rt
}

func (rt *route) matches(method string, parts []string) bool {
	if method != rt.method && !(method == http.MethodHead && rt.method == http.MethodGet) {
		return false
	}
	if len(parts) != len(rt.segs) {
		return false
	}
	for i, s := range rt.segs {
		if s.param == nil {
			if parts[i] != s.literal {
				return false
			}
		} else if !s.param(parts[i]) {
			return false
		}
	}
	return true
}

// Timeline filters Immich documents but the share page never sends.
var timelineDeny = map[string]string{
	"userId":          "share keys can't read user timelines",
	"tagId":           "share keys can't read tags",
	"personId":        "filters an album by person, and Immich doesn't check it for share keys",
	"withPartners":    "partner timelines aren't shared",
	"visibility":      "not used by the share page",
	"isFavorite":      "not used by the share page",
	"isTrashed":       "not used by the share page",
	"orderBy":         "not used by the share page",
	"bbox":            "not used by the share page",
	"withCoordinates": "not used by the share page",
	"withStacked":     "not used by the share page",
}

// buildRoutes returns the API allowlist. It is the subset of Immich's
// shared-link routes that the web share page uses, plus the public bootstrap
// routes the web app loads at startup. Query parameters are limited to what
// the web UI sends. excludedShareRoutes lists the shared-link routes left out.
func buildRoutes(cfg Config) []*route {
	media := map[string]validator{"c": vCacheKey, "edited": vBool}
	thumb := map[string]validator{"c": vCacheKey, "edited": vBool, "size": vThumbSize}
	timeline := map[string]validator{"albumId": vUUID, "order": vOrder}
	bucket := map[string]validator{"albumId": vUUID, "order": vOrder, "timeBucket": vTimeBucket}

	rs := []*route{
		{method: http.MethodGet, pattern: "server/config", public: true},
		{method: http.MethodGet, pattern: "server/features", public: true},
		// Loaded at startup by the web app's upload manager, even without uploads.
		{method: http.MethodGet, pattern: "server/media-types", public: true},

		{method: http.MethodGet, pattern: "shared-links/me", noShareCheck: true},
		{method: http.MethodPost, pattern: "shared-links/login", noShareCheck: true,
			body: bodyCanon, bodyFn: canonLogin, bodySpec: &loginPolicy},

		{method: http.MethodGet, pattern: "albums/{id}"},
		{method: http.MethodGet, pattern: "albums/{id}/map-markers"},

		{method: http.MethodGet, pattern: "timeline/buckets", query: timeline, deny: timelineDeny,
			required: []string{"albumId"}},
		{method: http.MethodGet, pattern: "timeline/bucket", query: bucket, deny: timelineDeny,
			required: []string{"albumId", "timeBucket"}},

		{method: http.MethodGet, pattern: "assets/{id}"},
		{method: http.MethodGet, pattern: "assets/{id}/thumbnail", query: thumb},
		{method: http.MethodGet, pattern: "assets/{id}/original", query: media},
		{method: http.MethodGet, pattern: "assets/{id}/video/playback", query: map[string]validator{"c": vCacheKey}},
		{method: http.MethodGet, pattern: "assets/{id}/video/stream/main.m3u8"},
		{method: http.MethodGet, pattern: "assets/{id}/video/stream/{sessionId}/{variantIndex}/playlist.m3u8",
			headers: map[string]validator{"X-Immich-Hls-Pos": vNumber}},
		{method: http.MethodGet, pattern: "assets/{id}/video/stream/{sessionId}/{variantIndex}/{filename}",
			headers: map[string]validator{"X-Immich-Hls-Msn": vInt}},
		{method: http.MethodDelete, pattern: "assets/{id}/video/stream/{sessionId}"},

		{method: http.MethodPost, pattern: "download/info",
			body: bodyCanon, bodyFn: canonDownloadInfo, bodySpec: &downloadInfoPolicy},
		{method: http.MethodPost, pattern: "download/archive",
			body: bodyCanon, bodyFn: canonDownloadArchive, bodySpec: &downloadArchivePolicy},
	}
	if cfg.AllowUpload {
		rs = append(rs, &route{method: http.MethodPost, pattern: "assets",
			body: bodyStream, mediaReq: "multipart/form-data",
			headers: map[string]validator{"X-Immich-Checksum": vChecksum}})
	}
	for _, rt := range rs {
		rt.compile(false)
	}
	return rs
}

func matchRoute(routes []*route, method, rel string) *route {
	parts := strings.Split(rel, "/")
	for _, rt := range routes {
		if rt.matches(method, parts) {
			return rt
		}
	}
	return nil
}

// Web (non-API) paths. Everything here is GET/HEAD only.
var (
	// Any single-segment root file with an asset extension. This covers
	// Immich's web/static (favicons, skeletons, manifest), custom.css, and
	// files browsers request on their own. Names Immich doesn't have get its
	// generic app page, which exposes nothing.
	reWebStatic = regexp.MustCompile(`^/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}\.(png|ico|svg|json|css|txt|webmanifest)$`)
	reWebApp    = regexp.MustCompile(`^/_app/[A-Za-z0-9_.~/-]+$`)
	// SvelteKit route share/[key]/[[photos=photos]]/[[assetId=id]]
	uuidRe     = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`
	reWebShare = regexp.MustCompile(`^/share/[A-Za-z0-9_-]{16,128}(/photos)?(/` + uuidRe + `)?/?$`)
	reWebSlug  = regexp.MustCompile(`^/s/[A-Za-z0-9_.~-]{1,128}(/photos)?(/` + uuidRe + `)?/?$`)
)

func webPathAllowed(path string, allowSlugs bool) bool {
	switch {
	case reWebStatic.MatchString(path), reWebApp.MatchString(path), reWebShare.MatchString(path):
		return true
	case allowSlugs && reWebSlug.MatchString(path):
		return true
	}
	return false
}
