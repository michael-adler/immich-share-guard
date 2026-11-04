// The drift check compares the allowlist with Immich's OpenAPI spec, which
// Immich serves at /api/spec.json. Routes that accept share keys are exactly
// the ones whose spec lists a "key" query parameter (verified against
// SHARED_LINK_ROUTES in Immich 3.3.5). The check reports:
//
//   - share-capable routes that are neither allowed nor in excludedShareRoutes
//   - allowed routes that are gone, no longer public, or no longer share-capable
//   - query, header, and body parameters with no allow or deny decision
//   - allow and deny decisions for parameters the spec no longer has
//   - changes in the request side of allowlisted routes since the reviewed
//     spec (see shape.go)
//
// The Immich version isn't compared: the spec's version is just the release
// number, so a release that leaves the share API unchanged passes.
//
// The proxy keeps failing closed either way. The report says what to review.

package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

const driftMsg = "possible Immich API change"

type driftIssue struct {
	Route, Kind, Detail string
}

func (d driftIssue) String() string {
	if d.Route == "" {
		return d.Kind + ": " + d.Detail
	}
	return d.Route + ": " + d.Kind + ": " + d.Detail
}

// specInfo is what the proxy keeps from the upstream spec, to classify
// blocked requests at runtime.
type specInfo struct {
	version string
	// Share-capable routes not in the allowlist, matching any path values.
	shareRoutes []*route
}

type specDoc struct {
	Info struct {
		Version string `json:"version"`
	} `json:"info"`
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Components struct {
		Schemas map[string]specSchema `json:"schemas"`
	} `json:"components"`

	schemas map[string]any // components.schemas, undecoded
}

type specOp struct {
	Parameters []struct {
		Name string `json:"name"`
		In   string `json:"in"`
	} `json:"parameters"`
	RequestBody *struct {
		Content map[string]struct {
			Schema specSchema `json:"schema"`
		} `json:"content"`
	} `json:"requestBody"`
	Security []json.RawMessage `json:"security"`

	raw map[string]any
}

type specSchema struct {
	Ref        string                     `json:"$ref"`
	Properties map[string]json.RawMessage `json:"properties"`
}

func (op *specOp) params(in string) map[string]bool {
	out := map[string]bool{}
	for _, p := range op.Parameters {
		if p.In == in {
			if in == "header" {
				out[http.CanonicalHeaderKey(p.Name)] = true
			} else {
				out[p.Name] = true
			}
		}
	}
	return out
}

func (op *specOp) shareCapable() bool { return op.params("query")["key"] }

var specMethods = []string{"get", "put", "post", "delete", "patch", "head", "options"}

func parseSpec(raw []byte) (*specDoc, map[string]*specOp, error) {
	var doc specDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("parsing spec: %w", err)
	}
	if len(doc.Paths) == 0 {
		return nil, nil, errors.New("spec has no paths")
	}
	var comps struct {
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &comps); err != nil {
		return nil, nil, fmt.Errorf("parsing spec: %w", err)
	}
	doc.schemas = comps.Components.Schemas
	ops := map[string]*specOp{}
	for path, item := range doc.Paths {
		for _, m := range specMethods {
			rawOp, ok := item[m]
			if !ok {
				continue
			}
			var op specOp
			if err := json.Unmarshal(rawOp, &op); err != nil {
				return nil, nil, fmt.Errorf("parsing %s %s: %w", strings.ToUpper(m), path, err)
			}
			if err := json.Unmarshal(rawOp, &op.raw); err != nil {
				return nil, nil, fmt.Errorf("parsing %s %s: %w", strings.ToUpper(m), path, err)
			}
			ops[strings.ToUpper(m)+" "+path] = &op
		}
	}
	return &doc, ops, nil
}

// bodyFields returns the top-level JSON properties of an operation's request
// body, or nil if it documents no JSON body.
func (doc *specDoc) bodyFields(op *specOp) map[string]bool {
	if op.RequestBody == nil {
		return nil
	}
	c, ok := op.RequestBody.Content["application/json"]
	if !ok {
		return nil
	}
	s := c.Schema
	if s.Ref != "" {
		s = doc.Components.Schemas[strings.TrimPrefix(s.Ref, "#/components/schemas/")]
	}
	out := map[string]bool{}
	for k := range s.Properties {
		out[k] = true
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// analyzeSpec compares routes with an OpenAPI spec.
func analyzeSpec(raw []byte, routes []*route) (*specInfo, []driftIssue, error) {
	doc, ops, err := parseSpec(raw)
	if err != nil {
		return nil, nil, err
	}
	var issues []driftIssue
	add := func(route, kind, format string, args ...any) {
		issues = append(issues, driftIssue{route, kind, fmt.Sprintf(format, args...)})
	}

	table := map[string]*route{}
	for _, rt := range routes {
		table[rt.id()] = rt
	}

	info := &specInfo{version: doc.Info.Version}
	for _, id := range sortedKeys(ops) {
		if !ops[id].shareCapable() {
			continue
		}
		if _, ok := table[id]; ok {
			continue
		}
		method, path, _ := strings.Cut(id, " ")
		info.shareRoutes = append(info.shareRoutes,
			(&route{method: method, pattern: strings.TrimPrefix(path, "/")}).compile(true))
		if _, ok := excludedShareRoutes[id]; !ok {
			add(id, "new share route", "Immich accepts share keys here, but the allowlist doesn't. "+
				"Add it to buildRoutes or to excludedShareRoutes.")
		}
	}

	for _, rt := range routes {
		id := rt.id()
		op, ok := ops[id]
		if !ok {
			add(id, "route removed", "the allowlist has it, but the spec doesn't")
			continue
		}
		switch {
		case rt.public && len(op.Security) > 0:
			add(id, "no longer public", "the spec now requires authentication")
		case !rt.public && !op.shareCapable():
			add(id, "no longer accepts share keys", "the spec has no key parameter")
		}
		compareShape(rt, doc.shape(op), add)

		query := op.params("query")
		for _, name := range sortedKeys(query) {
			if name == "key" || name == "slug" {
				continue
			}
			if _, ok := rt.query[name]; ok {
				continue
			}
			if _, ok := rt.deny[name]; ok {
				continue
			}
			add(id, "unreviewed query parameter", "%q: allow it with a validator or deny it with a reason", name)
		}
		for _, name := range sortedKeys(rt.query) {
			if !query[name] && undocumentedQuery[name] == "" {
				add(id, "allowed query parameter not in spec", "%q", name)
			}
		}
		for _, name := range sortedKeys(rt.deny) {
			if !query[name] {
				add(id, "denied query parameter not in spec", "%q", name)
			}
		}

		headers := op.params("header")
		for _, name := range sortedKeys(headers) {
			if _, ok := rt.headers[name]; !ok {
				add(id, "unreviewed header parameter", "%q", name)
			}
		}
		for _, name := range sortedKeys(rt.headers) {
			if !headers[name] {
				add(id, "allowed header not in spec", "%q", name)
			}
		}

		if rt.bodySpec != nil {
			fields := doc.bodyFields(op)
			if fields == nil {
				add(id, "body no longer documented", "the spec has no JSON request body")
				continue
			}
			for _, name := range sortedKeys(fields) {
				if rt.bodySpec.check(name) != nil {
					if _, denied := rt.bodySpec.deny[name]; !denied {
						add(id, "unreviewed body field", "%q: add it to the body struct or deny it with a reason", name)
					}
				}
			}
			for _, name := range rt.bodySpec.allowed {
				if !fields[name] {
					add(id, "allowed body field not in spec", "%q", name)
				}
			}
			for _, name := range sortedKeys(rt.bodySpec.deny) {
				if !fields[name] {
					add(id, "denied body field not in spec", "%q", name)
				}
			}
		}
	}
	return info, issues, nil
}

// WatchSpec runs the drift check against the upstream spec until ctx is
// done. Fetch failures are retried with exponential backoff, since Immich may
// be starting or restarting. After a success the spec is fetched again every
// SpecInterval (0 disables this), so an Immich upgrade made while the proxy
// keeps running is noticed. The report is logged only when the spec differs
// from the last one checked.
func (p *Proxy) WatchSpec(ctx context.Context) {
	u := *p.cfg.Upstream
	u.Path = "/api/spec.json"
	client := &http.Client{Transport: p.transport, Timeout: 30 * time.Second}

	var last [sha256.Size]byte
	checked := false
	retry := p.specRetryMin
	for {
		wait := retry
		err := func() error {
			raw, err := fetchSpec(ctx, client, u.String())
			if err != nil {
				return fmt.Errorf("can't fetch upstream spec: %w", err)
			}
			sum := sha256.Sum256(raw)
			if checked && sum == last {
				p.log.Debug("upstream spec unchanged")
				return nil
			}
			info, issues, err := analyzeSpec(raw, p.routes)
			if err != nil {
				return err
			}
			if checked {
				p.log.Info("upstream spec changed, checking again", "immich_version", info.version)
			}
			last, checked = sum, true
			p.spec.Store(info)
			p.reportDrift(info, issues)
			return nil
		}()
		switch {
		case err == nil:
			retry = p.specRetryMin
			if p.cfg.SpecInterval <= 0 {
				return
			}
			wait = p.cfg.SpecInterval
		case ctx.Err() != nil:
			return
		default:
			p.log.Warn("drift check failed", "url", u.Redacted(), "err", err, "retry_in", wait)
			retry = min(retry*2, p.specRetryMax)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

func (p *Proxy) reportDrift(info *specInfo, issues []driftIssue) {
	for _, i := range issues {
		p.log.Warn(driftMsg, "route", i.Route, "kind", i.Kind, "detail", i.Detail)
	}
	if len(issues) == 0 {
		p.log.Info("drift check passed", "immich_version", info.version, "reviewed_version", reviewed.Version)
	} else {
		p.log.Warn("drift check found differences", "count", len(issues),
			"immich_version", info.version, "reviewed_version", reviewed.Version)
	}
}

func fetchSpec(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// CheckSpec runs the drift check against a spec file's contents, for
// reviewing an Immich upgrade before deploying it. It writes the report to w
// and reports whether there was no drift.
func CheckSpec(w io.Writer, raw []byte, cfg Config) (bool, error) {
	info, issues, err := analyzeSpec(raw, buildRoutes(cfg))
	if err != nil {
		return false, err
	}
	for _, i := range issues {
		fmt.Fprintln(w, i)
	}
	if len(issues) > 0 {
		fmt.Fprintf(w, "%d differences from the allowlist (spec is Immich %s, reviewed against %s)\n",
			len(issues), info.version, reviewed.Version)
		return false, nil
	}
	fmt.Fprintf(w, "no drift (spec is Immich %s, reviewed against %s)\n", info.version, reviewed.Version)
	return true, nil
}
