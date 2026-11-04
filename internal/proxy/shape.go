// Request shapes for the drift check. reviewed-api.json records the request
// side of every allowlisted route as of the last reviewed Immich spec: the
// schema of each parameter and body field (with $refs resolved) and the
// route's permission. Comparing the upstream spec with it reports a change
// in a parameter's type, format, enum values or required flag even when no
// name changed. Descriptions and history annotations are ignored.
//
// Regenerate it from the fixture with:
//
//	go test ./internal/proxy -run TestReviewedAPI -update

package proxy

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// reviewedJSON is reviewed-api.json, built into the binary.
//
//go:embed reviewed-api.json
var reviewedJSON []byte

type apiShape struct {
	Version string                    `json:"version"`
	Routes  map[string]map[string]any `json:"routes"`
}

var reviewed = func() *apiShape {
	var s apiShape
	if err := json.Unmarshal(reviewedJSON, &s); err != nil {
		panic("reviewed-api.json: " + err.Error())
	}
	return &s
}()

// Schema keys that don't affect which requests Immich accepts.
var ignoredSchemaKeys = map[string]bool{
	"description": true, "summary": true, "title": true, "example": true,
	"examples": true, "deprecated": true, "x-immich-history": true, "x-immich-state": true,
}

// canon returns a schema with $refs resolved, ignored keys removed, and
// enum and required lists sorted. A recursive $ref is left as a reference.
func (doc *specDoc) canon(v any, stack []string) any {
	switch x := v.(type) {
	case map[string]any:
		if ref, ok := x["$ref"].(string); ok {
			name := strings.TrimPrefix(ref, "#/components/schemas/")
			for _, s := range stack {
				if s == name {
					return map[string]any{"$ref": name}
				}
			}
			target, ok := doc.schemas[name]
			if !ok {
				return map[string]any{"$ref": name, "missing": true}
			}
			return doc.canon(target, append(stack, name))
		}
		out := map[string]any{}
		for k, val := range x {
			switch {
			case ignoredSchemaKeys[k]:
			case k == "properties":
				props := map[string]any{}
				if m, ok := val.(map[string]any); ok {
					for name, p := range m {
						props[name] = doc.canon(p, stack)
					}
				}
				out[k] = props
			case k == "enum" || k == "required":
				out[k] = sortedList(doc.canon(val, stack))
			default:
				out[k] = doc.canon(val, stack)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = doc.canon(e, stack)
		}
		return out
	default:
		return v
	}
}

func sortedList(v any) any {
	list, ok := v.([]any)
	if !ok {
		return v
	}
	out := append([]any(nil), list...)
	sort.SliceStable(out, func(i, j int) bool { return fmt.Sprint(out[i]) < fmt.Sprint(out[j]) })
	return out
}

// shape returns the request side of one operation, keyed by element:
// "permission", "<in> <name>" for parameters, and for each body content
// type "body <type> field <name>", "body <type> required" and "body <type>"
// (the rest of the schema).
func (doc *specDoc) shape(op *specOp) map[string]any {
	out := map[string]any{}
	if perm, ok := op.raw["x-immich-permission"]; ok {
		out["permission"] = perm
	}
	params, _ := op.raw["parameters"].([]any)
	for _, p := range params {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		in, _ := m["in"].(string)
		if in == "header" {
			name = http.CanonicalHeaderKey(name)
		}
		req, _ := m["required"].(bool)
		out[in+" "+name] = map[string]any{"required": req, "schema": doc.canon(m["schema"], nil)}
	}
	body, _ := op.raw["requestBody"].(map[string]any)
	if req, ok := body["required"]; ok {
		out["body required"] = req
	}
	content, _ := body["content"].(map[string]any)
	for ct, c := range content {
		cm, _ := c.(map[string]any)
		s, ok := doc.canon(cm["schema"], nil).(map[string]any)
		if !ok {
			out["body "+ct] = cm["schema"]
			continue
		}
		props, _ := s["properties"].(map[string]any)
		for name, p := range props {
			out["body "+ct+" field "+name] = p
		}
		if req, ok := s["required"]; ok {
			out["body "+ct+" required"] = req
		}
		rest := map[string]any{}
		for k, v := range s {
			if k != "properties" && k != "required" {
				rest[k] = v
			}
		}
		if len(rest) > 0 {
			out["body "+ct] = rest
		}
	}
	return out
}

// buildShape records the shape of the allowlisted routes in a spec.
func buildShape(raw []byte, routes []*route) (*apiShape, error) {
	doc, ops, err := parseSpec(raw)
	if err != nil {
		return nil, err
	}
	s := &apiShape{Version: doc.Info.Version, Routes: map[string]map[string]any{}}
	for _, rt := range routes {
		if op, ok := ops[rt.id()]; ok {
			s.Routes[rt.id()] = doc.shape(op)
		}
	}
	return s, nil
}

// compareShape reports differences between a route's shape in the upstream
// spec and the reviewed one. Parameters and JSON body fields that were added
// or removed are left out where the name checks in analyzeSpec report them.
func compareShape(rt *route, got map[string]any, add func(route, kind, format string, args ...any)) {
	id := rt.id()
	want, ok := reviewed.Routes[id]
	if !ok {
		add(id, "not reviewed", "the route isn't in reviewed-api.json")
		return
	}
	named := func(key string) bool {
		return strings.HasPrefix(key, "query ") || strings.HasPrefix(key, "header ") ||
			rt.bodySpec != nil && strings.HasPrefix(key, "body application/json field ")
	}
	for _, key := range sortedKeys(union(got, want)) {
		g, inGot := got[key]
		w, inWant := want[key]
		switch {
		case inGot && inWant:
			gj, wj := canonJSON(g), canonJSON(w)
			if !bytes.Equal(gj, wj) {
				add(id, "request schema changed", "%s: reviewed %s, now %s", key, truncate(string(wj), 200), truncate(string(gj), 200))
			}
		case named(key):
		case inGot:
			add(id, "request schema changed", "%s: added %s", key, truncate(string(canonJSON(g)), 200))
		default:
			add(id, "request schema changed", "%s: removed", key)
		}
	}
}

func union(a, b map[string]any) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

// canonJSON encodes v with sorted map keys and numbers as decoded.
func canonJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimSpace(buf.Bytes())
}
