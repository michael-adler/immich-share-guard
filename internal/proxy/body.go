// Validation and re-encoding of the request bodies the share page sends
// (share password login and download requests). A body is decoded with
// exact field names and encoded again, so Immich only parses what the proxy
// produced.

package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const maxAssetIDs = 100_000

// bodyPolicy records the decision for every field of a request body: allowed
// fields come from the canonical struct, denied fields carry a reason. The
// drift check compares both against Immich's spec.
type bodyPolicy struct {
	allowed []string
	deny    map[string]string
}

// fieldError reports a body field that isn't allowed. An empty reason means
// the field is unknown, which suggests an Immich API change.
type fieldError struct {
	field, reason string
}

func (e *fieldError) Error() string {
	if e.reason == "" {
		return "unknown field " + strconv.Quote(truncate(e.field, 40))
	}
	return "field " + strconv.Quote(e.field) + " not allowed: " + e.reason
}

func (p *bodyPolicy) check(field string) error {
	for _, a := range p.allowed {
		if field == a {
			return nil
		}
	}
	return &fieldError{field: field, reason: p.deny[field]}
}

// jsonFields returns the JSON field names of a struct.
func jsonFields(v any) []string {
	t := reflect.TypeOf(v)
	var names []string
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			names = append(names, name)
		}
	}
	return names
}

// Canonical request bodies. Field names must match Immich's DTOs exactly.

type loginBody struct {
	Password *string `json:"password"`
}

type downloadInfoBody struct {
	AlbumID     *string  `json:"albumId,omitempty"`
	AssetIDs    []string `json:"assetIds,omitempty"`
	ArchiveSize *int64   `json:"archiveSize,omitempty"`
}

type downloadArchiveBody struct {
	AssetIDs    []string `json:"assetIds"`
	ArchiveName *string  `json:"archiveName,omitempty"`
	Edited      *bool    `json:"edited,omitempty"`
}

var (
	loginPolicy        = bodyPolicy{allowed: jsonFields(loginBody{})}
	downloadInfoPolicy = bodyPolicy{
		allowed: jsonFields(downloadInfoBody{}),
		deny:    map[string]string{"userId": "share keys can't download other users' assets"},
	}
	downloadArchivePolicy = bodyPolicy{allowed: jsonFields(downloadArchiveBody{})}
)

func mediaType(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	return mt
}

// decodeChecked decodes a JSON object into v. Every top-level field name must
// pass the policy exactly (Go's own decoding would match names
// case-insensitively), and there must be no trailing data.
func decodeChecked(raw []byte, policy *bodyPolicy, v any) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return errors.New("body must be a JSON object")
	}
	keys := make([]string, 0, len(top))
	for k := range top {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := policy.check(k); err != nil {
			return err
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func checkUUIDs(ids []string) error {
	if len(ids) > maxAssetIDs {
		return fmt.Errorf("too many asset IDs (%d)", len(ids))
	}
	for _, id := range ids {
		if !vUUID(id) {
			return fmt.Errorf("invalid asset ID %q", truncate(id, 40))
		}
	}
	return nil
}

func requireJSON(contentType string) error {
	if mediaType(contentType) != "application/json" {
		return fmt.Errorf("content type %q, want application/json", contentType)
	}
	return nil
}

// POST shared-links/login
func canonLogin(raw []byte, contentType string) ([]byte, string, error) {
	if err := requireJSON(contentType); err != nil {
		return nil, "", err
	}
	var b loginBody
	if err := decodeChecked(raw, &loginPolicy, &b); err != nil {
		return nil, "", err
	}
	if b.Password == nil || *b.Password == "" || len(*b.Password) > 1024 {
		return nil, "", errors.New("password missing or too long")
	}
	out, err := json.Marshal(b)
	return out, "application/json", err
}

// POST download/info
func canonDownloadInfo(raw []byte, contentType string) ([]byte, string, error) {
	if err := requireJSON(contentType); err != nil {
		return nil, "", err
	}
	var b downloadInfoBody
	if err := decodeChecked(raw, &downloadInfoPolicy, &b); err != nil {
		return nil, "", err
	}
	if b.AlbumID == nil && len(b.AssetIDs) == 0 {
		return nil, "", errors.New("need albumId or assetIds")
	}
	if b.AlbumID != nil && !vUUID(*b.AlbumID) {
		return nil, "", errors.New("invalid albumId")
	}
	if err := checkUUIDs(b.AssetIDs); err != nil {
		return nil, "", err
	}
	if b.ArchiveSize != nil && *b.ArchiveSize < 1 {
		return nil, "", errors.New("invalid archiveSize")
	}
	out, err := json.Marshal(b)
	return out, "application/json", err
}

func checkArchiveName(name string) error {
	if len(name) > 512 {
		return errors.New("archiveName too long")
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == '/' || r == '\\' {
			return errors.New("invalid character in archiveName")
		}
	}
	return nil
}

// POST download/archive. The web UI submits an HTML form
// (assetIds=<comma-separated>, archiveName, edited). Immich also accepts
// JSON, which is what its spec documents. The body is re-encoded in the
// format it arrived in.
func canonDownloadArchive(raw []byte, contentType string) ([]byte, string, error) {
	switch mediaType(contentType) {
	case "application/x-www-form-urlencoded":
		vals, err := url.ParseQuery(string(raw))
		if err != nil {
			return nil, "", err
		}
		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := url.Values{}
		for _, k := range keys {
			v := vals[k]
			if err := downloadArchivePolicy.check(k); err != nil {
				return nil, "", err
			}
			if len(v) != 1 {
				return nil, "", fmt.Errorf("repeated form field %q", k)
			}
			switch k {
			case "assetIds":
				ids := strings.Split(v[0], ",")
				if err := checkUUIDs(ids); err != nil {
					return nil, "", err
				}
				out.Set(k, strings.Join(ids, ","))
			case "archiveName":
				if err := checkArchiveName(v[0]); err != nil {
					return nil, "", err
				}
				out.Set(k, v[0])
			case "edited":
				if !vBool(v[0]) {
					return nil, "", errors.New("invalid edited")
				}
				out.Set(k, v[0])
			default:
				// A field added to downloadArchiveBody without form handling.
				return nil, "", &fieldError{field: k}
			}
		}
		if out.Get("assetIds") == "" {
			return nil, "", errors.New("assetIds missing")
		}
		return []byte(out.Encode()), "application/x-www-form-urlencoded", nil

	case "application/json":
		var b downloadArchiveBody
		if err := decodeChecked(raw, &downloadArchivePolicy, &b); err != nil {
			return nil, "", err
		}
		if len(b.AssetIDs) == 0 {
			return nil, "", errors.New("assetIds missing")
		}
		if err := checkUUIDs(b.AssetIDs); err != nil {
			return nil, "", err
		}
		if b.ArchiveName != nil {
			if err := checkArchiveName(*b.ArchiveName); err != nil {
				return nil, "", err
			}
		}
		out, err := json.Marshal(b)
		return out, "application/json", err
	}
	return nil, "", fmt.Errorf("unsupported content type %q", contentType)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
