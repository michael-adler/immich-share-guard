// Removal of server filesystem paths, user email addresses, and share
// passwords from JSON documents, so share viewers don't learn the server's
// layout, its users' logins, or a share's password. It applies to every JSON
// API response, so fields added in future Immich versions are covered too.
//
//   - originalPath is reduced to its base name. The web UI displays it and
//     reads the file extension from it, so the base name keeps both working.
//   - Any other string field whose name ends in "Path" (for example
//     profileImagePath) is blanked. The UI treats an empty profileImagePath
//     as "no picture" and shows initials, which is right here because the
//     profile image route isn't served.
//   - Any string field named "email" is blanked. Immich includes the email
//     address of every album user and asset owner (the login name for
//     their Immich account). The web UI only shows it in avatar tooltips.
//   - Any string field named "password" is blanked. Immich returns a
//     shared link's password in plain text from shared-links/me once the
//     visitor has logged in, so anyone holding the share cookie could read
//     it. Only the owner's shared-link management pages read it.

package proxy

import (
	"bytes"
	"encoding/json"
	"path"
	"strings"
)

// scrubJSON applies the rules at the top of this file to raw.
func scrubJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	scrubValue(v)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func scrubValue(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if s, ok := val.(string); ok {
				switch {
				case k == "originalPath":
					t[k] = baseName(s)
				case strings.HasSuffix(k, "Path"), k == "email", k == "password":
					t[k] = ""
				}
				continue
			}
			scrubValue(val)
		}
	case []any:
		for _, e := range t {
			scrubValue(e)
		}
	}
}

func baseName(p string) string {
	if p == "" {
		return p
	}
	// Handle Windows-style paths from external libraries as well.
	return path.Base(strings.ReplaceAll(p, `\`, "/"))
}
