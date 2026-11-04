# internal/proxy

The proxy itself. `cmd/immich-share-guard` reads the settings, builds a
`Config` and calls `New`.

| Path | Contents |
|---|---|
| `config.go` | `Config` and its defaults |
| `proxy.go` | Request handling, credential stripping, response rewriting |
| `routes.go` | The allowlist: routes, parameters and validators |
| `body.go` | Request body validation and re-encoding |
| `sharecheck.go` | Share key and password check |
| `scrub.go` | Removal of server paths from JSON responses |
| `ratelimit.go` | Per-IP failure limit |
| `drift.go` | Drift check of the allowlist against Immich's OpenAPI spec |
| `shape.go` | Request shapes for the drift check |
| `reviewed-api.json` | Reviewed request shapes, built into the binary |
| `testdata/` | The reviewed Immich spec |
| `proxy_test.go` | Tests of request handling |
| `drift_test.go` | Tests of the drift check and reviewed shapes |
| `helpers_test.go` | Shared test helpers: a fake Immich upstream and test proxies |
