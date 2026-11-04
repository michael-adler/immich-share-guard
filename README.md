# Immich Share Guard

A small reverse proxy that exposes [Immich](https://immich.app/) shared links to
the public using Immich's own web UI, while keeping the rest of Immich unreachable.

It holds no API key and no state. A visitor's share key is the only
credential, and Immich already restricts share-key requests to a small set of
routes.

Putting Immich directly on the internet exposes its login page and its whole API
to anyone who finds it. A sharing proxy lets strangers open shared links without
reaching the rest of the server. There are multiple ways to structure a proxy.
Another project,
[Immich Public Proxy](https://github.com/alangrainger/immich-public-proxy),
renders its own gallery pages and fetches only the shared photos and videos from
Immich, so visitors never talk to Immich or run its web code. The cost is that
visitors get that project's gallery instead of Immich's share page. Share Guard
takes another approach. It passes Immich's own web UI and a filtered set of its
API routes through to Immich, so visitors get the core Immich sharing features,
such as the timeline and map views. The trade-off is that more of Immich's code
faces the public, which the checks below are meant to contain.

The proxy narrows what reaches Immich:

- **API allowlist.** Only the routes the share page uses are forwarded.
  Every query parameter and body field Immich documents for those routes is
  either allowed with a validator or denied with a recorded reason. Path
  parameters must be UUIDs (or integers and segment names for HLS).
  Everything else under `/api` returns 404, including `auth/*`, `oauth/*`,
  `users/*`, `admin/*`, `search/*`, the spec, and the websocket.
- **Share auth required.** Every non-public API route needs a `key` query
  parameter (or `slug`, with `SHARE_GUARD_ALLOW_SLUGS`).
- **Share passwords enforced on every route.** Immich (3.3.5) checks a
  share's password only in `GET shared-links/me`. Every other shared-link
  route accepts the bare key, so with the link and an album or asset ID,
  content is reachable without the password. Before forwarding any content
  request, the proxy asks Immich `GET shared-links/me` with the same key and
  share cookie and forwards only on 200. This also covers expired and deleted
  links. The key is checked without the cookie first, and with it only if
  that fails, so varying the cookie can't force extra checks on a share
  without a password. Successful checks are cached for
  `SHARE_GUARD_SHARE_CHECK_TTL` (default 1m), failures for at most 10s, and
  concurrent checks for the same key and cookie are merged into one.
- **Credentials stripped.** `Authorization`, `x-api-key`,
  `x-immich-user-token`, `x-immich-session-token`, the share-key headers, the
  `apiKey` and `sessionKey` query parameters, and every cookie except
  `immich_shared_link_token` are always removed, even in log-only mode. This
  matters because Immich falls back to session or API-key auth when no share
  key is present.
- **Canonical requests.** Query strings are re-encoded after validation.
  JSON and form bodies (`download/info`, `download/archive`,
  `shared-links/login`) are parsed with exact field names, and re-encoded, so
  Immich only parses input the proxy produced.
- **Response scrubbing.** In every JSON API response, `originalPath` (the
  server filesystem path) is reduced to its file name, and any other string
  field ending in `Path` is blanked. The web UI only uses `originalPath` for
  display and the file extension, and shows initials when
  `profileImagePath` is empty. Every `email` field is blanked too: Immich
  includes the email address (the Immich login) of each album user and
  asset owner, and the web UI only shows it in avatar tooltips. Every
  `password` field is blanked as well: after a visitor logs in,
  `shared-links/me` returns the share's password in plain text, and only the
  owner's shared-link pages use it.
  `Set-Cookie` is limited to `immich_shared_link_token`.
- **Web allowlist.** GET/HEAD only: `/share/<key>[/photos][/<assetId>]`,
  `/_app/*`, and single-segment root files with asset extensions (`png`,
  `ico`, `svg`, `json`, `css`, `txt`, `webmanifest`), which covers Immich's
  static files and files browsers request on their own. Names Immich doesn't
  have get its generic app page.
- **Rate limiting.** Each client IP (IPv6: each /64) is blocked for the rest
  of a window after too many failures: API rejections by the proxy, upstream
  400/401/403 on API routes, and Immich's 404 for an invalid key or slug on a
  share page (`/share/<key>`, `/s/<slug>`). This slows guessing of keys,
  slugs, IDs, and share passwords. Web paths the proxy rejects don't count,
  since browsers routinely probe for files that don't exist.

Allowed API routes (Immich 3.3.5):

```
GET  server/config, server/features, server/media-types (public)
GET  shared-links/me                POST shared-links/login
GET  albums/:id                     GET  albums/:id/map-markers
GET  timeline/buckets               GET  timeline/bucket      (albumId required)
GET  assets/:id                     GET  assets/:id/thumbnail (size: thumbnail|preview|fullsize)
GET  assets/:id/original            GET  assets/:id/video/playback
GET  assets/:id/video/stream/...    DELETE assets/:id/video/stream/:sessionId
POST download/info                  POST download/archive
POST assets                                                 (ALLOW_UPLOAD only)
```

The full table, with parameter decisions, is `buildRoutes` in [`routes.go`](internal/proxy/routes.go).
Shared-link routes deliberately left out are in `excludedShareRoutes`.

## Install with Docker

There is no published image yet, so Docker builds one from this repository.
[`docker-compose.yml`](docker-compose.yml) runs the proxy on the host's
network, alongside Immich and the TLS front end.

1. Clone the repository:

   ```
   git clone https://github.com/michael-adler/immich-share-guard.git
   cd immich-share-guard
   ```

2. Copy the settings file and edit it:

   ```
   cp examples/immich-share-guard.env .env
   ```

   The defaults fit a single host: Immich at `http://127.0.0.1:2283`, the port
   Immich's own compose file publishes, the proxy listening on
   `127.0.0.1:2284`, and a front end on the same host as the only trusted
   proxy. If Immich or the front end is elsewhere, change
   `SHARE_GUARD_UPSTREAM`, `SHARE_GUARD_LISTEN`, and
   `SHARE_GUARD_TRUSTED_PROXIES`. See [Configuration](#configuration).

3. Build and start the container, then check its log for errors:

   ```
   docker compose up -d --build
   docker compose logs
   ```

4. Point the front end at `127.0.0.1:2284`, serving it over HTTPS at the
   public name. See [Deployment](#deployment) and the Apache and Caddy
   examples.

5. Set Immich's **Administration > Settings > Server > External domain** to
   the public URL, for example `https://photos.example.com`, so the share
   links Immich generates point at the proxy.

To update, pull the repository and run `docker compose up -d --build` again.

## Build and run

Without Docker, build from a clone of the repository with Go 1.24 or later:

```
go build ./cmd/immich-share-guard
cp examples/immich-share-guard.env .env      # then edit
./immich-share-guard
```

Or install the binary into `$(go env GOPATH)/bin` without cloning:

```
go install github.com/michael-adler/immich-share-guard/cmd/immich-share-guard@latest
```

Then copy
[`examples/immich-share-guard.env`](examples/immich-share-guard.env) to the
directory you run it from as `.env`, or name the file with `-env`.

### Configuration

Settings are read from an env file in the format of Immich's `.env`:
`NAME=value` lines, `#` comments, optional quotes. By default the proxy reads
`.env` in the current directory if it exists. `-env FILE` names another file,
which must then exist. A variable set in the environment overrides the file,
so a one-off change doesn't need an edit:

```
SHARE_GUARD_MODE=log ./immich-share-guard -v
```

Unknown `SHARE_GUARD_*` names, in the file or the environment, are errors, so
a misspelled setting can't silently fall back to its default.
[`examples/immich-share-guard.env`](examples/immich-share-guard.env) lists
every setting. `-h` prints them with their defaults.

| Setting | Default | Meaning |
|---|---|---|
| `SHARE_GUARD_UPSTREAM` | (required) | Internal Immich URL |
| `SHARE_GUARD_LISTEN` | `127.0.0.1:2284` | Listen address |
| `SHARE_GUARD_MODE` | `enforce` | `log` forwards disallowed requests and logs them as `would block` |
| `SHARE_GUARD_ALLOW_SLUGS` | `false` | Allow custom-URL shares (`/s/<slug>`). Slugs are guessable. |
| `SHARE_GUARD_ALLOW_UPLOAD` | `false` | Allow uploads to shares that permit them. Upload bodies are streamed unvalidated. |
| `SHARE_GUARD_TRUSTED_PROXIES` | `127.0.0.1/32,::1/128` | Sources whose `X-Forwarded-*` headers are trusted |
| `SHARE_GUARD_FAIL_LIMIT` / `_FAIL_WINDOW` | `30` / `10m` | API failures per IP per window before blocking (0 disables) |
| `SHARE_GUARD_SHARE_CHECK_TTL` | `1m` | How long a successful share check is cached (0 checks every request) |
| `SHARE_GUARD_MAX_BODY` | 8 MiB | Largest validated request body, in bytes |
| `SHARE_GUARD_MAX_SCRUB_BODY` | 64 MiB | Largest JSON response that is rewritten, in bytes |
| `SHARE_GUARD_SPEC_INTERVAL` | `15m` | How often to fetch the Immich spec again to detect an upgrade (0 checks only at startup) |

Command-line flags:

| Flag | Meaning |
|---|---|
| `-v` | Log every request |
| `-env FILE` | Settings file (default `.env`, if present) |
| `-check-spec FILE` | Compare the allowlist with an Immich OpenAPI spec file, print the differences, and exit (status 1 if any). Reads the settings, but doesn't need `SHARE_GUARD_UPSTREAM`. |

Share keys are shortened in logs (`key=AbCdEf...`), and slugs, share
passwords, and stripped credentials are replaced with `<redacted>`.

Use the internal HTTP address of Immich as the upstream, not a URL that goes
through another TLS proxy. Immich marks the share password cookie `Secure`
when it sees HTTPS, and the proxy passes on the scheme it received.

## Deployment

Terminate TLS in a web server and forward everything to the proxy over plain
HTTP. [`examples/apache-photos.conf`](examples/apache-photos.conf) and
[`examples/caddy-photos.caddyfile`](examples/caddy-photos.caddyfile) are
commented Apache and Caddy configurations for this. Whatever the front end, it
needs to:

- send `X-Forwarded-Proto: https`. Otherwise Immich treats clients as plain
  HTTP and sets the share-password cookie without the `Secure` flag. Apache's
  `mod_proxy` doesn't send it on its own. Caddy does.
- compress responses. The proxy sends JSON API responses uncompressed
  because it rewrites them.
- allow long pauses in large zip downloads (`ProxyTimeout` in Apache,
  `write_idle` in Caddy).

Run the proxy with the front end's address as the only trusted proxy:

```
SHARE_GUARD_UPSTREAM=http://127.0.0.1:2283
SHARE_GUARD_LISTEN=192.168.1.20:2284
SHARE_GUARD_TRUSTED_PROXIES=192.168.1.10
```

A service started at boot usually doesn't run in the directory holding
`.env`, so give the path: `immich-share-guard -env
/etc/immich-share-guard.env`.

The proxy takes the client address from the rightmost `X-Forwarded-For` hop
that isn't a trusted proxy. From `X-Forwarded-Proto` and `X-Forwarded-Host`
it takes only the last entry, the one the front end added, because some
front ends (Apache among them) append to a value the client sent. It ignores
those headers from anyone not in `SHARE_GUARD_TRUSTED_PROXIES`.

Only the front end should be able to reach the proxy's port, and the front
end should not be able to reach Immich directly.

Then set Immich's **Administration > Settings > Server > External domain** to
`https://photos.example.com`, so the share links Immich generates point at the
proxy. Immich itself should not be reachable from the internet except through
the proxy.

## Logs and Immich API changes

The proxy fails closed: anything it doesn't know is blocked. To make
breakage after an Immich upgrade easy to diagnose, every log line caused by a
likely API change contains `possible Immich API change`:

- **At startup and periodically**, the proxy fetches `/api/spec.json` from Immich and compares
  it with the allowlist. It reports share-capable routes that are neither
  allowed nor excluded, allowed routes that are gone or changed
  authentication, parameters and body fields with no allow or deny decision,
  decisions for parameters the spec no longer has, and any change to the
  request side of an allowlisted route since the reviewed spec: a
  parameter's or body field's type, format, enum values, limits or required
  flag, or the route's permission. The reviewed shapes are in
  `internal/proxy/reviewed-api.json`, which is built into the binary. The Immich version
  itself isn't compared, because the spec's version is just the release
  number. A release that leaves the share API unchanged passes, and the log
  shows both `immich_version` and `reviewed_version`. It ends with
  `drift check passed` or `drift check found differences`. If Immich
  can't be reached, the proxy logs `drift check failed` and retries with
  backoff (5 seconds, doubling to at most 5 minutes) until it succeeds.
  After that it fetches the spec again every `SHARE_GUARD_SPEC_INTERVAL`. When the spec
  has changed, as after an Immich upgrade, it logs
  `upstream spec changed, checking again` and the full report. An unchanged
  spec is only logged with `-v`.
- **At runtime**, blocked requests that a legitimate web UI would cause after
  an API change are logged at WARN with the same text: unknown query
  parameters or body fields on allowed routes, invalid values, missing
  required parameters, and requests to share-capable routes missing from the
  allowlist. Other blocks (denied parameters, unknown routes, bad keys) are
  logged at INFO as `blocked`, with the reason.

```
grep 'possible Immich API change' proxy.log
```

### Upgrading Immich

1. Before upgrading, check the new release's spec:
   ```
   curl -sLo new-spec.json https://raw.githubusercontent.com/immich-app/immich/<tag>/open-api/immich-openapi-specs.json
   ./immich-share-guard -check-spec new-spec.json
   ```
   The repository spec matches the one Immich serves in everything the check
   reads (verified for 3.3.5). If it prints `no drift`, the share API is
   unchanged and steps 2 and 3 are optional.
2. For each difference, update `buildRoutes`, the deny maps, the body structs
   in `internal/proxy/body.go`, or `excludedShareRoutes`. A new parameter needs a decision:
   allow it only if the share page sends it.
3. Replace `internal/proxy/testdata/immich-openapi-3.3.5.json` with the new spec (renamed),
   update `fixture` in `internal/proxy/drift_test.go`, then regenerate the
   reviewed shapes and rebuild:
   ```
   go test ./internal/proxy -run TestReviewedAPI -update
   go test ./...
   go build ./cmd/immich-share-guard
   ```
   The diff of `reviewed-api.json` shows every request-side change to the
   allowlisted routes. Check each against the validators in `internal/proxy/routes.go`.
4. After upgrading, run with `SHARE_GUARD_MODE=log` and `-v`, browse a few shares (photos,
   video, map, downloads, a password link), and check for `would block`.

The spec doesn't show which parameters the web UI sends, so step 4 is still
needed for those. Requests the UI makes outside the share page, such as
startup calls and static files, also only show up in step 4.

## Tests

```
go test -race ./...
```

`TestDriftFixtureClean` fails if the allowlist and the spec fixture
disagree, and `TestReviewedAPI` fails if `reviewed-api.json` doesn't match
the fixture.
