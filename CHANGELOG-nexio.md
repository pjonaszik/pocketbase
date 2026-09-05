# Nexio Labs fork changelog

Maintained fork of PocketBase. Upstream disabled non-collaborator PRs and does
not accept these reports, so the fixes below live here. Each fix was written
test-first (failing test seen red before the fix) and the full `go test ./...`
suite is green on `master`.

Base: upstream `develop` (post v0.40.2). Go 1.27.

## v0.40.2-nexio.1 (2026-09-05)

### Correctness
- **search:** clamp the `geoDistance()` `acos()` argument to [-1, 1] so the
  distance of a point to itself is `0`, not SQL `NULL`. Previously an exact
  "within N km" match silently dropped out at ~3.8% of latitudes.
- **router:** run the `?fields` picker before writing the status header, so a
  malformed `fields` value returns a JSON error instead of HTTP 200 with an
  empty body.
- **dbutils:** parse partial-index `WHERE` clauses that contain parentheses
  (`col IN (...)`, `length(col) > 0`, `(a = 1)`); the greedy regex used to
  reject them and break the `Build`/`ParseIndex` round trip.
- **dbutils:** keep multi-line index column expressions intact; the `(?im)`
  flag truncated `a || b || c` to `a || b` and wrapped `json_extract(...)` to
  invalid DDL.
- **core:** reject `json` field values with duplicate object keys, which the
  jsonv1 validator accepted but the jsonv2 response writer cannot emit,
  permanently breaking the collection's list/view endpoints.
- **core:** reload each referencing record during a cascade delete, fixing a
  self-referential multi-value relation that left a dangling reference and
  skipped a cascade due to a stale in-memory batch snapshot.
- **auth:** OIDC returns an "empty id_token" error instead of panicking on an
  unchecked type assertion when the token response has no `id_token`.
- **jsvm:** `$http.send` throws on a response-body read error instead of
  returning a truncated body as a successful HTTP 200.
- **migratecmd:** stop corrupting collection data that contains a literal
  backslash-u sequence (a redundant jsonv1-era unescape pass).
- **apis:** use an ASCII hyphen in the `X-Forwarded-For` proxy-header hint,
  which never matched a real header because of a Unicode non-breaking hyphen.
- **filesystem:** match the `Serve` content-type override case-insensitively so
  uppercase extensions (`.CSS`, `.JS`) are served with the correct type.

### Robustness / availability
- **apis:** enforce `BodyLimit` on streaming (chunked / no Content-Length)
  requests; the sentinel was swallowed by the jsonv2 decoder, letting an
  oversized body be buffered entirely (memory DoS).
- **cron:** fix a `Stop()` deadlock (blocking send under the write lock) and a
  ticker leak when `Stop()` runs during `Start()`'s startup-delay window; also
  removes an unsynchronized `c.ticker` read (data race under `-race`).
- **security:** return an error instead of panicking on a base64 cipher text
  shorter than the GCM nonce.
- **core:** revert `pb_data` when the restore's second dir-swap fails after the
  first succeeded, per the documented contract (avoids data loss).

## JavaScript SDK (pjonaszik/js-sdk)
- **filter:** `pb.filter()` no longer corrupts param values containing `$&`,
  `` $` ``, `$'` or `$$` (they were treated as `replaceAll` substitution
  patterns). Fixed with the callback form of `replaceAll`.
