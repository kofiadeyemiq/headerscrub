# headerscrub

An `http.Client` CheckRedirect policy that stops caller-set headers from following a redirect to a different host.

```go
client := headerscrub.Client(&http.Client{})

req, _ := http.NewRequest(http.MethodGet, someURL, nil)
req.Header.Set("X-Api-Key", secret)

resp, err := client.Do(req)
// If someURL redirects to a different host, X-Api-Key does not go with it.
```

## Why

`net/http`'s default redirect handling copies every header the caller set on the original request onto each subsequent hop, forwarding it to whatever host a 3xx response points at. There is one carve-out: a fixed list of headers it considers sensitive — `Authorization`, `Www-Authenticate`, `Cookie`, `Cookie2`, `Proxy-Authorization`, `Proxy-Authenticate` — is dropped when the redirect target isn't the same domain or a subdomain of the original host (`shouldCopyHeaderOnRedirect` in `net/http/client.go`).

Everything else on the list is not: `X-Api-Key`, `X-Auth-Token`, a custom bearer scheme, an internal service token. If your code sets one of those and the response you're fetching (or forwarding on a user's behalf) redirects to a host you don't control, that header goes with it. This is the shape of bug that shows up in webhook delivery, link previews, outbound proxies, and any client that follows redirects on URLs it doesn't fully trust.

This isn't a hypothetical reading of the source — it reproduces on a current Go toolchain with two `httptest` servers reached via different hostnames on the same machine (see `TestLeakRepro` in `headerscrub_test.go`).

Headers are matched by their canonical form regardless of how they were set, including a header assigned directly on the `Header` map with a non-canonical key (`req.Header["x-api-key"] = ...` instead of `req.Header.Set(...)`, which is legal — `http.Header` is just a `map[string][]string`). An earlier version of this package used `Header.Del`, which canonicalizes its argument before deleting and so missed exactly that case; see `TestCheckRedirect_NonCanonicalKeyIsScrubbed`.

Incumbent checked: `net/http`'s own `CheckRedirect` carve-out, described above, which does not cover caller-set headers outside its fixed sensitive-header list.

Measured: `go run ./examples/leak-demo`

```
plain http.Client (no policy):
  X-Api-Key received by other host:    "super-secret"
  Authorization received by other host: ""  (stdlib already strips this one)

headerscrub.Client (policy installed):
  X-Api-Key received by other host:    ""
  Authorization received by other host: ""
```

Both requests set the same two headers. `Authorization` never reaches the second host either way — the standard library already handles that one. `X-Api-Key` reaches it in the first case and not in the second.

## Installation

```sh
go get github.com/__GH_OWNER__/headerscrub
```

Go 1.23+. No dependencies outside the standard library.

## Usage

### Wrap a client

```go
client := headerscrub.Client(&http.Client{})
```

`headerscrub.Client` returns a shallow copy of the `*http.Client` you pass in — the input is never modified — and automatically preserves any `CheckRedirect` function it already had, running it after the scrubbing logic.

### Install the policy directly

```go
client := &http.Client{
    CheckRedirect: headerscrub.CheckRedirect(),
}
```

### Allow specific headers across origins

```go
client := headerscrub.Client(&http.Client{}, headerscrub.Allow("Accept", "X-Request-Id"))
```

`Allow` replaces the default allowlist (`Accept`, `Accept-Language`, `User-Agent`); it is not additive, so list everything you want kept.

### Combine with an existing CheckRedirect

```go
client := headerscrub.Client(&http.Client{}, headerscrub.Wrap(existingCheckRedirect))
```

`Wrap` runs an existing `CheckRedirect` function after the scrubbing logic, so URL allowlists or logging keep working. See `TestWrap_DelegatesRedirectLimit`.

### Same origin, not same domain

The standard library's own carve-out treats `example.com` and `sub.example.com` as close enough to keep `Authorization`/`Cookie` flowing between them. This package does not extend that courtesy: it compares scheme, host and port exactly, so a redirect from `example.com` to `sub.example.com` is treated as cross-origin and scrubbed.

The stdlib's list is small and its headers have well-understood domain scope. This package strips arbitrary caller-set headers, which have no such convention, and a subdomain is not necessarily operated by the same party — subdomain takeover and multi-tenant hosting are both real. Matching the permissive rule here would leave a gap for exactly the redirect shapes this package exists to catch. If you do want specific headers to follow a known family of subdomains, list them with `Allow`.

### 307 and 308: the body goes too

A 307 or 308 redirect tells the client to repeat the request exactly, including its method and body — unlike 301/302/303, which `net/http` downgrades a `POST` to a `GET` and drops the body for. So a cross-origin 307/308 resends whatever body the original request had to the new host, same as `net/http` would do without this package installed.

`headerscrub` does not scrub or inspect that body — doing so is out of scope for a header-only policy, and if a body is going to leak on a 307 regardless, hiding that behind a false sense of security would be worse than being upfront about it. What it does do is keep `Content-Type`, `Content-Encoding`, `Content-Language` and `Content-Location` on a hop that still carries a body, in addition to whatever's in your allowlist — those headers describe the payload rather than the caller, and stripping them would leave the server holding a body it can't interpret while doing nothing for security. Every other header is still scrubbed as usual on a cross-origin body-preserving hop; see `TestCheckRedirect_307KeepsBodyAndContentType`.

If a redirect chain includes a 301/302/303 hop, `net/http` drops the body itself before this package's logic runs at all, and `Content-Type` is then treated like any other non-allowlisted header — scrubbed on a cross-origin hop, same as `X-Api-Key` — since there's no body left for it to describe; see `TestCheckRedirect_302DowngradesToGETNoBody`. If your request body might itself contain a secret, don't rely on this package to protect it on a 307/308 — that's a URL/redirect-policy decision, not a header-scrubbing one.

## Reference

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `Client(c *http.Client, opts ...Option) *http.Client` | function | — | Returns a shallow copy of `c` with the scrubbing `CheckRedirect` installed, preserving and chaining any existing `CheckRedirect`. |
| `CheckRedirect(opts ...Option) func(req *http.Request, via []*http.Request) error` | function | — | Returns the redirect policy function directly, for assigning to `http.Client.CheckRedirect` by hand. |
| `Allow(names ...string) Option` | option | `Accept`, `Accept-Language`, `User-Agent` | Replaces the allowlist of headers that survive a cross-origin hop. Not additive — list everything you want kept. |
| `Wrap(next func(req *http.Request, via []*http.Request) error) Option` | option | none | Runs an existing `CheckRedirect` function after the scrubbing logic, so URL allowlists or logging keep working. |

The returned policy enforces the standard library's default 10-redirect limit only when no `Wrap` is used. As soon as you wrap an existing `CheckRedirect`, the limit is delegated to it entirely — `headerscrub` doesn't second-guess it. This matters if you wrap a function that's meant to allow more than 10 hops: without delegating, this package's own cap would silently override it. If you wrap a function that doesn't enforce any limit of its own, redirects are unbounded (aside from whatever `net/http`'s connection handling eventually does), same as it would be if you'd passed that function to `http.Client.CheckRedirect` directly. See `TestWrap_DelegatesRedirectLimit`.

## How it works

The policy is installed as (or chained into) `http.Client.CheckRedirect`, which the standard library calls before following each redirect hop, with the original and all prior requests available via `via`. On each hop it compares the redirect target's scheme, host and port against the original request's; if they differ, it removes every header from the outgoing request except the configured allowlist and, when a body is still being carried (307/308), the content-description headers. Because `CheckRedirect` runs before `net/http` copies headers from `via[0]` onto the next request, the policy sees and controls the full header set for that hop.

## Limitations

- It only sees headers set on the original request. `CheckRedirect` runs before the request is sent, so a header a `Transport` injects inside `RoundTrip` — the pattern `golang.org/x/oauth2`'s `Transport` uses to add `Authorization` on every request — is added after this policy has already decided what to keep, and reaches every host regardless. `TestTransportInjectedHeaderSurvives` demonstrates this with a small custom `RoundTripper`; there's no way to fix it from `CheckRedirect`.
- A hop back to the original host restores its headers. Each hop is judged against the original request's host, not the previous hop. A redirect A → B → A gets scrubbed on the A → B leg (cross-origin) but not on B → A (same origin as the original request), because by that point the standard library has rebuilt the header set from the original request again. In practice this matches what you'd expect: A is the host the caller actually trusted.
- Not a URL or SSRF filter. It only ever removes headers; it never blocks a redirect or inspects where a hop goes beyond deciding whether to scrub. Pair it with your own `CheckRedirect` (via `Wrap`) if you also need to reject redirects to private or unexpected hosts.
- No cookie jar interaction beyond what the stdlib already does. If `http.Client.Jar` is set, cookie handling is unaffected by this package.
- Does not scrub or inspect the request body on a 307/308 redirect that preserves it (see "307 and 308" above).

## Compatibility

Run in CI: Go 1.23, on `ubuntu-latest`. No dependencies outside the standard library.

## Development

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
gofmt -l .
go run ./examples/leak-demo
```

## License

MIT — see [LICENSE](LICENSE).
