# headerscrub

An `http.Client` CheckRedirect policy that stops caller-set headers from
following a redirect to a different host.

```
plain http.Client (no policy):
  X-Api-Key received by other host:    "super-secret"
  Authorization received by other host: ""  (stdlib already strips this one)

headerscrub.Client (policy installed):
  X-Api-Key received by other host:    ""
  Authorization received by other host: ""
```

That's `go run ./examples/leak-demo`. Both requests set the same two
headers. `Authorization` never reaches the second host either way — the
standard library already handles that one. `X-Api-Key` reaches it in the
first case and not in the second.

## The problem

`net/http`'s default redirect handling copies every header the caller set
on the original request onto each subsequent hop, forwarding it to
whatever host a 3xx response points at. There is one carve-out: a fixed
list of headers it considers sensitive — `Authorization`, `Www-Authenticate`,
`Cookie`, `Cookie2`, `Proxy-Authorization`, `Proxy-Authenticate` — is
dropped when the redirect target isn't the same domain or a subdomain of
the original host (`shouldCopyHeaderOnRedirect` in `net/http/client.go`).

Everything else on the list is not: `X-Api-Key`, `X-Auth-Token`, a custom
bearer scheme, an internal service token. If your code sets one of those
and the response you're fetching (or forwarding on a user's behalf) redirects
to a host you don't control, that header goes with it. This is the shape of
bug that shows up in webhook delivery, link previews, outbound proxies, and
any client that follows redirects on URLs it doesn't fully trust.

This isn't a hypothetical reading of the source — it reproduces on a
current Go toolchain with two `httptest` servers reached via different
hostnames on the same machine (see `TestLeakRepro` in
`headerscrub_test.go`, and `examples/leak-demo` above).

## Install

```sh
go get github.com/__GH_OWNER__/headerscrub
```

Go 1.23+. No dependencies outside the standard library.

## Use

```go
client := headerscrub.Client(&http.Client{})

req, _ := http.NewRequest(http.MethodGet, someURL, nil)
req.Header.Set("X-Api-Key", secret)

resp, err := client.Do(req)
// If someURL redirects to a different host, X-Api-Key does not go with it.
```

Or install the policy directly on a `CheckRedirect` field:

```go
client := &http.Client{
    CheckRedirect: headerscrub.CheckRedirect(),
}
```

`headerscrub.Client` returns a shallow copy of the `*http.Client` you pass
in — the input is never modified — and automatically preserves any
`CheckRedirect` function it already had, running it after the scrubbing
logic.

### Options

| Option | Default | What it does |
| --- | --- | --- |
| `Allow(names ...string)` | `Accept`, `Accept-Language`, `User-Agent` | Replaces the allowlist of headers that survive a cross-origin hop. Not additive — list everything you want kept. |
| `Wrap(next)` | none | Runs an existing `CheckRedirect` function after the scrubbing logic, so redirect-count limits, URL allowlists, or logging keep working. |

The returned policy preserves the standard library's default 10-redirect
limit on its own; you don't need `Wrap` just to keep that.

## Same origin, not same domain

The standard library's own carve-out treats `example.com` and
`sub.example.com` as close enough to keep `Authorization`/`Cookie` flowing
between them. This package does not extend that courtesy: it compares
scheme, host and port exactly, so a redirect from `example.com` to
`sub.example.com` is treated as cross-origin and scrubbed.

The stdlib's list is small and its headers have well-understood domain
scope. This package strips arbitrary caller-set headers, which have no such
convention, and a subdomain is not necessarily operated by the same party —
subdomain takeover and multi-tenant hosting are both real. Matching the
permissive rule here would leave a gap for exactly the redirect shapes this
package exists to catch. If you do want specific headers to follow a known
family of subdomains, list them with `Allow`.

## What it does not do

- **It only sees headers set on the original request.** `CheckRedirect`
  runs before the request is sent, so a header a `Transport` injects
  inside `RoundTrip` — the pattern `golang.org/x/oauth2`'s `Transport` uses
  to add `Authorization` on every request — is added *after* this policy
  has already decided what to keep, and reaches every host regardless.
  `TestTransportInjectedHeaderSurvives` demonstrates this with a small
  custom `RoundTripper`; there's no way to fix it from `CheckRedirect`.
- **A hop back to the original host restores its headers.** Each hop is
  judged against the *original* request's host, not the previous hop. A
  redirect A → B → A gets scrubbed on the A → B leg (cross-origin) but not
  on B → A (same origin as the original request), because by that point
  the standard library has rebuilt the header set from the original
  request again. In practice this matches what you'd expect: A is the host
  the caller actually trusted.
- **Not a URL or SSRF filter.** It only ever removes headers; it never
  blocks a redirect or inspects where a hop goes beyond deciding whether to
  scrub. Pair it with your own `CheckRedirect` (via `Wrap`) if you also need
  to reject redirects to private or unexpected hosts.
- **No cookie jar interaction beyond what the stdlib already does.** If
  `http.Client.Jar` is set, cookie handling is unaffected by this package.

## Develop

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
gofmt -l .
go run ./examples/leak-demo
```

## License

MIT
