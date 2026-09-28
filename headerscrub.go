// Package headerscrub provides an [http.Client] CheckRedirect policy that
// strips caller-set headers before following a redirect to a different host.
//
// [http.Client]'s default redirect handling forwards every header the
// caller set on the original request to every host a 3xx response points
// it at, with one exception: a fixed list of "sensitive" headers
// (Authorization, Www-Authenticate, Cookie, Cookie2, Proxy-Authorization,
// Proxy-Authenticate) is dropped when the redirect target is not the same
// domain or a subdomain of the original host. Anything outside that list —
// X-Api-Key, X-Auth-Token, a custom bearer header, an internal service
// token — is copied to any host the response redirects to, including a
// host the caller never intended to talk to. See net/http's
// makeHeadersCopier and shouldCopyHeaderOnRedirect in client.go.
//
// CheckRedirect closes that gap for headers the standard library doesn't
// already protect, by deleting every header the original request carried
// (except a small allowlist) whenever a hop crosses to a different origin.
//
// # Same origin, not same domain
//
// The standard library's shouldCopyHeaderOnRedirect treats "example.com"
// and "sub.example.com" as the same domain, on the theory that a caller
// who set a Cookie or Authorization header directly likely intended it for
// the whole domain. This package does not extend that same courtesy: it
// compares scheme, host and port exactly (see sameOrigin), so a redirect
// from "example.com" to "sub.example.com" is treated as cross-origin and
// triggers scrubbing.
//
// The reasoning is different for this package's job. The standard
// library's list is small and specific (Authorization, Cookie, and
// similar), chosen because those headers have well-understood domain
// scope. This package strips arbitrary caller-set headers — API keys,
// internal bearer tokens, anything — which have no such convention, and a
// subdomain of the original host is not necessarily operated by the same
// party (subdomain takeover, multi-tenant hosting, a CDN edge). Matching
// the stdlib's permissive rule here would silently defeat the point of the
// package for exactly the redirect shapes it exists to catch. Configure
// [Allow] if a specific set of headers should follow a known family of
// subdomains.
package headerscrub

import (
	"errors"
	"net/http"
	"net/url"
)

// maxRedirects matches the standard library's [http.Client] default
// redirect limit (see defaultCheckRedirect in net/http/client.go). It is
// preserved so installing this policy does not change a client's existing
// redirect-loop behavior.
const maxRedirects = 10

// DefaultAllow is the set of header names preserved across a cross-origin
// redirect when no allowlist is configured via [Allow]. These are headers
// that describe the client or its content preferences rather than
// authorization or identity, and are safe to send to any host.
var DefaultAllow = []string{"Accept", "Accept-Language", "User-Agent"}

// config holds the policy's resolved options.
type config struct {
	allow []string
	next  func(req *http.Request, via []*http.Request) error
}

// Option configures the policy returned by [CheckRedirect].
type Option func(*config)

// Allow adds header names to the allowlist of headers that survive a
// cross-origin redirect. It replaces [DefaultAllow] rather than adding to
// it — pass all the names you want kept, including any of the defaults you
// still want, if you use Allow at all. Names are matched
// case-insensitively via [http.CanonicalHeaderKey].
func Allow(names ...string) Option {
	return func(c *config) {
		c.allow = names
	}
}

// Wrap installs next to run after this policy's own header-scrubbing
// logic, so an existing CheckRedirect func (redirect-count limits, URL
// allowlists, logging, and so on) keeps running. next receives the request
// after headers have already been scrubbed. A nil next is a no-op.
func Wrap(next func(req *http.Request, via []*http.Request) error) Option {
	return func(c *config) {
		c.next = next
	}
}

// bodyHeaders are the headers that describe a request body's encoding and
// language rather than the caller's identity. They mirror the set
// net/http's own makeHeadersCopier treats as "body" headers (the `body`
// case in client.go) — the ones it strips itself only when a redirect
// drops the body (a 301/302/303 POST-to-GET downgrade), and otherwise
// carries along with the body.
//
// CheckRedirect keeps these automatically, in addition to the configured
// allowlist, whenever the redirected request still carries a body (a
// cross-origin 307 or 308). Scrubbing them in that case would not improve
// security — they don't identify the caller — and would leave the server
// unable to interpret the body it just received. See the README's "What
// it does not do" for the body itself, which is resent as-is and is not
// scrubbed or inspected.
var bodyHeaders = map[string]bool{
	"Content-Type":     true,
	"Content-Encoding": true,
	"Content-Language": true,
	"Content-Location": true,
}

// CheckRedirect returns an [http.Client] CheckRedirect function that
// deletes every header the original request (via[0]) carried from a
// redirected request's headers, except headers named in [DefaultAllow] or
// configured with [Allow] (and, when the hop still carries a body, the
// [bodyHeaders] set), whenever the redirect crosses to a different origin.
// Same-origin hops are left untouched. Header names are compared by their
// canonical form regardless of how the caller or the allowlist spelled
// them, and the exact map key(s) present on the redirected request are
// deleted — so a header set directly on the map with a non-canonical key
// (req.Header["x-api-key"] = ... instead of req.Header.Set(...)) is
// scrubbed correctly rather than surviving because a canonicalizing delete
// missed it.
//
// "Different origin" means scheme, host and port are not all identical —
// see the package doc comment's "Same origin, not same domain" note for
// why this is stricter than the standard library's own same-domain-or-
// subdomain rule.
//
// The returned function enforces the standard library's default 10-hop
// redirect limit itself only when no existing CheckRedirect is chained in
// via [Wrap]. When a next function is wrapped, the limit is delegated to
// it entirely — set your own bound inside next, or return nil for no cap —
// so that wrapping a policy which permits more than 10 hops actually takes
// effect instead of being capped underneath it. [Client] always wraps
// whatever CheckRedirect the input client already had (nil or not), so the
// same rule applies there: pass a client with no CheckRedirect to keep the
// default 10-hop cap.
func CheckRedirect(opts ...Option) func(req *http.Request, via []*http.Request) error {
	cfg := &config{allow: DefaultAllow}
	for _, opt := range opts {
		opt(cfg)
	}

	allow := make(map[string]bool, len(cfg.allow))
	for _, name := range cfg.allow {
		allow[http.CanonicalHeaderKey(name)] = true
	}

	return func(req *http.Request, via []*http.Request) error {
		if cfg.next == nil && len(via) >= maxRedirects {
			return errors.New("stopped after 10 redirects")
		}

		original := via[0]
		if !sameOrigin(original.URL, req.URL) {
			hasBody := req.Body != nil || req.GetBody != nil
			for name := range original.Header {
				canon := http.CanonicalHeaderKey(name)
				if allow[canon] {
					continue
				}
				if hasBody && bodyHeaders[canon] {
					continue
				}
				// Delete the exact key from original.Header, not a
				// canonicalized version of it: req.Header.Del would
				// canonicalize name first and so never remove an entry
				// that was set directly on the map with a non-canonical
				// key, since net/http's own header-copying preserves
				// whatever casing the original request's map key had.
				delete(req.Header, name)
			}
		}

		if cfg.next != nil {
			return cfg.next(req, via)
		}
		return nil
	}
}

// Client returns a shallow copy of c with [CheckRedirect] installed as its
// CheckRedirect policy. c is not modified. If c already has a
// CheckRedirect function set, it is preserved and run after the scrubbing
// logic, equivalent to passing Wrap(c.CheckRedirect) — so a manually
// supplied Wrap option is overridden by this automatic wrapping. If c is
// nil, Client uses the zero value of [http.Client].
//
// Because Client always wraps c's existing CheckRedirect (even when it's
// nil), [CheckRedirect]'s redirect-limit rule applies here too: the
// default 10-hop cap only applies when c.CheckRedirect was nil to begin
// with. A client that already enforces its own limit (or none) keeps doing
// exactly that.
func Client(c *http.Client, opts ...Option) *http.Client {
	var cp http.Client
	if c != nil {
		cp = *c
	}
	opts = append(opts, Wrap(cp.CheckRedirect))
	cp.CheckRedirect = CheckRedirect(opts...)
	return &cp
}

// sameOrigin reports whether a and b share the same scheme, host and port.
// A missing port (":80" left implicit on an http URL, say) is treated as
// distinct from the explicit default port — see the package doc comment.
func sameOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && a.Host == b.Host
}
