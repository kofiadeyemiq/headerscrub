package headerscrub_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/__GH_OWNER__/headerscrub"
)

// newRedirectPair starts two httptest servers and returns the origin
// server's URL, plus the target server's URL rewritten to be reached via a
// different hostname ("localhost" instead of "127.0.0.1") so a hop between
// them is a cross-host redirect even though it's the same machine and,
// often, the same port range. It returns the header the target actually
// received, populated after the request completes.
func newRedirectPair(t *testing.T, targetHeaders *http.Header) (originURL string, cleanup func()) {
	t.Helper()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*targetHeaders = r.Header.Clone()
	}))
	targetViaOtherHost := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", targetViaOtherHost)
		w.WriteHeader(http.StatusFound)
	}))

	return origin.URL, func() {
		origin.Close()
		target.Close()
	}
}

// newSameHostRedirect starts one httptest server that redirects a request
// for "/start" to "/end" on itself, so the hop stays on the same host.
func newSameHostRedirect(t *testing.T, endHeaders *http.Header) (startURL string, cleanup func()) {
	t.Helper()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Set("Location", srv.URL+"/end")
			w.WriteHeader(http.StatusFound)
			return
		}
		*endHeaders = r.Header.Clone()
	}))

	return srv.URL + "/start", func() { srv.Close() }
}

func doRequest(t *testing.T, client *http.Client, url string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("X-Api-Key", "super-secret")
	req.Header.Set("Authorization", "Bearer super-secret-token")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	resp.Body.Close()
}

// TestLeakRepro reproduces the underlying stdlib behavior this package
// exists to fix: a plain http.Client with no CheckRedirect policy forwards
// a caller-set header like X-Api-Key across a cross-host redirect.
func TestLeakRepro(t *testing.T) {
	var got http.Header
	originURL, cleanup := newRedirectPair(t, &got)
	defer cleanup()

	client := &http.Client{} // no policy installed - default stdlib behavior
	doRequest(t, client, originURL)

	if key := got.Get("X-Api-Key"); key != "super-secret" {
		t.Fatalf("expected the stdlib leak to reproduce (X-Api-Key present), got %q", key)
	}
	if auth := got.Get("Authorization"); auth != "" {
		t.Fatalf("expected stdlib to already strip Authorization on its own, got %q", auth)
	}
}

// TestCheckRedirect_StripsOnCrossHost confirms the policy closes the gap
// TestLeakRepro demonstrates: X-Api-Key no longer reaches the second host.
func TestCheckRedirect_StripsOnCrossHost(t *testing.T) {
	var got http.Header
	originURL, cleanup := newRedirectPair(t, &got)
	defer cleanup()

	client := &http.Client{CheckRedirect: headerscrub.CheckRedirect()}
	doRequest(t, client, originURL)

	if key := got.Get("X-Api-Key"); key != "" {
		t.Fatalf("expected X-Api-Key to be scrubbed on cross-host redirect, got %q", key)
	}
	if auth := got.Get("Authorization"); auth != "" {
		t.Fatalf("expected Authorization to remain stripped, got %q", auth)
	}
	if accept := got.Get("Accept"); accept != "application/json" {
		t.Fatalf("expected default-allowed Accept header to survive, got %q", accept)
	}
}

// TestCheckRedirect_SameHostKeepsHeaders confirms a same-host redirect is
// left untouched.
func TestCheckRedirect_SameHostKeepsHeaders(t *testing.T) {
	var got http.Header
	startURL, cleanup := newSameHostRedirect(t, &got)
	defer cleanup()

	client := &http.Client{CheckRedirect: headerscrub.CheckRedirect()}
	doRequest(t, client, startURL)

	if key := got.Get("X-Api-Key"); key != "super-secret" {
		t.Fatalf("expected X-Api-Key to survive a same-host redirect, got %q", key)
	}
}

// TestCheckRedirect_SubdomainIsCrossOrigin confirms the package's
// documented choice: unlike the stdlib's own permissive same-domain rule,
// this package treats a different host - including what would be a
// subdomain relationship - as cross-origin and scrubs it.
func TestCheckRedirect_SubdomainIsCrossOrigin(t *testing.T) {
	var got http.Header

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	defer target.Close()
	// Rewrite the target host to look like a subdomain of "localhost" by
	// reusing "localhost" as a suffix; net/http's own shouldCopyHeaderOnRedirect
	// would treat "sub.localhost" as a subdomain of "localhost" and keep
	// sensitive headers flowing. This package should not.
	targetHost := strings.Replace(target.URL, "127.0.0.1", "sub.localhost", 1)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", targetHost)
		w.WriteHeader(http.StatusFound)
	}))
	defer origin.Close()
	originURL := strings.Replace(origin.URL, "127.0.0.1", "localhost", 1)

	client := &http.Client{CheckRedirect: headerscrub.CheckRedirect()}
	doRequest(t, client, originURL)

	if key := got.Get("X-Api-Key"); key != "" {
		t.Fatalf("expected X-Api-Key to be scrubbed for a subdomain hop, got %q", key)
	}
}

// TestAllow confirms a custom allowlist replaces the default and is
// honored.
func TestAllow(t *testing.T) {
	var got http.Header
	originURL, cleanup := newRedirectPair(t, &got)
	defer cleanup()

	client := &http.Client{
		CheckRedirect: headerscrub.CheckRedirect(headerscrub.Allow("X-Api-Key")),
	}
	doRequest(t, client, originURL)

	if key := got.Get("X-Api-Key"); key != "super-secret" {
		t.Fatalf("expected allowlisted X-Api-Key to survive, got %q", key)
	}
	// Accept is part of DefaultAllow but Allow() replaces the default
	// rather than adding to it, so it should now be stripped.
	if accept := got.Get("Accept"); accept != "" {
		t.Fatalf("expected Accept to be scrubbed once Allow() replaces the defaults, got %q", accept)
	}
}

// TestWrap confirms an existing CheckRedirect function still runs after
// the scrubbing logic.
func TestWrap(t *testing.T) {
	var got http.Header
	originURL, cleanup := newRedirectPair(t, &got)
	defer cleanup()

	var nextCalled bool
	next := func(req *http.Request, via []*http.Request) error {
		nextCalled = true
		return nil
	}

	client := &http.Client{
		CheckRedirect: headerscrub.CheckRedirect(headerscrub.Wrap(next)),
	}
	doRequest(t, client, originURL)

	if !nextCalled {
		t.Fatal("expected wrapped CheckRedirect to be called")
	}
	if key := got.Get("X-Api-Key"); key != "" {
		t.Fatalf("expected X-Api-Key still scrubbed with a wrapped func, got %q", key)
	}
}

// TestWrap_ErrorPropagates confirms a wrapped CheckRedirect's error still
// stops the redirect chain.
func TestWrap_ErrorPropagates(t *testing.T) {
	var got http.Header
	originURL, cleanup := newRedirectPair(t, &got)
	defer cleanup()

	wantErr := errors.New("no thanks")
	next := func(req *http.Request, via []*http.Request) error {
		return wantErr
	}

	client := &http.Client{
		CheckRedirect: headerscrub.CheckRedirect(headerscrub.Wrap(next)),
	}
	req, err := http.NewRequest(http.MethodGet, originURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	_, err = client.Do(req)
	if err == nil || !strings.Contains(err.Error(), wantErr.Error()) {
		t.Fatalf("expected wrapped error to propagate, got %v", err)
	}
}

// TestRedirectLimitPreserved confirms the stdlib's default 10-hop redirect
// limit still applies.
func TestRedirectLimitPreserved(t *testing.T) {
	var srv *httptest.Server
	hops := 0
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		w.Header().Set("Location", srv.URL+"/"+strings.Repeat("x", hops))
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	client := &http.Client{CheckRedirect: headerscrub.CheckRedirect()}
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	_, err = client.Do(req)
	if err == nil {
		t.Fatal("expected an error after too many redirects")
	}
	if !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("expected the stdlib's redirect-limit message, got %v", err)
	}
}

// TestNoRedirect confirms a request with no redirect at all works cleanly
// with the policy installed.
func TestNoRedirect(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{CheckRedirect: headerscrub.CheckRedirect()}
	doRequest(t, client, srv.URL)

	if key := got.Get("X-Api-Key"); key != "super-secret" {
		t.Fatalf("expected headers untouched with no redirect, got %q", key)
	}
}

// injectingTransport simulates something like golang.org/x/oauth2's
// Transport: it sets an Authorization header inside RoundTrip, which runs
// after CheckRedirect has already decided what to strip. This is a
// deliberate limitation documented in the README's "What it does not do":
// CheckRedirect cannot see or prevent headers a Transport injects below it.
type injectingTransport struct {
	base http.RoundTripper
}

func (t *injectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer injected-by-transport")
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

func TestTransportInjectedHeaderSurvives(t *testing.T) {
	var got http.Header
	originURL, cleanup := newRedirectPair(t, &got)
	defer cleanup()

	client := &http.Client{
		CheckRedirect: headerscrub.CheckRedirect(),
		Transport:     &injectingTransport{},
	}
	doRequest(t, client, originURL)

	// This documents a real limitation rather than asserting desired
	// behavior: a Transport-injected header is added after CheckRedirect
	// runs, so it reaches the cross-host target regardless of the policy.
	if auth := got.Get("Authorization"); auth != "Bearer injected-by-transport" {
		t.Fatalf("expected transport-injected Authorization to survive despite the policy (documented limitation), got %q", auth)
	}
}

func TestClient_DoesNotMutateInput(t *testing.T) {
	orig := &http.Client{}
	scrubbed := headerscrub.Client(orig)

	if orig.CheckRedirect != nil {
		t.Fatal("expected original client's CheckRedirect to remain nil")
	}
	if scrubbed.CheckRedirect == nil {
		t.Fatal("expected returned client to have CheckRedirect installed")
	}
	if scrubbed == orig {
		t.Fatal("expected Client to return a distinct *http.Client")
	}
}

func TestClient_WrapsExistingCheckRedirect(t *testing.T) {
	var got http.Header
	originURL, cleanup := newRedirectPair(t, &got)
	defer cleanup()

	var existingCalled bool
	existing := func(req *http.Request, via []*http.Request) error {
		existingCalled = true
		return nil
	}

	client := headerscrub.Client(&http.Client{CheckRedirect: existing})
	doRequest(t, client, originURL)

	if !existingCalled {
		t.Fatal("expected the input client's existing CheckRedirect to still run")
	}
	if key := got.Get("X-Api-Key"); key != "" {
		t.Fatalf("expected X-Api-Key still scrubbed via Client(), got %q", key)
	}
}

// TestCheckRedirect_NonCanonicalKeyIsScrubbed is a regression test for a
// leak found in review: setting a header directly on the map with a
// non-canonical key (req.Header["x-api-key"] = ..., which is legal - a
// Header is just a map[string][]string) survived scrubbing, because
// http.Header.Del canonicalizes its argument before deleting and so never
// matched the non-canonical map key net/http's own header-copying had
// carried over verbatim. The fix deletes the exact original map key
// instead of a canonicalized guess at it.
func TestCheckRedirect_NonCanonicalKeyIsScrubbed(t *testing.T) {
	var got http.Header
	originURL, cleanup := newRedirectPair(t, &got)
	defer cleanup()

	client := headerscrub.Client(nil)

	req, err := http.NewRequest(http.MethodGet, originURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header["x-api-key"] = []string{"LOWER-SECRET"} // bypasses Set's canonicalization
	req.Header.Set("X-Auth-Token", "canonical-secret") // canonical, for contrast

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	resp.Body.Close()

	if key := got.Get("X-Api-Key"); key != "" {
		t.Fatalf("expected non-canonical x-api-key to be scrubbed, got %q", key)
	}
	if token := got.Get("X-Auth-Token"); token != "" {
		t.Fatalf("expected canonical X-Auth-Token to still be scrubbed, got %q", token)
	}
}

// TestAllow_NonCanonicalAllowMatchesNonCanonicalKey confirms an allowlist
// name and a request header key are both compared by their canonical
// form, regardless of how either one was spelled.
func TestAllow_NonCanonicalAllowMatchesNonCanonicalKey(t *testing.T) {
	var got http.Header
	originURL, cleanup := newRedirectPair(t, &got)
	defer cleanup()

	client := &http.Client{
		CheckRedirect: headerscrub.CheckRedirect(headerscrub.Allow("accept")),
	}

	req, err := http.NewRequest(http.MethodGet, originURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header["accept"] = []string{"application/json"} // non-canonical key
	req.Header["x-api-key"] = []string{"super-secret"}  // non-canonical, not allowlisted

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	resp.Body.Close()

	if accept := got.Get("Accept"); accept != "application/json" {
		t.Fatalf("expected a non-canonically-spelled Allow() entry to match a non-canonical header key, got %q", accept)
	}
	if key := got.Get("X-Api-Key"); key != "" {
		t.Fatalf("expected a non-allowlisted non-canonical header to still be scrubbed, got %q", key)
	}
}

// bodyReceived captures what a target server actually received, for the
// 307/308 body-preservation tests below.
type bodyReceived struct {
	method      string
	body        []byte
	contentType string
	header      http.Header
}

// newBodyRedirectPair starts two httptest servers reached via different
// hostnames (like newRedirectPair) where the origin redirects to the
// target with the given status code, preserving whatever method and body
// that status code implies.
func newBodyRedirectPair(t *testing.T, status int) (originURL string, got *bodyReceived, cleanup func()) {
	t.Helper()
	got = &bodyReceived{}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.method = r.Method
		got.body = b
		got.contentType = r.Header.Get("Content-Type")
		got.header = r.Header.Clone()
	}))
	targetViaOtherHost := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", targetViaOtherHost)
		w.WriteHeader(status)
	}))

	return origin.URL, got, func() {
		origin.Close()
		target.Close()
	}
}

// TestCheckRedirect_307KeepsBodyAndContentType is a regression test for a
// correctness bug found in review: a cross-origin 307/308 resends the
// request body (net/http preserves method and body for those codes), but
// the policy was stripping Content-Type along with everything else,
// leaving the server unable to interpret the body it just received.
// Content-Type (and the other headers in bodyHeaders) must survive
// whenever the hop still carries a body; the body itself is resent as-is
// and is not scrubbed - see the README.
func TestCheckRedirect_307KeepsBodyAndContentType(t *testing.T) {
	originURL, got, cleanup := newBodyRedirectPair(t, http.StatusTemporaryRedirect)
	defer cleanup()

	client := &http.Client{CheckRedirect: headerscrub.CheckRedirect()}

	body := `{"x":1}`
	req, err := http.NewRequest(http.MethodPost, originURL, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "super-secret")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	resp.Body.Close()

	if got.method != http.MethodPost {
		t.Fatalf("expected a 307 to preserve POST, got %q", got.method)
	}
	if string(got.body) != body {
		t.Fatalf("expected the body to be resent on a cross-origin 307, got %q", got.body)
	}
	if got.contentType != "application/json" {
		t.Fatalf("expected Content-Type to survive a cross-origin 307 that resends the body, got %q", got.contentType)
	}
	if key := got.header.Get("X-Api-Key"); key != "" {
		t.Fatalf("expected X-Api-Key to still be scrubbed even though the body is kept, got %q", key)
	}
}

// TestCheckRedirect_302DowngradesToGETNoBody is a companion to the 307
// test above: a 302 makes net/http itself convert POST to GET and drop the
// body (redirectBehavior in client.go), before headerscrub's own logic
// ever runs. With no body on the hop, Content-Type is treated like any
// other non-allowlisted header and scrubbed, matching net/http's own
// behavior for a POST-to-GET downgrade.
func TestCheckRedirect_302DowngradesToGETNoBody(t *testing.T) {
	originURL, got, cleanup := newBodyRedirectPair(t, http.StatusFound)
	defer cleanup()

	client := &http.Client{CheckRedirect: headerscrub.CheckRedirect()}

	req, err := http.NewRequest(http.MethodPost, originURL, strings.NewReader(`{"x":1}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	resp.Body.Close()

	if got.method != http.MethodGet {
		t.Fatalf("expected a 302 to downgrade POST to GET per net/http's own behavior, got %q", got.method)
	}
	if len(got.body) != 0 {
		t.Fatalf("expected no body on a GET-downgraded redirect, got %q", got.body)
	}
	if got.contentType != "" {
		t.Fatalf("expected Content-Type to be scrubbed when no body is resent, got %q", got.contentType)
	}
}

// TestWrap_DelegatesRedirectLimit is a regression test for a behavior
// found in review: CheckRedirect always enforced its own 10-hop cap even
// when Wrap chained in a policy that permits more, silently overriding it.
// When next is set, the limit is fully delegated to it.
func TestWrap_DelegatesRedirectLimit(t *testing.T) {
	var srv *httptest.Server
	const hops = 15 // more than the built-in 10-hop cap
	count := 0
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		if count > hops {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Location", srv.URL+"/"+strings.Repeat("x", count))
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	permissive := func(req *http.Request, via []*http.Request) error {
		return nil // no limit of its own
	}

	client := &http.Client{
		CheckRedirect: headerscrub.CheckRedirect(headerscrub.Wrap(permissive)),
	}
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected wrapping a permissive CheckRedirect to allow more than 10 hops, got error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected the redirect chain to complete, got status %d", resp.StatusCode)
	}
}
