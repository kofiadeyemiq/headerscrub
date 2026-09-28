package headerscrub_test

import (
	"errors"
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
