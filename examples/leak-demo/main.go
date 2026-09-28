// Command leak-demo shows the header leak headerscrub closes: a caller-set
// header on the original request reaching a different host after a 3xx
// redirect, with and without the policy installed.
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/kofiadeyemiq/headerscrub"
)

func main() {
	var received http.Header

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Clone()
	}))
	defer target.Close()

	// Reach the target via "localhost" instead of "127.0.0.1" - same
	// machine, different hostname, so the hop is cross-host.
	targetViaOtherHost := strings.Replace(target.URL, "127.0.0.1", "localhost", 1)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", targetViaOtherHost)
		w.WriteHeader(http.StatusFound)
	}))
	defer origin.Close()

	request := func(client *http.Client) http.Header {
		received = nil
		req, _ := http.NewRequest(http.MethodGet, origin.URL, nil)
		req.Header.Set("X-Api-Key", "super-secret")
		req.Header.Set("Authorization", "Bearer super-secret-token")
		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}
		resp.Body.Close()
		return received
	}

	plain := request(&http.Client{})
	fmt.Println("plain http.Client (no policy):")
	fmt.Printf("  X-Api-Key received by other host:    %q\n", plain.Get("X-Api-Key"))
	fmt.Printf("  Authorization received by other host: %q  (stdlib already strips this one)\n", plain.Get("Authorization"))

	scrubbed := request(headerscrub.Client(&http.Client{}))
	fmt.Println("\nheaderscrub.Client (policy installed):")
	fmt.Printf("  X-Api-Key received by other host:    %q\n", scrubbed.Get("X-Api-Key"))
	fmt.Printf("  Authorization received by other host: %q\n", scrubbed.Get("Authorization"))
}
