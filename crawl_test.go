package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// hitCounter records the paths requested from a test server, letting the
// tests assert that a third-party target received zero requests.
type hitCounter struct {
	mu    sync.Mutex
	paths []string
}

func (h *hitCounter) record(path string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.paths = append(h.paths, path)
}

func (h *hitCounter) len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.paths)
}

func newCountingServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *hitCounter) {
	t.Helper()
	counter := &hitCounter{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter.record(r.URL.Path)
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return server, counter
}

// TestCrawlNeverRequestsOutOfScopeLinks verifies that links pointing at a
// different host, port, userinfo or trailing-dot variant are never fetched.
func TestCrawlNeverRequestsOutOfScopeLinks(t *testing.T) {
	external, externalHits := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("third party content must never be collected"))
	})
	externalURL := strings.TrimPrefix(external.URL, "http://") // host:port

	// A second listener on a different port acts as the "same host,
	// different port" confusion target.
	otherPort, otherPortHits := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("different origin"))
	})
	otherPortURL := strings.TrimPrefix(otherPort.URL, "http://")

	origin, originHits := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			page := fmt.Sprintf(`<html><body>
				<a href="/in-scope">same origin relative</a>
				<a href="nested/relative">nested relative</a>
				<a href="%s/suffix-attack">suffix attack</a>
				<a href="http://%s/userinfo-confusion">bare external</a>
				<a href="http://user:pass@%s/userinfo">userinfo</a>
				<a href="http://%s./trailing-dot">trailing dot</a>
				<a href="http://%s/port-confusion">port confusion</a>
				<a href="//%s/scheme-relative">scheme relative</a>
				<a href="javascript:alert(1)">javascript</a>
				</body></html>`,
				external.URL, externalURL, externalURL, r.Host, otherPortURL, externalURL)
			_, _ = w.Write([]byte(page))
		case "/in-scope":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><a href="/">home</a></body></html>`))
		default:
			http.NotFound(w, r)
		}
	})

	scope, err := NewCrawlScope(origin.URL)
	if err != nil {
		t.Fatalf("NewCrawlScope: %v", err)
	}
	c := newCrawler(scope, 2, 4)

	if err := c.Visit(origin.URL); err != nil {
		t.Fatalf("Visit: %v", err)
	}
	c.Wait()

	if got := externalHits.len(); got != 0 {
		t.Fatalf("third-party server received %d requests: %v", got, externalHits.paths)
	}
	if got := otherPortHits.len(); got != 0 {
		t.Fatalf("different-port server received %d requests: %v", got, otherPortHits.paths)
	}
	if got := originHits.len(); got < 2 {
		t.Fatalf("same-origin crawl did not happen, only %d requests: %v", got, originHits.paths)
	}
}

// TestCrawlRechecksScopeAfterRedirect verifies that an in-scope URL which
// redirects to a third party is stopped before the third party is hit.
func TestCrawlRechecksScopeAfterRedirect(t *testing.T) {
	external, externalHits := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("redirect destination"))
	})

	origin, originHits := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bounce" {
			http.Redirect(w, r, external.URL+"/landed", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/bounce">redirect</a></body></html>`))
	})

	scope, err := NewCrawlScope(origin.URL)
	if err != nil {
		t.Fatalf("NewCrawlScope: %v", err)
	}
	c := newCrawler(scope, 2, 4)

	if err := c.Visit(origin.URL + "/bounce"); err != nil {
		t.Fatalf("Visit: %v", err)
	}
	c.Wait()

	if got := externalHits.len(); got != 0 {
		t.Fatalf("redirect target received %d requests: %v", got, externalHits.paths)
	}
	if got := originHits.len(); got != 1 {
		t.Fatalf("origin server hits = %d (%v), want exactly 1 blocked redirect", got, originHits.paths)
	}
}

// TestCrawlFollowsInScopeRedirect makes sure the redirect re-validation
// does not break legitimate same-origin redirects.
func TestCrawlFollowsInScopeRedirect(t *testing.T) {
	origin, originHits := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			http.Redirect(w, r, "/new", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>ok</body></html>`))
	})

	scope, err := NewCrawlScope(origin.URL)
	if err != nil {
		t.Fatalf("NewCrawlScope: %v", err)
	}
	c := newCrawler(scope, 2, 4)

	if err := c.Visit(origin.URL + "/old"); err != nil {
		t.Fatalf("Visit: %v", err)
	}
	c.Wait()

	want := map[string]bool{"/old": false, "/new": false}
	for _, path := range originHits.paths {
		if _, ok := want[path]; ok {
			want[path] = true
		}
	}
	for path, seen := range want {
		if !seen {
			t.Fatalf("same-origin redirect not followed, missing %q, got %v", path, originHits.paths)
		}
	}
}
