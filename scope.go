package main

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// idnaProfile is the strict IDNA "lookup" profile: it lowercases the
// hostname, converts Unicode labels to punycode and rejects malformed
// labels (for example invalid punycode or disallowed runes).
var idnaProfile = idna.Lookup

// CrawlScope describes the exact origin boundary the crawler is allowed
// to request. A URL is in scope only when its normalized host is either
// the target host itself or a proper subdomain of it, its port matches
// the target port, and it does not try to smuggle identity through
// userinfo or a trailing dot.
type CrawlScope struct {
	host string
	port string
}

// NewCrawlScope builds a CrawlScope from the target URL.
func NewCrawlScope(target string) (*CrawlScope, error) {
	baseURL, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	host, err := normalizeHost(baseURL.Hostname())
	if err != nil {
		return nil, err
	}

	return &CrawlScope{host: host, port: baseURL.Port()}, nil
}

// Allows reports whether the given URL may be requested by the crawler.
// Relative URLs are resolved against base so that same-origin relative
// links are accepted while scheme-relative links pointing elsewhere are
// rejected.
func (s *CrawlScope) Allows(rawURL string, base *url.URL) bool {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if base != nil {
		parsedURL = base.ResolveReference(parsedURL)
	}

	// Only http/https URLs have a network origin that can be checked.
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return false
	}
	// userinfo (user:pass@host) is an identity-smuggling attempt.
	if parsedURL.User != nil {
		return false
	}
	// A different port is a different origin and must not be reached.
	if parsedURL.Port() != s.port {
		return false
	}

	host, err := normalizeHost(parsedURL.Hostname())
	if err != nil {
		return false
	}

	return s.hostAllows(host)
}

// hostAllows matches the exact target host or a proper subdomain of it.
// IP literals (including loopback and private addresses) and single-label
// names such as "localhost" only match themselves.
func (s *CrawlScope) hostAllows(host string) bool {
	if host == s.host {
		return true
	}

	if net.ParseIP(s.host) != nil || !strings.Contains(s.host, ".") {
		return false
	}

	return strings.HasSuffix(host, "."+s.host)
}

// normalizeHost returns the IDNA-normalized form of host. A trailing dot
// (FQDN root), an empty host or an IDNA-invalid label is rejected instead
// of being silently accepted.
func normalizeHost(host string) (string, error) {
	if host == "" || strings.HasSuffix(host, ".") {
		return "", errInvalidHost
	}

	// IP literals are not DNS names: compare them as-is (lower-cased for
	// IPv6) instead of running them through IDNA, which rejects colons.
	if ip := net.ParseIP(host); ip != nil {
		return strings.ToLower(host), nil
	}

	normalized, err := idnaProfile.ToASCII(host)
	if err != nil {
		return "", err
	}

	return normalized, nil
}

type hostError struct {
	reason string
}

func (e *hostError) Error() string {
	return e.reason
}

var errInvalidHost = &hostError{reason: "invalid or ambiguous hostname"}

// checkOrigin reports whether link belongs to the same origin as base,
// where same-origin means the exact IDNA-normalized host or one of its
// proper subdomains, with an identical port and no userinfo/trailing-dot
// obfuscation.
func checkOrigin(link, base string) bool {
	baseURL, err := url.Parse(base)
	if err != nil {
		return false
	}

	scope, err := NewCrawlScope(base)
	if err != nil {
		return false
	}

	return scope.Allows(link, baseURL)
}
