package main

import "testing"

func TestCheckOrigin(t *testing.T) {
	tests := []struct {
		name string
		link string
		base string
		want bool
	}{
		// exact host and real subdomains
		{"exact host", "https://example.com/path", "https://example.com/", true},
		{"subdomain", "https://www.example.com/path", "https://example.com/", true},
		{"nested subdomain", "https://a.b.example.com/path", "https://example.com/", true},
		{"relative path", "/login?x=1", "https://example.com/dir/page", true},
		{"relative host", "https://example.com:8443/x", "https://example.com:8443/", true},

		// suffix / substring confusion must not be treated as subdomains
		{"suffix attack", "https://evilexample.com/", "https://example.com/", false},
		{"suffix label attack", "https://notexample.com/", "https://example.com/", false},
		{"dotted suffix attack", "http://evilexample.com/x", "http://example.com/x", false},

		// identity smuggling
		{"userinfo", "https://example.com@evilexample.com/", "https://example.com/", false},
		{"userinfo with password", "https://user:pass@example.com/", "https://example.com/", false},
		{"trailing dot", "https://example.com./", "https://example.com/", false},
		{"subdomain trailing dot", "https://www.example.com./", "https://example.com/", false},

		// port confusion
		{"different port", "https://example.com:8443/", "https://example.com/", false},
		{"explicit default port mismatch", "http://example.com:8080/", "http://example.com/", false},

		// case and IDNA normalization
		{"case insensitive host", "https://EXAMPLE.COM/x", "https://example.com/", true},
		{"mixed case subdomain", "https://WWW.Example.COM/x", "https://example.com/", true},
		{"unicode host", "https://xn--bcher-kva.example.com/x", "https://bücher.example.com/", true},
		{"unicode subdomain", "https://shop.bücher.example.com/x", "https://bücher.example.com/", true},
		{"invalid punycode", "https://xn--0000h.example.com/", "https://example.com/", false},

		// scheme-relative and foreign schemes
		{"scheme relative external", "//evilexample.com/path", "https://example.com/", false},
		{"scheme relative subdomain", "//www.example.com/path", "https://example.com/", true},
		{"javascript scheme", "javascript:alert(1)", "https://example.com/", false},
		{"data scheme", "data:text/html,hi", "https://example.com/", false},

		// localhost and IP targets are kept but matched exactly
		{"localhost exact", "http://localhost:8080/a", "http://localhost:8080/b", true},
		{"localhost suffix attack", "http://evillocalhost:8080/a", "http://localhost:8080/b", false},
		{"ip exact", "http://127.0.0.1:8080/a", "http://127.0.0.1:8080/b", true},
		{"ip neighbour", "http://127.0.0.2:8080/a", "http://127.0.0.1:8080/b", false},
		{"ipv6 exact", "http://[::1]:8080/a", "http://[::1]:8080/b", true},
		{"ipv6 neighbour", "http://[::2]:8080/a", "http://[::1]:8080/b", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkOrigin(tt.link, tt.base); got != tt.want {
				t.Errorf("checkOrigin(%q, %q) = %v, want %v", tt.link, tt.base, got, tt.want)
			}
		})
	}
}

func TestNormalizeHostRejectsTrailingDot(t *testing.T) {
	if _, err := normalizeHost("example.com."); err == nil {
		t.Fatal("expected trailing-dot host to be rejected")
	}
	if _, err := normalizeHost(""); err == nil {
		t.Fatal("expected empty host to be rejected")
	}
	host, err := normalizeHost("BüCher.Example.COM")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "xn--bcher-kva.example.com" {
		t.Fatalf("normalized host = %q, want punycode lower-case form", host)
	}
}

func TestNewCrawlScopeRejectsTrailingDotTarget(t *testing.T) {
	if _, err := NewCrawlScope("https://example.com./"); err == nil {
		t.Fatal("expected trailing-dot target to be rejected")
	}
}
