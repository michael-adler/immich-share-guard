// Proxy settings and their defaults.

package proxy

import (
	"net"
	"net/url"
	"time"
)

// Config is passed to New. Start from DefaultConfig.
type Config struct {
	Upstream       *url.URL     // internal Immich URL, with no path
	LogOnly        bool         // log disallowed requests instead of blocking them
	AllowSlugs     bool         // allow custom-URL shares (/s/<slug>)
	AllowUpload    bool         // allow uploads to shares that permit them
	TrustedProxies []*net.IPNet // peers whose X-Forwarded-* headers are trusted
	FailLimit      int          // failed API requests per IP per window (0 disables)
	FailWindow     time.Duration
	ShareCheckTTL  time.Duration // cache lifetime of share password checks
	MaxBody        int64         // validated request bodies
	MaxScrubBody   int64         // rewritten JSON responses
	SpecInterval   time.Duration // how often to recheck the upstream spec (0: only at startup)
}

// DefaultConfig returns the default settings, with no upstream.
func DefaultConfig() Config {
	return Config{
		TrustedProxies: []*net.IPNet{
			{IP: net.IPv4(127, 0, 0, 1).To4(), Mask: net.CIDRMask(32, 32)},
			{IP: net.IPv6loopback, Mask: net.CIDRMask(128, 128)},
		},
		FailLimit:     30,
		FailWindow:    10 * time.Minute,
		ShareCheckTTL: time.Minute,
		MaxBody:       8 << 20,
		MaxScrubBody:  64 << 20,
		SpecInterval:  15 * time.Minute,
	}
}
