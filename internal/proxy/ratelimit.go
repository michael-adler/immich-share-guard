// Per-IP failure limit. Failed requests (API rejections, upstream auth
// errors on API routes, and Immich's 404s for share pages) are counted per
// client IP in a fixed window, and an IP that
// exceeds the limit is blocked until its window expires. This slows down
// guessing of share keys, slugs, IDs and share passwords.
//
// IPv6 clients are counted per /64, the smallest block an ISP normally
// assigns, so rotating addresses within it doesn't reset the count.

package proxy

import (
	"net"
	"sync"
	"time"
)

// failLimiter implements the limit. It is safe for concurrent use.
type failLimiter struct {
	limit  int
	window time.Duration
	now    func() time.Time

	mu        sync.Mutex
	entries   map[string]*failEntry
	lastSweep time.Time
}

type failEntry struct {
	start time.Time
	count int
}

func newFailLimiter(limit int, window time.Duration) *failLimiter {
	return &failLimiter{limit: limit, window: window, now: time.Now, entries: map[string]*failEntry{}}
}

func (l *failLimiter) enabled() bool { return l.limit > 0 && l.window > 0 }

// limitKey returns the counting key for a client IP: the address itself
// for IPv4, its /64 prefix for IPv6.
func limitKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func (l *failLimiter) blocked(ip string) bool {
	if !l.enabled() {
		return false
	}
	ip = limitKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[ip]
	if e == nil {
		return false
	}
	if l.now().Sub(e.start) >= l.window {
		delete(l.entries, ip)
		return false
	}
	return e.count >= l.limit
}

func (l *failLimiter) fail(ip string) {
	if !l.enabled() {
		return
	}
	ip = limitKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.lastSweep) >= l.window {
		for k, e := range l.entries {
			if now.Sub(e.start) >= l.window {
				delete(l.entries, k)
			}
		}
		l.lastSweep = now
	}
	e := l.entries[ip]
	if e == nil || now.Sub(e.start) >= l.window {
		e = &failEntry{start: now}
		l.entries[ip] = e
	}
	e.count++
}
