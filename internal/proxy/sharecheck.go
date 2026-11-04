// Immich checks a share's password only in GET shared-links/me. Every other
// shared-link route accepts the bare key, so anyone who has the link and an
// album or asset ID can fetch content without the password. shareChecker
// closes that gap: before forwarding a content request, it asks Immich
// GET shared-links/me with the same key and share cookie, and only forwards
// on 200. That covers passwords, expiry, and deleted links, with Immich
// remaining the authority. Results are cached briefly, and concurrent checks
// for the same key and cookie are merged.
//
// The key is checked without the cookie first. Only if Immich refuses that
// (the share has a password, or the key is bad) is it checked again with
// the cookie. So for a share without a password, the cookie never reaches
// the cache key, and varying it can't force new upstream checks or flood
// the cache. For a password share, every wrong cookie is a denial, which the
// rate limiter counts.

package proxy

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

var errShareDenied = errors.New("share access denied")

type shareChecker struct {
	upstream *url.URL
	client   *http.Client
	ttl      time.Duration
	negTTL   time.Duration
	now      func() time.Time

	mu       sync.Mutex
	cache    map[[32]byte]checkResult
	inflight map[[32]byte]*checkCall
}

type checkResult struct {
	ok      bool
	expires time.Time
}

type checkCall struct {
	done chan struct{}
	ok   bool
	err  error
}

const maxCheckCache = 10_000

func newShareChecker(upstream *url.URL, transport http.RoundTripper, ttl time.Duration) *shareChecker {
	neg := ttl
	if neg > 10*time.Second {
		neg = 10 * time.Second
	}
	return &shareChecker{
		upstream: upstream,
		client:   &http.Client{Transport: transport, Timeout: 15 * time.Second},
		ttl:      ttl,
		negTTL:   neg,
		now:      time.Now,
		cache:    map[[32]byte]checkResult{},
		inflight: map[[32]byte]*checkCall{},
	}
}

// check reports nil if the share identified by param ("key" or "slug") and
// value is accessible with the given share cookie, errShareDenied if Immich
// refuses it, or another error if Immich couldn't be asked.
func (c *shareChecker) check(param, value, cookie, clientIP string) error {
	err := c.lookup(param, value, "", clientIP)
	if cookie == "" || !errors.Is(err, errShareDenied) {
		return err
	}
	return c.lookup(param, value, cookie, clientIP)
}

// lookup checks one key and cookie combination, through the cache.
func (c *shareChecker) lookup(param, value, cookie, clientIP string) error {
	id := sha256.Sum256([]byte(param + "\x00" + value + "\x00" + cookie))

	c.mu.Lock()
	if r, ok := c.cache[id]; ok && c.now().Before(r.expires) {
		c.mu.Unlock()
		if r.ok {
			return nil
		}
		return errShareDenied
	}
	if call, ok := c.inflight[id]; ok {
		c.mu.Unlock()
		<-call.done
		return result(call)
	}
	call := &checkCall{done: make(chan struct{})}
	c.inflight[id] = call
	c.mu.Unlock()

	call.ok, call.err = c.ask(param, value, cookie, clientIP)

	c.mu.Lock()
	delete(c.inflight, id)
	if call.err == nil && c.ttl > 0 {
		c.store(id, call.ok)
	}
	c.mu.Unlock()
	close(call.done)
	return result(call)
}

func result(call *checkCall) error {
	if call.err != nil {
		return call.err
	}
	if !call.ok {
		return errShareDenied
	}
	return nil
}

// store must be called with c.mu held.
func (c *shareChecker) store(id [32]byte, ok bool) {
	now := c.now()
	if len(c.cache) >= maxCheckCache {
		for k, r := range c.cache {
			if !now.Before(r.expires) {
				delete(c.cache, k)
			}
		}
		if len(c.cache) >= maxCheckCache {
			clear(c.cache)
		}
	}
	ttl := c.ttl
	if !ok {
		ttl = c.negTTL
	}
	c.cache[id] = checkResult{ok: ok, expires: now.Add(ttl)}
}

func (c *shareChecker) ask(param, value, cookie, clientIP string) (bool, error) {
	u := *c.upstream
	u.Path = "/api/shared-links/me"
	u.RawQuery = url.Values{param: {value}}.Encode()
	ctx, cancel := context.WithTimeout(context.Background(), c.client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, err
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	req.Header.Set("X-Forwarded-For", clientIP)
	resp, err := c.client.Do(req)
	if err != nil {
		// A *url.Error includes the URL, and so the full share key. It is
		// logged as the reason the request was blocked.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return false, errors.New("share check: " + err.Error())
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return false, nil
	}
	return false, errors.New("share check: upstream status " + resp.Status)
}
