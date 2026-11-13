package auth

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// clientIP returns the request's client address. X-Forwarded-For is read only
// when the peer is a trusted proxy; the client is then the rightmost entry
// that is not itself a trusted proxy.
func (a *Auth) clientIP(r *http.Request) netip.Addr {
	peer := parseHostAddr(r.RemoteAddr)
	if !peer.IsValid() || !a.trusted(peer) {
		return peer
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(h, ",")...)
	}
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		client = ip.Unmap()
		if !a.trusted(client) {
			break
		}
	}
	return client
}

func (a *Auth) trusted(ip netip.Addr) bool {
	for _, p := range a.proxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func parseHostAddr(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}

// limiter counts failed password logins per username and per client IP in a
// fixed window. State is per process.
type limiter struct {
	perUser, perIP int
	window         time.Duration

	mu      sync.Mutex
	entries map[string]*window
	calls   int
}

type window struct {
	start time.Time
	count int
}

func newLimiter(perUser, perIP int, w time.Duration) *limiter {
	return &limiter{perUser: perUser, perIP: perIP, window: w, entries: map[string]*window{}}
}

// blocked reports whether either key has reached its limit, and until when.
func (l *limiter) blocked(user, ip string, now time.Time) (bool, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var until time.Time
	for key, limit := range map[string]int{"u:" + user: l.perUser, "ip:" + ip: l.perIP} {
		e := l.entries[key]
		if e == nil || now.Sub(e.start) >= l.window || e.count < limit {
			continue
		}
		if end := e.start.Add(l.window); end.After(until) {
			until = end
		}
	}
	return !until.IsZero(), until
}

// blockedUser reports whether the username alone has reached its limit.
func (l *limiter) blockedUser(user string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries["u:"+user]
	return e != nil && now.Sub(e.start) < l.window && e.count >= l.perUser
}

func (l *limiter) fail(user, ip string, now time.Time) {
	l.count([]string{"u:" + user, "ip:" + ip}, now)
}

// failUser counts a failure against the username only.
func (l *limiter) failUser(user string, now time.Time) {
	l.count([]string{"u:" + user}, now)
}

func (l *limiter) count(keys []string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		e := l.entries[key]
		if e == nil || now.Sub(e.start) >= l.window {
			e = &window{start: now}
			l.entries[key] = e
		}
		e.count++
	}
	l.calls++
	if l.calls%256 == 0 {
		for k, e := range l.entries {
			if now.Sub(e.start) >= l.window {
				delete(l.entries, k)
			}
		}
	}
}

// reset clears the username counter after a successful login.
func (l *limiter) reset(user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, "u:"+user)
}
