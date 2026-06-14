package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type ipRateLimiter struct {
	mu      sync.Mutex
	entries map[string][]time.Time
	limit   int
	window  time.Duration
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	rl := &ipRateLimiter{
		entries: make(map[string][]time.Time),
		limit:   limit,
		window:  window,
	}
	go rl.periodicCleanup()
	return rl
}

func (rl *ipRateLimiter) allow(ip string) bool {
	now := time.Now()
	cutoff := now.Add(-rl.window)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	times := rl.entries[ip]
	j := 0
	for _, t := range times {
		if t.After(cutoff) {
			times[j] = t
			j++
		}
	}
	times = times[:j]

	if len(times) >= rl.limit {
		rl.entries[ip] = times
		return false
	}
	rl.entries[ip] = append(times, now)
	return true
}

func (rl *ipRateLimiter) periodicCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		cutoff := time.Now().Add(-rl.window)
		rl.mu.Lock()
		for ip, times := range rl.entries {
			j := 0
			for _, t := range times {
				if t.After(cutoff) {
					times[j] = t
					j++
				}
			}
			if j == 0 {
				delete(rl.entries, ip)
			} else {
				rl.entries[ip] = times[:j]
			}
		}
		rl.mu.Unlock()
	}
}

// LoginRateLimit returns a middleware allowing at most limit login attempts per
// window per client IP. Excess requests get 429.
func LoginRateLimit(limit int, window time.Duration) gin.HandlerFunc {
	rl := newIPRateLimiter(limit, window)
	return func(c *gin.Context) {
		if !rl.allow(c.ClientIP()) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests,
				gin.H{"detail": "too many login attempts, please try again later"})
			return
		}
		c.Next()
	}
}
