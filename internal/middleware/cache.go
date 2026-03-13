package middleware

import (
	"bytes"
	"net/http"
	"sync"
	"time"
)

// CacheConfig configures the response cache.
type CacheConfig struct {
	TTLSeconds int   // Cache TTL in seconds
	MaxEntries int   // Max cached responses (0 = 1024)
	MaxBodyKB  int64 // Max response body to cache in KB (0 = 256)
}

type cacheEntry struct {
	status   int
	headers  http.Header
	body     []byte
	expireAt time.Time
}

// Cache returns a middleware that caches GET/HEAD responses in memory.
func Cache(cfg CacheConfig) Middleware {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 1024
	}
	if cfg.MaxBodyKB <= 0 {
		cfg.MaxBodyKB = 256
	}
	maxBody := cfg.MaxBodyKB * 1024
	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 60 * time.Second
	}

	store := &cacheStore{
		entries: make(map[string]*cacheEntry),
		max:     cfg.MaxEntries,
		maxBody: maxBody,
	}
	var mu sync.Mutex

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}
			key := r.URL.String()
			mu.Lock()
			ent := store.get(key)
			mu.Unlock()
			if ent != nil {
				for k, vv := range ent.headers {
					for _, v := range vv {
						w.Header().Add(k, v)
					}
				}
				w.WriteHeader(ent.status)
				if r.Method == http.MethodGet && len(ent.body) > 0 {
					_, _ = w.Write(ent.body)
				}
				return
			}

			buf := &bytes.Buffer{}
			rec := &responseRecorder{
				ResponseWriter: w,
				status:         http.StatusOK,
				header:         make(http.Header),
				body:           buf,
				maxBody:        maxBody,
			}
			next.ServeHTTP(rec, r)

			if rec.status >= 200 && rec.status < 300 && buf.Len() > 0 && int64(buf.Len()) <= maxBody {
				mu.Lock()
				store.set(key, &cacheEntry{
					status:   rec.status,
					headers:  rec.header,
					body:     bytes.Clone(buf.Bytes()),
					expireAt: time.Now().Add(ttl),
				})
				mu.Unlock()
			}
		})
	}
}

type responseRecorder struct {
	http.ResponseWriter
	status  int
	header  http.Header
	body    *bytes.Buffer
	maxBody int64
	wrote   int64
}

func (r *responseRecorder) Header() http.Header {
	if r.header == nil {
		r.header = make(http.Header)
	}
	return r.header
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	for k, vv := range r.header {
		for _, v := range vv {
			r.ResponseWriter.Header().Add(k, v)
		}
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(p []byte) (n int, err error) {
	n, err = r.ResponseWriter.Write(p)
	if r.body != nil && r.wrote < r.maxBody {
		remain := r.maxBody - r.wrote
		if int64(len(p)) <= remain {
			r.body.Write(p)
			r.wrote += int64(len(p))
		} else {
			r.body.Write(p[:remain])
			r.wrote = r.maxBody
		}
	}
	return n, err
}

type cacheStore struct {
	entries map[string]*cacheEntry
	order   []string
	max     int
	maxBody int64
}

func (s *cacheStore) get(key string) *cacheEntry {
	ent, ok := s.entries[key]
	if !ok || ent == nil || time.Now().After(ent.expireAt) {
		if ok {
			delete(s.entries, key)
		}
		return nil
	}
	return ent
}

func (s *cacheStore) set(key string, ent *cacheEntry) {
	if len(s.entries) >= s.max && s.order != nil {
		old := s.order[0]
		s.order = s.order[1:]
		delete(s.entries, old)
	}
	s.entries[key] = ent
	s.order = append(s.order, key)
}
