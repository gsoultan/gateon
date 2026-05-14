package telemetry

import (
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
)

type UserLocation struct {
	Lat         float64
	Lon         float64
	Time        time.Time
	Fingerprint string
}

var (
	userLocationCache *lru.ARCCache
	zerotrustMu       sync.Mutex
)

func init() {
	// Cache up to 100,000 users
	cache, _ := lru.NewARC(100000)
	userLocationCache = cache
}

// CheckZeroTrust validates if the request is consistent with previous behavior for this user.
func CheckZeroTrust(userID string, currentFingerprint string, ip string, r *http.Request) error {
	if userID == "" {
		return nil
	}

	zerotrustMu.Lock()
	defer zerotrustMu.Unlock()

	_, _, lat, lon := ResolveIPInfo(r.Context(), ip)
	now := time.Now()

	val, ok := userLocationCache.Get(userID)
	if !ok {
		// First time seeing this user, just record and return
		userLocationCache.Add(userID, &UserLocation{
			Lat:         lat,
			Lon:         lon,
			Time:        now,
			Fingerprint: currentFingerprint,
		})
		return nil
	}

	last := val.(*UserLocation)

	// 1. Impossible Travel Detection
	if last.Lat != 0 && last.Lon != 0 && lat != 0 && lon != 0 {
		dist := HaversineDistance(last.Lat, last.Lon, lat, lon)
		timeDiff := now.Sub(last.Time).Hours()

		if timeDiff > 0 {
			speed := dist / timeDiff
			// If speed > 1000 km/h (speed of a commercial jet), it's suspicious
			if speed > 1000 && dist > 100 {
				RecordSecurityThreat(SecurityThreat{
					Type:        "impossible_travel",
					Fingerprint: currentFingerprint,
					Score:       80,
					Details:     fmt.Sprintf("User moved %.2f km in %.2f hours (Speed: %.2f km/h)", dist, timeDiff, speed),
					RequestURI:  r.URL.Path,
				})
				return fmt.Errorf("impossible travel detected")
			}
		}
	}

	// 2. Device Posture Correlation
	if last.Fingerprint != "" && last.Fingerprint != currentFingerprint {
		// Hardware fingerprint changed for the same user session
		RecordSecurityThreat(SecurityThreat{
			Type:        "device_posture_change",
			Fingerprint: currentFingerprint,
			Score:       60,
			Details:     fmt.Sprintf("Fingerprint changed for user %s (Previous: %s, Current: %s)", userID, last.Fingerprint, currentFingerprint),
			RequestURI:  r.URL.Path,
		})
		// We don't necessarily block, but we record it.
		// In a stricter mode, we might require re-auth.
	}

	// Update cache
	last.Lat = lat
	last.Lon = lon
	last.Time = now
	last.Fingerprint = currentFingerprint
	userLocationCache.Add(userID, last)

	return nil
}

// HaversineDistance calculates the distance between two points in km.
func HaversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371 // Earth radius in km
	dLat := (lat2 - lat1) * math.Pi / 180
	dLon := (lon2 - lon1) * math.Pi / 180
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*math.Pi/180)*math.Cos(lat2*math.Pi/180)*
			math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return R * c
}
