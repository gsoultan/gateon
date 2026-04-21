package telemetry

import (
	"context"
	"math/rand"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TraceRoute performs a traceroute-like operation to the target IP.
// For production stability and to avoid requiring raw socket privileges,
// it combines real GeoIP data for the endpoints with simulated intermediate network hops.
func TraceRoute(ctx context.Context, targetIP string, serverIP string) ([]*gateonv1.TraceHop, error) {
	var hops []*gateonv1.TraceHop

	// 1. Server Hop (Source)
	sCountry, sCity, sLat, sLon := ResolveIPInfo(serverIP)
	hops = append(hops, &gateonv1.TraceHop{
		Hop:         1,
		Ip:          serverIP,
		Latitude:    sLat,
		Longitude:   sLon,
		CountryCode: sCountry,
		City:        sCity,
		RttMs:       1,
	})

	// 2. Destination Hop (Target)
	dCountry, dCity, dLat, dLon := ResolveIPInfo(targetIP)

	// If we don't have coordinates for destination, we can't really visualize it on map.
	// But we'll still return it.

	// 3. Simulated intermediate hops if they are far apart
	// This is for visual effect in the map animation as requested "like traceroute".
	numIntermediate := 2
	if sLat != 0 && dLat != 0 {
		for i := 1; i <= numIntermediate; i++ {
			ratio := float64(i) / float64(numIntermediate+1)

			// Add some randomness to the path
			lat := sLat + (dLat-sLat)*ratio + (rand.Float64()-0.5)*2.0
			lon := sLon + (dLon-sLon)*ratio + (rand.Float64()-0.5)*2.0

			hops = append(hops, &gateonv1.TraceHop{
				Hop:         int32(i + 1),
				Ip:          "10.0.0." + string(rune('0'+i)), // Simulated internal IP
				Latitude:    lat,
				Longitude:   lon,
				CountryCode: "XX",
				City:        "Network Path",
				RttMs:       int64(10 + i*20 + rand.Intn(10)),
			})
		}
	}

	// Add the final destination hop
	hops = append(hops, &gateonv1.TraceHop{
		Hop:         int32(len(hops) + 1),
		Ip:          targetIP,
		Latitude:    dLat,
		Longitude:   dLon,
		CountryCode: dCountry,
		City:        dCity,
		RttMs:       int64(50 + rand.Intn(100)),
	})

	return hops, nil
}
