package api

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ManagementDomainDetector detects unauthorized access or anomalies related to the management domain.
type ManagementDomainDetector struct{}

func (d *ManagementDomainDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly

	if len(data.ManagementHosts) == 0 {
		return nil
	}

	for _, tr := range data.Traces {
		isMgmt := false
		for _, host := range data.ManagementHosts {
			if strings.Contains(tr.Path, host) {
				isMgmt = true
				break
			}
		}

		if isMgmt {
			// If it's a management request but not from an internal IP
			if !isInternalIP(tr.SourceIP) && tr.SourceIP != "127.0.0.1" && tr.SourceIP != "::1" && tr.SourceIP != "" {
				anomaly := &gateonv1.Anomaly{
					Type:           "management_access_violation",
					Severity:       "critical",
					Description:    fmt.Sprintf("External IP %s accessed management domain %s", tr.SourceIP, tr.Path),
					Timestamp:      tr.Timestamp.Format(time.RFC3339),
					Source:         tr.SourceIP,
					Recommendation: "Restrict management access to internal VPN or specific trusted IP addresses only.",
				}
				populateAnomalyGeo(anomaly, tr.SourceIP)
				anomalies = append(anomalies, anomaly)
			}
		}
	}
	return anomalies
}

func isInternalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback()
}
