package proxy

import (
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// LoadBalancer defines the interface for selecting backend targets.
type LoadBalancer interface {
	Next() string
	NextState() *targetState
	UpdateWeightedTargets(targets []*gateonv1.Target)
	GetStats() []TargetStats
	SetAlive(url string, alive bool)
}
