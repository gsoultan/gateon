package telemetry

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/hashicorp/memberlist"
)

// ReputationDelegate implements memberlist.Delegate for broadcasting reputation updates.
type ReputationDelegate struct {
	mu       sync.Mutex
	messages [][]byte
}

func (d *ReputationDelegate) NodeMeta(limit int) []byte {
	return nil
}

func (d *ReputationDelegate) NotifyMsg(msg []byte) {
	var payload gateonv1.ReputationSyncPayload
	if err := json.Unmarshal(msg, &payload); err != nil {
		logger.L.LogError("failed to unmarshal gossip message", "error", err)
		return
	}

	// Apply the received reputation update locally.
	// We use a internal-only decrease that doesn't trigger another broadcast to avoid loops.
	ApplyRemoteReputation(payload.Fingerprint, payload.Score, int(payload.ViolationCount), payload.History)
}

func (d *ReputationDelegate) GetBroadcasts(overhead, limit int) [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.messages) == 0 {
		return nil
	}

	res := d.messages
	d.messages = nil
	return res
}

func (d *ReputationDelegate) LocalState(join bool) []byte {
	return nil
}

func (d *ReputationDelegate) MergeRemoteState(buf []byte, join bool) {
}

func (d *ReputationDelegate) Enqueue(msg []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// Limit queue size to avoid memory exhaustion under heavy attack.
	if len(d.messages) > 1000 {
		d.messages = d.messages[1:]
	}
	d.messages = append(d.messages, msg)
}

var (
	gossipManager *GossipManager
	gossipOnce    sync.Once
)

type GossipManager struct {
	list     *memberlist.Memberlist
	delegate *ReputationDelegate
	conf     *gateonv1.HaConfig
}

func InitGossip(conf *gateonv1.HaConfig) error {
	if conf == nil || !conf.Enabled {
		return nil
	}

	var err error
	gossipOnce.Do(func() {
		delegate := &ReputationDelegate{}
		mconf := memberlist.DefaultLANConfig()
		mconf.Delegate = delegate
		mconf.BindPort = 7946 // Default memberlist port
		mconf.Name = fmt.Sprintf("gateon-%d", time.Now().UnixNano())

		// If we have a specific interface from HA config, use its IP.
		if conf.Interface != "" {
			if iface, err := net.InterfaceByName(conf.Interface); err == nil {
				if addrs, err := iface.Addrs(); err == nil {
					for _, addr := range addrs {
						if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
							if ipnet.IP.To4() != nil {
								mconf.BindAddr = ipnet.IP.String()
								break
							}
						}
					}
				}
			}
		}

		list, lerr := memberlist.Create(mconf)
		if lerr != nil {
			err = lerr
			return
		}

		gossipManager = &GossipManager{
			list:     list,
			delegate: delegate,
			conf:     conf,
		}

		logger.L.LogInfo("Gossip reputation sync initialized", "node", mconf.Name, "bind", mconf.BindAddr)
	})

	return err
}

func BroadcastReputation(fingerprint string, score float64, violations int, history []string) {
	if gossipManager == nil {
		return
	}

	payload := gateonv1.ReputationSyncPayload{
		Fingerprint:    fingerprint,
		Score:          score,
		ViolationCount: int32(violations),
		History:        history,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	gossipManager.delegate.Enqueue(data)
}

func GetGossipStatus() *gateonv1.GossipStatus {
	if gossipManager == nil {
		return &gateonv1.GossipStatus{Enabled: false}
	}

	members := gossipManager.list.Members()
	names := make([]string, 0, len(members))
	for _, m := range members {
		names = append(names, m.Name)
	}

	return &gateonv1.GossipStatus{
		Enabled:      true,
		MembersCount: int32(len(members)),
		MemberNames:  names,
	}
}
