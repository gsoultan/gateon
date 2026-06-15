package entrypoint

import (
	"context"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// fakeEPStore is a minimal EntryPointStore for testing dynamic timeouts.
type fakeEPStore struct {
	ep *gateonv1.EntryPoint
}

func (f *fakeEPStore) List(ctx context.Context) []*gateonv1.EntryPoint {
	if f.ep == nil {
		return nil
	}
	return []*gateonv1.EntryPoint{f.ep}
}

func (f *fakeEPStore) ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.EntryPoint, int32) {
	list := f.List(ctx)
	return list, int32(len(list))
}

func (f *fakeEPStore) Get(ctx context.Context, id string) (*gateonv1.EntryPoint, bool) {
	if f.ep != nil && f.ep.Id == id {
		return f.ep, true
	}
	return nil, false
}

func (f *fakeEPStore) Update(ctx context.Context, ep *gateonv1.EntryPoint) error {
	f.ep = ep
	return nil
}

func (f *fakeEPStore) Delete(ctx context.Context, id string) error {
	if f.ep != nil && f.ep.Id == id {
		f.ep = nil
	}
	return nil
}

// TestResolveEPTimeouts_UsesLiveStore verifies that read/write timeouts are
// always read from the live store, so configuration changes take effect
// without restarting gateon.
func TestResolveEPTimeouts_UsesLiveStore(t *testing.T) {
	// Snapshot captured at startup.
	snapshot := &gateonv1.EntryPoint{
		Id:             "ep-1",
		ReadTimeoutMs:  1000,
		WriteTimeoutMs: 2000,
	}
	store := &fakeEPStore{ep: &gateonv1.EntryPoint{
		Id:             "ep-1",
		ReadTimeoutMs:  1000,
		WriteTimeoutMs: 2000,
	}}
	deps := &Deps{EpStore: store}

	read, write := resolveEPTimeouts(snapshot.Id, snapshot, deps)
	if read != time.Second {
		t.Errorf("read timeout = %v, want 1s", read)
	}
	if write != 2*time.Second {
		t.Errorf("write timeout = %v, want 2s", write)
	}

	// Simulate a live config update (as would happen via the UI/API) without
	// restarting the server. The next resolution must reflect the new values.
	_ = store.Update(context.Background(), &gateonv1.EntryPoint{
		Id:             "ep-1",
		ReadTimeoutMs:  5000,
		WriteTimeoutMs: 7000,
	})

	read, write = resolveEPTimeouts(snapshot.Id, snapshot, deps)
	if read != 5*time.Second {
		t.Errorf("read timeout after update = %v, want 5s", read)
	}
	if write != 7*time.Second {
		t.Errorf("write timeout after update = %v, want 7s", write)
	}
}

// TestResolveEPTimeouts_Defaults verifies fallback to sane defaults when no
// timeout is configured and no store is available.
func TestResolveEPTimeouts_Defaults(t *testing.T) {
	read, write := resolveEPTimeouts("missing", nil, nil)
	if read != defaultEntryPointTimeout {
		t.Errorf("read timeout = %v, want default %v", read, defaultEntryPointTimeout)
	}
	if write != defaultEntryPointTimeout {
		t.Errorf("write timeout = %v, want default %v", write, defaultEntryPointTimeout)
	}
}
