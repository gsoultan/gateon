package correlation

import "testing"

func TestIncidentStore_NewestFirstAndBounded(t *testing.T) {
	s := NewIncidentStore(3)

	for _, id := range []string{"a", "b", "c", "d", "e"} {
		s.Add(Incident{ID: id})
	}

	if got := s.Len(); got != 3 {
		t.Fatalf("Len = %d, want 3 (bounded)", got)
	}
	if got := s.TotalSeen(); got != 5 {
		t.Fatalf("TotalSeen = %d, want 5", got)
	}

	got := s.List(0)
	want := []string{"e", "d", "c"} // newest-first, oldest evicted
	if len(got) != len(want) {
		t.Fatalf("List len = %d, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].ID != id {
			t.Errorf("List[%d].ID = %q, want %q", i, got[i].ID, id)
		}
	}
}

func TestIncidentStore_ListLimit(t *testing.T) {
	s := NewIncidentStore(10)
	for _, id := range []string{"1", "2", "3", "4"} {
		s.Add(Incident{ID: id})
	}
	got := s.List(2)
	if len(got) != 2 || got[0].ID != "4" || got[1].ID != "3" {
		t.Fatalf("List(2) = %+v, want [4 3]", got)
	}
}

func TestNewIncidentStore_FloorsCapacity(t *testing.T) {
	s := NewIncidentStore(0)
	s.Add(Incident{ID: "x"})
	s.Add(Incident{ID: "y"})
	if s.Len() != 1 || s.List(0)[0].ID != "y" {
		t.Fatalf("expected floored capacity 1 retaining newest, got len=%d", s.Len())
	}
}
