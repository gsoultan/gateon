package auth

import "testing"

func TestAllowed(t *testing.T) {
	tests := []struct {
		name     string
		role     string
		action   Action
		resource Resource
		want     bool
	}{
		// Admin: full access
		{"admin read routes", RoleAdmin, ActionRead, ResourceRoutes, true},
		{"admin write routes", RoleAdmin, ActionWrite, ResourceRoutes, true},
		{"admin write users", RoleAdmin, ActionWrite, ResourceUsers, true},
		{"admin write global", RoleAdmin, ActionWrite, ResourceGlobal, true},
		{"admin read config", RoleAdmin, ActionRead, ResourceConfig, true},
		{"admin write config", RoleAdmin, ActionWrite, ResourceConfig, true},
		// Operator: read all, write config entities (no users/global)
		{"operator read routes", RoleOperator, ActionRead, ResourceRoutes, true},
		{"operator write routes", RoleOperator, ActionWrite, ResourceRoutes, true},
		{"operator write config", RoleOperator, ActionWrite, ResourceConfig, true},
		{"operator read users", RoleOperator, ActionRead, ResourceUsers, true},
		{"operator write users", RoleOperator, ActionWrite, ResourceUsers, false},
		{"operator write global", RoleOperator, ActionWrite, ResourceGlobal, false},
		{"operator write certs", RoleOperator, ActionWrite, ResourceCerts, false},
		// Viewer: read only
		{"viewer read routes", RoleViewer, ActionRead, ResourceRoutes, true},
		{"viewer write routes", RoleViewer, ActionWrite, ResourceRoutes, false},
		{"viewer read users", RoleViewer, ActionRead, ResourceUsers, true},
		{"viewer write users", RoleViewer, ActionWrite, ResourceUsers, false},
		{"viewer write global", RoleViewer, ActionWrite, ResourceGlobal, false},
		// Unknown role
		{"unknown read", "unknown", ActionRead, ResourceRoutes, false},
		{"empty role", "", ActionRead, ResourceRoutes, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Allowed(tt.role, tt.action, tt.resource)
			if got != tt.want {
				t.Errorf("Allowed(%q, %q, %q) = %v, want %v",
					tt.role, tt.action, tt.resource, got, tt.want)
			}
		})
	}
}

func TestValidRole(t *testing.T) {
	tests := []struct {
		role string
		want bool
	}{
		{RoleAdmin, true},
		{RoleOperator, true},
		{RoleViewer, true},
		{"admin", true},
		{"operator", true},
		{"viewer", true},
		{"unknown", false},
		{"", false},
		{"Admin", false}, // case-sensitive
	}
	for _, tt := range tests {
		got := ValidRole(tt.role)
		if got != tt.want {
			t.Errorf("ValidRole(%q) = %v, want %v", tt.role, got, tt.want)
		}
	}
}
