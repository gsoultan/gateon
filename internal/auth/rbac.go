package auth

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Action represents the type of operation.
type Action string

const (
	ActionRead  Action = "read"
	ActionWrite Action = "write"
)

// Resource represents the target entity.
type Resource string

const (
	ResourceRoutes      Resource = "routes"
	ResourceServices    Resource = "services"
	ResourceEntryPoints Resource = "entrypoints"
	ResourceMiddlewares Resource = "middlewares"
	ResourceTLSOptions  Resource = "tls_options"
	ResourceCerts       Resource = "certificates"
	ResourceGlobal      Resource = "global"
	ResourceUsers       Resource = "users"
	ResourceConfig      Resource = "config"
)

var globalConfigGetter interface {
	Get(ctx context.Context) *gateonv1.GlobalConfig
}

func SetConfigGetter(getter interface {
	Get(ctx context.Context) *gateonv1.GlobalConfig
}) {
	globalConfigGetter = getter
}

// Allowed returns whether the role can perform the action on the resource.
// If dynamic RBAC is enabled in GlobalConfig, it uses those rules.
// Otherwise, it falls back to hardcoded defaults.
func Allowed(ctx context.Context, role string, action Action, resource Resource) bool {
	if globalConfigGetter != nil {
		cfg := globalConfigGetter.Get(ctx)
		if cfg != nil && cfg.Rbac != nil && cfg.Rbac.Enabled {
			return allowedDynamic(cfg.Rbac, role, action, resource)
		}
	}

	return allowedHardcoded(role, action, resource)
}

func allowedDynamic(cfg *gateonv1.RBACConfig, role string, action Action, resource Resource) bool {
	// Admin always has full access
	if role == RoleAdmin {
		return true
	}

	for _, p := range cfg.Roles {
		if p.Role == role {
			for _, perm := range p.Permissions {
				if (perm.Resource == string(resource) || perm.Resource == "*") &&
					(perm.Action == string(action) || perm.Action == "*") {
					return true
				}
			}
		}
	}
	return false
}

func allowedHardcoded(role string, action Action, resource Resource) bool {
	switch role {
	case RoleAdmin:
		return true
	case RoleOperator:
		if action == ActionRead {
			return true
		}
		switch resource {
		case ResourceRoutes, ResourceServices, ResourceEntryPoints,
			ResourceMiddlewares, ResourceTLSOptions, ResourceConfig:
			return true
		}
		return false
	case RoleViewer:
		if action != ActionRead {
			return false
		}
		// Viewers can see general configuration but NOT system global config, users, or diagnostics.
		switch resource {
		case ResourceRoutes, ResourceServices, ResourceEntryPoints,
			ResourceMiddlewares, ResourceTLSOptions, ResourceCerts:
			return true
		}
		return false
	default:
		return false
	}
}

// ValidRole returns true if the role is a known RBAC role.
func ValidRole(role string) bool {
	return role == RoleAdmin || role == RoleOperator || role == RoleViewer
}
