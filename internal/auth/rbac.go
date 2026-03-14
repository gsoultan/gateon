package auth

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

// Allowed returns whether the role can perform the action on the resource.
// admin: full access; operator: read all, write config entities (no users/global); viewer: read only.
func Allowed(role string, action Action, resource Resource) bool {
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
		return action == ActionRead
	default:
		return false
	}
}

// ValidRole returns true if the role is a known RBAC role.
func ValidRole(role string) bool {
	return role == RoleAdmin || role == RoleOperator || role == RoleViewer
}
