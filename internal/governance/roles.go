package governance

type Role string

const (
	RoleAnalyst  Role = "analyst"
	RoleApprover Role = "approver"
	RoleAdmin    Role = "admin"
)

func IsValidRole(r string) bool {
	switch Role(r) {
	case RoleAnalyst, RoleApprover, RoleAdmin:
		return true
	default:
		return false
	}
}
