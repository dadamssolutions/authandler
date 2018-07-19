package authandler

// Represent roles used for users.
const (
	Member = iota
	Manager
	Supervisor
	Admin
)

// Role is represents the role of a user.
// Roles elevate and have a linear heirachy.
type Role int

// HasRole returns whether the role has the given permssion level.
func (r Role) HasRole(permission Role) bool {
	return r >= permission
}

// User represents a user to be logged in or signed up represented in the created database.
// For ease, you would want the representation of the user in your app to embed User.
type User struct {
	FirstName, LastName, Email string
	Role                       Role
	validated                  bool
	passHash                   []byte
}

// HasPermission determines whether the user has the given permission level
func (u User) HasPermission(role Role) bool {
	return u.Role.HasRole(role)
}

// IsValidated returns whether the user has validated their login
func (u User) IsValidated() bool {
	return u.validated
}
