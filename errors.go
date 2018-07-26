package authandler

// TODO: Bad login error, username exists error, email exists error

// Error codes
const (
	BadLogin = iota
	UsernameExists
	EmailExists
	UserDoesNotExist
	EmailDoesNotExist
	TokenError
	PasswordError
	UnknownError
)

// An Error represents an error. We use a type so a caller can read the error type
type Error struct {
	Code int
	msg  string
}

// NewError creates a new error from the provided code.
func NewError(code int) Error {
	switch code {
	case BadLogin:
		return Error{BadLogin, "Username or password is not valid"}
	case UsernameExists:
		return Error{UsernameExists, "Username or password is not valid"}
	case EmailExists:
		return Error{EmailExists, "Username or password is not valid"}
	case UserDoesNotExist:
		return Error{UserDoesNotExist, "Username or password is not valid"}
	case EmailDoesNotExist:
		return Error{EmailDoesNotExist, "Username or password is not valid"}
	case TokenError:
		return Error{TokenError, "Username or password is not valid"}
	case PasswordError:
		return Error{PasswordError, "Username or password is not valid"}
	default:
		return Error{UnknownError, "An unknown error occurred"}
	}
}

func (e Error) Error() string {
	return e.msg
}
