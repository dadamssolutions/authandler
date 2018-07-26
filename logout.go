package authandler

import (
	"net/http"

	"github.com/dadamssolutions/adaptd"
)

// LogoutAdapter handles the logout requests
// The handler passed to the Adapter is only called is when the logout fails.
// In this case, the error and the session are put on the Request's context.
func (a *HTTPAuth) LogoutAdapter(redirectOnSuccess string) adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		g := func(w http.ResponseWriter, r *http.Request) bool {
			return !a.logUserOut(w, r)
		}

		adapters := []adaptd.Adapter{
			adaptd.CheckAndRedirect(a.userIsAuthenticated, "Requesting logout page, but no user is logged in", redirectOnSuccess, http.StatusFound),
			adaptd.CheckAndRedirect(g, "User was logged out", redirectOnSuccess, http.StatusFound),
		}
		return adaptd.Adapt(h, adapters...)
	}
}
