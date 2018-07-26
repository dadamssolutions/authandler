package authandler

import (
	"log"
	"net/http"
	"net/url"
	"strconv"

	"github.com/dadamssolutions/adaptd"
	"github.com/dadamssolutions/authandler/handlers/session/sessions"
)

// LoginAdapter handles the login GET and POST requests
// If it is determined that the login page should be shown, then the handler passed to the Adapter is called.
// If the user login POST request fails, the handler passed to the adapter is called again,
// this time with an error on the Request's context.
//
// The form for the POST request should point back to this handler.
// The form should have three inputs: username, password, and remember.
func (a *HTTPAuth) LoginAdapter() adaptd.Adapter {
	f := func(w http.ResponseWriter, r *http.Request) bool {
		return !a.userIsAuthenticated(w, r)
	}

	postHandler := adaptd.Adapt(http.HandlerFunc(a.logUserIn),
		adaptd.OnCheck(f, http.RedirectHandler(a.RedirectAfterLogin, http.StatusAccepted), "User already logged in"),
		a.CSRFPostAdapter(a.LoginURL, "CSRF token not valid for log in request"),
	)

	return a.standardPostAndGetAdapter(postHandler, a.RedirectAfterLogin, adaptd.CheckAndRedirect(f, a.RedirectAfterLogin, "User requesting login page is logged in", http.StatusAccepted))
}

func (a *HTTPAuth) logUserIn(w http.ResponseWriter, r *http.Request) {
	var ses *sessions.Session
	// If the user is authenticated already, then we just redirect
	if a.userIsAuthenticated(w, r) {
		log.Printf("User requesting login page, but is already logged in. Redirecting to %v\n", a.RedirectAfterLogin)
		return
	}
	// If the user is not logged in, we check the credentials
	username, password := url.QueryEscape(r.PostFormValue("username")), url.QueryEscape(r.PostFormValue("password"))
	remember := url.QueryEscape(r.PostFormValue("remember"))
	rememberMe, _ := strconv.ParseBool(remember)
	user := getUserFromDB(a.db, a.UsersTableName, "username", username)
	// If the user has provided correct credentials, then we log them in by creating a session.
	if user != nil && user.IsValidated() && a.CompareHashAndPassword(user.passHash, []byte(password)) == nil {
		ses, _ = a.sesHandler.CreateSession(username, rememberMe)
	}
	// If the session was created, then the user is logged in
	if ses != nil {
		log.Printf("User %v logged in successfully. Redirecting to %v\n", username, a.RedirectAfterLogin)
		a.sesHandler.AttachCookie(w, ses)
		return
	}
	log.Println("User login failed, redirecting back to login page")
	err := NewError(BadLogin)
	*r = *r.WithContext(NewErrorContext(r.Context(), err))
}
