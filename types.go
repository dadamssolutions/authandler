package httpauth

import "net/http"

// CSRFHandler is a request handler that will take a CSRF token as a string in GET requests.
// This type of handler should be used on any page that contains a form.
// The form should have a line that reads (or something like it):
// `<input type="hidden" name="token" value="{{.token}}">`
type CSRFHandler func(http.ResponseWriter, *http.Request, string, error)
