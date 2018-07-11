package httpauth

import "net/http"

// CSRFHandler is a request handler that will take a CSRF token as a string in GET requests
type CSRFHandler func(http.ResponseWriter, *http.Request, string, error)
