package httpauth

import "net/http"

// HTTPHandler is a general request handler taken in a call to http.HandleFunc
type HTTPHandler func(http.ResponseWriter, *http.Request)

// CSRFHandler is a request handler that will take a CSRF token as a string in GET requests
type CSRFHandler func(http.ResponseWriter, *http.Request, string, error)
