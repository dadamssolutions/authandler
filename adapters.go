package authandler

import (
	"net/http"

	"github.com/dadamssolutions/adaptd"
	"github.com/dadamssolutions/authandler/seshandler/session"
)

// TryPostErrorContext checks that the error from f is nil.
// If the error is not nil, it is put into the Request context
// and the handler passed to the Adapter is called.
// The usage should be `TryPostErrorContext(postHandler)(getHandler)`
// The getHandler could then check if there is an error on the context.
func TryPostErrorContext(f func(*http.Request) error, postHandler http.Handler) adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var err error
			if r.Method == http.MethodPost {
				err = f(r)
				if err == nil {
					postHandler.ServeHTTP(w, r)
					return
				}
			}
			if err != nil {
				r = r.WithContext(NewErrorContext(r.Context(), err))
			}
			h.ServeHTTP(w, r)
		})
	}
}

// PullSessionFromContextAndCall pulls from the request context and calls the given function.
// If f returns an error, the error is put on the Request's context to be read.
// It is the callers responsibility to ensure that the return type of fromContext and the parameter
// type of f are the same or do type checking.
func PullSessionFromContextAndCall(f func(http.ResponseWriter, *session.Session) error) adaptd.Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ses := SessionFromContext(r.Context())
			err := f(w, ses)
			if err != nil {
				r = r.WithContext(NewErrorContext(r.Context(), err))
			}
			h.ServeHTTP(w, r)
		})
	}
}
