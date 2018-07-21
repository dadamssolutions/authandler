package authandler

import (
	"net/http"

	"github.com/dadamssolutions/adaptd"
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

// RedirectOnError redirects based on whether it kind find an error in the Request's context.
func RedirectOnError(f func(http.ResponseWriter, *http.Request), logOnError string, h http.Handler) adaptd.Adapter {
	g := func(w http.ResponseWriter, r *http.Request) bool {
		f(w, r)
		err := ErrorFromContext(r.Context())
		return err == nil
	}

	return adaptd.OnCheck(g, h, logOnError)
}

// QueryStringExists calls the handler if the given query string exists.
// If the query string does not exist, then the handler to the Adapter is called.
func QueryStringExists(key, logOnNonexist string, h http.Handler) adaptd.Adapter {
	f := func(w http.ResponseWriter, r *http.Request) bool {
		if val := r.URL.Query()[key]; val != nil {
			return false
		}
		return true
	}

	return adaptd.OnCheck(f, h, logOnNonexist)
}
